package server

import (
	"context"
	"encoding/json"
	"github.com/s-humphreys/patchwright/pkg/group"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/internal/metrics"
	"github.com/s-humphreys/patchwright/internal/version"
	"github.com/s-humphreys/patchwright/pkg/analytics"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

var (
	errTicketingNotConfigured = errTicketing("ticketing is not configured: a jira config block and JIRA_* credentials are required")
	errNoAssessment           = errTicketing("no assessment has completed yet")
)

// errTicketing is a plain error type so the handlers can report the reason without
// a dependency on a specific error package.
type errTicketing string

func (e errTicketing) Error() string { return string(e) }

// assessmentMeta tells clients how fresh the data is.
type assessmentMeta struct {
	GeneratedAt *time.Time `json:"generated_at"`
	Running     bool       `json:"running"`
	Error       string     `json:"error,omitempty"`
	// StartedAt is set while an assessment is in flight, so a client can say how
	// long it has been going rather than showing an empty page and leaving the
	// viewer to guess whether anything is happening.
	StartedAt *time.Time `json:"started_at,omitempty"`
	// Version is the build serving this. Reported so a reader can tell which
	// deployment they are looking at rather than inferring it from the image tag
	// they believe is running - which is the thing that goes wrong when a rollout
	// half-succeeds.
	Version string `json:"version"`
}

// routes is the one place a pattern is written down: Handler registers from it and
// the OpenAPI drift test reads it, so a route cannot be served and undocumented, or
// documented and unserved.
func (s *Server) routes() map[string]http.Handler {
	mcpH := s.mcpHandler()
	return map[string]http.Handler{
		// The status page is served by the same process as the API it reads, so
		// there is no second deployment and no build step.
		"GET /":            http.HandlerFunc(s.handleUI),
		"GET /tickets":     http.HandlerFunc(s.handleTicketsPage),
		"GET /analytics":   http.HandlerFunc(s.handleAnalyticsPage),
		"GET /favicon.png": http.HandlerFunc(s.handleFavicon),
		"GET /static/app/": http.HandlerFunc(s.handleAsset),
		"GET /healthz":     http.HandlerFunc(s.handleHealthz),
		"GET /readyz":      http.HandlerFunc(s.handleReadyz),
		"GET /metrics":     metrics.Handler(),
		// MCP is a normal route, so it sits behind the same authentication as
		// everything else. An exempt path here would be an unauthenticated read of
		// the whole estate on the same port as a page that is behind sign-in.
		// Methods are named individually because a bare "/mcp" would out-specify
		// "GET /" and collide with it. Streamable HTTP uses all three: POST to call
		// a tool, GET for the server's stream, DELETE to end a session.
		"POST /mcp":                mcpH,
		"GET /mcp":                 mcpH,
		"DELETE /mcp":              mcpH,
		"GET /api/v1/findings":     http.HandlerFunc(s.handleFindings),
		"GET /api/v1/finding":      http.HandlerFunc(s.handleFinding),
		"GET /api/v1/items":        http.HandlerFunc(s.handleItems),
		"GET /api/v1/service":      http.HandlerFunc(s.handleService),
		"GET /api/v1/cves":         http.HandlerFunc(s.handleCVEs),
		"GET /api/v1/cve":          http.HandlerFunc(s.handleCVE),
		"GET /api/v1/owners":       http.HandlerFunc(s.handleOwners),
		"GET /api/v1/summary":      http.HandlerFunc(s.handleSummary),
		"GET /api/v1/analytics":    http.HandlerFunc(s.handleAnalytics),
		"GET /api/v1/config":       http.HandlerFunc(s.handleConfig),
		"POST /api/v1/assessments": http.HandlerFunc(s.handleRefresh),
		"GET /api/v1/tickets":      http.HandlerFunc(s.handleTicketPlan),
		"POST /api/v1/tickets":     http.HandlerFunc(s.handleTicketApply),
	}
}

// signInRoutes are the endpoints the OIDC flow needs, registered only when it is
// configured. Registering them unconditionally would advertise a sign-in that cannot
// work and hand anybody who found them a 500.
func (s *Server) signInRoutes() map[string]http.Handler {
	if !s.signInEnabled() {
		return nil
	}
	return map[string]http.Handler{
		"GET " + loginPath:    http.HandlerFunc(s.handleLogin),
		"GET " + callbackPath: http.HandlerFunc(s.handleCallback),
		"GET " + logoutPath:   http.HandlerFunc(s.handleLogout),
	}
}

// registeredRoutes lists the served patterns, for the spec test.
func registeredRoutes() []string {
	var out []string
	for pattern := range (&Server{}).routes() {
		out = append(out, pattern)
	}
	return out
}

// Handler returns the HTTP handler for the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for pattern, h := range s.routes() {
		mux.Handle(pattern, h)
	}
	for pattern, h := range s.signInRoutes() {
		mux.Handle(pattern, h)
	}
	// Authentication wraps everything, including the page: the page is a data view,
	// so leaving it open while gating the API would protect nothing. /metrics and the
	// probes are exempt; see openPaths.
	//
	// Compression is outermost so it covers the sign-in pages too, and revalidation
	// sits inside authentication: a 304 must not be served to a caller who has not
	// authenticated, or the presence of a cached copy would leak that the resource
	// exists.
	return compress(s.authorize(s.revalidate(mux)))
}

func (s *Server) meta() assessmentMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := assessmentMeta{Running: s.running, Version: version.String()}
	if s.running && !s.startedAt.IsZero() {
		t := s.startedAt
		m.StartedAt = &t
	}
	if s.latest != nil {
		t := s.latest.generatedAt
		m.GeneratedAt = &t
		m.Error = s.latest.err
	}
	return m
}

func (s *Server) snapshot() *snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latest
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz reports ready once a first successful assessment is cached.
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	if snap == nil || snap.views == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "no assessment yet"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshot()
	views := []sink.FindingView{}
	if snap != nil {
		views = filterViews(snap.views, r)
	}
	var tickets map[string][]ticketRef
	if snap != nil && snap.tickets != nil {
		tickets = map[string][]ticketRef{}
		// Only the tickets relevant to the rows being returned, so a filtered
		// request does not carry the whole project's index.
		for _, v := range views {
			if refs, ok := snap.tickets[v.Repository]; ok {
				tickets[v.Repository] = refs
			}
		}
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta     `json:"assessment"`
		Count      int                `json:"count"`
		Findings   []sink.FindingView `json:"findings"`
		// Tickets is keyed by image repository, alongside the findings rather than
		// inside them: a ticket is external state someone else can change, not a
		// fact this assessment measured. Absent when Jira is not configured, which
		// a client must not read as "no ticket exists".
		Tickets map[string][]ticketRef `json:"tickets,omitempty"`
	}{s.meta(), len(views), views, tickets})
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	image := r.URL.Query().Get("image")
	if image == "" {
		writeError(w, http.StatusBadRequest, "query parameter 'image' is required")
		return
	}
	snap := s.snapshot()
	if snap == nil {
		writeError(w, http.StatusNotFound, "no assessment available")
		return
	}
	v, ok := snap.byImage[image]
	if !ok {
		writeError(w, http.StatusNotFound, "no finding for image "+image)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta   `json:"assessment"`
		Finding    sink.FindingView `json:"finding"`
	}{s.meta(), v})
}

func (s *Server) handleOwners(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	owners := []ownerStats{}
	if snap != nil {
		owners = snap.owners
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Owners     []ownerStats   `json:"owners"`
	}{s.meta(), owners})
}

// handleAnalytics serves per-team responsiveness: who is not moving, and on what.
func (s *Server) handleAnalytics(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	var a analytics.AnalyticsView
	if snap != nil {
		a = snap.analytics
	}
	// Notes travel with an empty payload too. A consumer that reaches this before
	// the first assessment should still learn what the page can and cannot answer.
	if a.Notes == nil {
		a.Notes = analytics.Notes
		a.AgeBucketOrder = analytics.BucketNames()
		a.StaleFixDays = analytics.StaleFixDays
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta          `json:"assessment"`
		Analytics  analytics.AnalyticsView `json:"analytics"`
	}{s.meta(), a})
}

func (s *Server) handleSummary(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	var sum summaryView
	if snap != nil {
		sum = snap.summary
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Summary    summaryView    `json:"summary"`
	}{s.meta(), sum})
}

// handleRefresh triggers an assessment in the background and returns 202.
func (s *Server) handleRefresh(w http.ResponseWriter, _ *http.Request) {
	go s.Refresh(context.Background())
	writeJSON(w, http.StatusAccepted, struct {
		Assessment assessmentMeta `json:"assessment"`
		Message    string         `json:"message"`
	}{s.meta(), "assessment triggered"})
}

// filterViews applies the query-parameter filters. By default suppressed
// findings are excluded unless ?suppressed=true.
func filterViews(views []sink.FindingView, r *http.Request) []sink.FindingView {
	q := r.URL.Query()
	ownerClass := q.Get("owner_class")
	team := q.Get("team")
	repository := q.Get("repository")
	priority := q.Get("priority")
	actionable, hasActionable := boolParam(q.Get("actionable"))
	live, hasLive := boolParam(q.Get("live"))
	upgradable, hasUpgradable := boolParam(q.Get("upgradable"))
	knownExploited, hasKEV := boolParam(q.Get("known_exploited"))
	suppressed, hasSuppressed := boolParam(q.Get("suppressed"))
	assessed, hasAssessed := boolParam(q.Get("provider_assessed"))
	remChecked, hasRemChecked := boolParam(q.Get("remediation_checked"))
	upResolved, hasUpResolved := boolParam(q.Get("upgrade_resolved"))

	out := make([]sink.FindingView, 0, len(views))
	for _, v := range views {
		if !hasSuppressed && v.Suppressed {
			continue // default: hide suppressed
		}
		if hasSuppressed && v.Suppressed != suppressed {
			continue
		}
		if ownerClass != "" && v.Owner.Class != ownerClass {
			continue
		}
		// Repository rather than the full reference: a service is the unit somebody
		// asks about, and its tags change under them.
		if repository != "" && v.Repository != repository {
			continue
		}
		if team != "" && v.Owner.Team != team {
			continue
		}
		if priority != "" && v.Priority != priority {
			continue
		}
		if hasActionable && v.Actionable != actionable {
			continue
		}
		if hasKEV && v.KnownExploited != knownExploited {
			continue
		}
		if hasLive {
			isLive := v.Liveness != nil && v.Liveness.Live
			if isLive != live {
				continue
			}
		}
		if hasUpgradable {
			up := v.Upgrade != nil && v.Upgrade.Available && v.Upgrade.Actionable
			if up != upgradable {
				continue
			}
		}
		// Coverage filters: "show me what nothing has looked at" is a first-class
		// question, not a detail to derive client-side.
		if hasAssessed && v.ProviderAssessed != assessed {
			continue
		}
		if hasRemChecked && v.RemediationChecked != remChecked {
			continue
		}
		if hasUpResolved {
			resolved := v.Upgrade != nil && v.Upgrade.Resolved
			if resolved != upResolved {
				continue
			}
		}
		out = append(out, v)
	}
	return out
}

func boolParam(s string) (bool, bool) {
	if s == "" {
		return false, false
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false, false
	}
	return b, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// handleItems serves the queue as work items: one per service and upgrade target,
// which is the same unit a ticket covers.
//
// It exists so a consumer does not have to aggregate for itself. A service catalogue
// page asking "what does this service owe" was otherwise pulling every finding in the
// estate and grouping them, which is both slow and a second implementation of the
// grouping rules that can drift from this one.
func (s *Server) handleItems(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshot()
	items := []group.Item{}
	if snap != nil {
		items = group.Items(filterViews(snap.views, r))
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Count      int            `json:"count"`
		Items      []group.Item   `json:"items"`
	}{s.meta(), len(items), items})
}

// handleService answers for one service: its work items and whether anything is in
// progress. One request per component page, keyed by the repository a catalogue
// already knows.
func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	repository := r.URL.Query().Get("repository")
	if repository == "" {
		writeError(w, http.StatusBadRequest, "repository is required")
		return
	}
	snap := s.snapshot()
	if snap == nil {
		writeError(w, http.StatusServiceUnavailable, "no assessment yet")
		return
	}
	items := group.Items(filterViews(snap.views, r))
	mine := []group.Item{}
	for _, it := range items {
		if it.Repository == repository {
			mine = append(mine, it)
		}
	}
	// An empty list is a real answer — nothing outstanding — but only if this
	// assessment covers the service at all, which the caller cannot tell from an
	// empty array. Say whether it was seen.
	seen := false
	for _, v := range snap.views {
		if v.Repository == repository {
			seen = true
			break
		}
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Repository string         `json:"repository"`
		// Known is false when this assessment contains no finding for the service at
		// all: nothing deployed it, or the provider never reported it. An empty items
		// list with known:false is ignorance, not health.
		Known bool         `json:"known"`
		Count int          `json:"count"`
		Items []group.Item `json:"items"`
	}{s.meta(), repository, seen, len(mine), mine})
}

// handleCVEs serves the estate by CVE: how bad, how far it reaches, how much of that
// reach has a fix. The question a security team asks, which the per-service queue can
// only answer by reading every row.
func (s *Server) handleCVEs(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshot()
	cves := []group.CVE{}
	scanned, total := 0, 0
	if snap != nil {
		views := filterViews(snap.views, r)
		total = len(views)
		cves = group.CVEs(views, false)
		if len(cves) > 0 {
			scanned = cves[0].ScannedImages
		} else {
			for _, v := range views {
				if v.Scanned {
					scanned++
				}
			}
		}
		cves = filterCVEs(cves, r)
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Count      int            `json:"count"`
		// ScannedFindings and TotalFindings state what this was aggregated over. A CVE
		// list built from a third of the estate is not the estate, and zero CVEs with
		// zero scanned findings means nothing was looked at rather than nothing found.
		ScannedFindings int         `json:"scanned_findings"`
		TotalFindings   int         `json:"total_findings"`
		CVEs            []group.CVE `json:"cves"`
	}{s.meta(), len(cves), scanned, total, cves})
}

// handleCVE answers for one CVE, with every affected image.
func (s *Server) handleCVE(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	snap := s.snapshot()
	if snap == nil {
		writeError(w, http.StatusServiceUnavailable, "no assessment yet")
		return
	}
	views := filterViews(snap.views, r)
	found := group.FindCVE(views, id)
	if found == nil {
		// 404 with the coverage attached: "not found" over an unscanned estate means
		// nothing looked, which is a different answer from "nothing carries it".
		scanned := 0
		for _, v := range views {
			if v.Scanned {
				scanned++
			}
		}
		writeJSON(w, http.StatusNotFound, struct {
			Error           string `json:"error"`
			ScannedFindings int    `json:"scanned_findings"`
			TotalFindings   int    `json:"total_findings"`
		}{"no scanned image carries this CVE", scanned, len(views)})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		CVE        group.CVE      `json:"cve"`
	}{s.meta(), *found})
}

// filterCVEs applies the list filters a security consumer wants: what is exploited,
// what is severe, and what is widespread enough to be worth a campaign.
func filterCVEs(cves []group.CVE, r *http.Request) []group.CVE {
	q := r.URL.Query()
	severity := q.Get("severity")
	kev, hasKEV := boolParam(q.Get("kev"))
	fixable, hasFixable := boolParam(q.Get("fixable"))
	minImages := intParam(q.Get("min_images"))
	minServices := intParam(q.Get("min_services"))

	out := make([]group.CVE, 0, len(cves))
	for _, c := range cves {
		if severity != "" && c.Severity != severity {
			continue
		}
		if hasKEV && c.KEV != kev {
			continue
		}
		// fixable=true means at least one affected image can be fixed; false means
		// none can, which is the "waiting on upstream" list.
		if hasFixable && (c.Fixable > 0) != fixable {
			continue
		}
		if c.Images < minImages || c.Services < minServices {
			continue
		}
		out = append(out, c)
	}
	return out
}

// intParam reads a non-negative integer parameter, treating anything unparseable as
// absent rather than as zero-with-intent.
func intParam(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	return n
}
