package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/s-humphreys/patchwright/internal/metrics"
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
}

// routes is the one place a pattern is written down: Handler registers from it and
// the OpenAPI drift test reads it, so a route cannot be served and undocumented, or
// documented and unserved.
func (s *Server) routes() map[string]http.Handler {
	return map[string]http.Handler{
		// The status page is served by the same process as the API it reads, so
		// there is no second deployment and no build step.
		"GET /":                    http.HandlerFunc(s.handleUI),
		"GET /favicon.png":         http.HandlerFunc(s.handleFavicon),
		"GET /static/app/":         http.HandlerFunc(s.handleAsset),
		"GET /healthz":             http.HandlerFunc(s.handleHealthz),
		"GET /readyz":              http.HandlerFunc(s.handleReadyz),
		"GET /metrics":             metrics.Handler(),
		"GET /api/v1/findings":     http.HandlerFunc(s.handleFindings),
		"GET /api/v1/finding":      http.HandlerFunc(s.handleFinding),
		"GET /api/v1/owners":       http.HandlerFunc(s.handleOwners),
		"GET /api/v1/summary":      http.HandlerFunc(s.handleSummary),
		"GET /api/v1/config":       http.HandlerFunc(s.handleConfig),
		"POST /api/v1/assessments": http.HandlerFunc(s.handleRefresh),
		"GET /api/v1/tickets":      http.HandlerFunc(s.handleTicketPlan),
		"POST /api/v1/tickets":     http.HandlerFunc(s.handleTicketApply),
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
	// Authentication wraps everything, including the page: the page is a data view,
	// so leaving it open while gating the API would protect nothing. /metrics and the
	// probes are exempt; see openPaths.
	return s.authorize(mux)
}

func (s *Server) meta() assessmentMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := assessmentMeta{Running: s.running}
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
