package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

// stubAssessor returns fixed findings.
type stubAssessor struct {
	findings []model.Finding
	err      error
}

func (s stubAssessor) Run(context.Context) ([]model.Finding, error) {
	return s.findings, s.err
}

func finding(image, class, team string, actionable, suppressed bool) model.Finding {
	return model.Finding{
		Image:      model.ParseImageRef(image),
		Owner:      model.Owner{Class: class, Team: team},
		Counts:     model.Counts{},
		Actionable: actionable,
		Suppressed: suppressed,
	}
}

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	s := New(stubAssessor{findings: []model.Finding{
		finding("acr.io/app:1", "engineering", "orders", true, false),
		finding("acr.io/lib:2", "engineering", "orders", false, false),
		finding("acr.io/sys:3", "platform", "platform", true, false),
		finding("mcr.io/managed:4", "cloud-provider", "aks", false, true),
	}})
	s.Refresh(context.Background())
	return s.Handler()
}

func getJSON(t *testing.T, h http.Handler, path string, out any) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if out != nil && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s: decode: %v (body %s)", path, err, rec.Body.String())
		}
	}
	return rec.Code
}

func TestFindingsExcludesSuppressedByDefault(t *testing.T) {
	h := newTestServer(t)
	var resp struct {
		Count    int                `json:"count"`
		Findings []sink.FindingView `json:"findings"`
	}
	if code := getJSON(t, h, "/api/v1/findings", &resp); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	// 3 non-suppressed (the cloud-provider one is suppressed).
	if resp.Count != 3 {
		t.Errorf("default findings should exclude suppressed: got %d, want 3", resp.Count)
	}
}

func TestFindingsFilters(t *testing.T) {
	h := newTestServer(t)

	cases := map[string]int{
		"/api/v1/findings?actionable=true":                         2,
		"/api/v1/findings?owner_class=platform":                    1,
		"/api/v1/findings?team=orders":                             2,
		"/api/v1/findings?actionable=false":                        1, // non-suppressed, non-actionable
		"/api/v1/findings?suppressed=true":                         1, // opt into suppressed
		"/api/v1/findings?owner_class=engineering&actionable=true": 1,
	}
	for path, want := range cases {
		var resp struct {
			Count int `json:"count"`
		}
		getJSON(t, h, path, &resp)
		if resp.Count != want {
			t.Errorf("%s: got %d, want %d", path, resp.Count, want)
		}
	}
}

func TestSummaryAndOwners(t *testing.T) {
	h := newTestServer(t)

	var sum struct {
		Summary summaryView `json:"summary"`
	}
	getJSON(t, h, "/api/v1/summary", &sum)
	if sum.Summary.Findings != 3 || sum.Summary.Actionable != 2 || sum.Summary.Suppressed != 1 {
		t.Errorf("unexpected summary: %+v", sum.Summary)
	}

	var owners struct {
		Owners []ownerStats `json:"owners"`
	}
	getJSON(t, h, "/api/v1/owners", &owners)
	// engineering/orders, platform/platform (cloud-provider suppressed excluded).
	if len(owners.Owners) != 2 {
		t.Fatalf("expected 2 owner rows, got %d: %+v", len(owners.Owners), owners.Owners)
	}
}

func TestFindingByImage(t *testing.T) {
	h := newTestServer(t)
	if code := getJSON(t, h, "/api/v1/finding?image=acr.io/app:1", nil); code != http.StatusOK {
		t.Errorf("existing image: status %d, want 200", code)
	}
	if code := getJSON(t, h, "/api/v1/finding?image=nope:1", nil); code != http.StatusNotFound {
		t.Errorf("missing image: status %d, want 404", code)
	}
	if code := getJSON(t, h, "/api/v1/finding", nil); code != http.StatusBadRequest {
		t.Errorf("no image param: status %d, want 400", code)
	}
}

func TestReadyzBeforeAndAfter(t *testing.T) {
	s := New(stubAssessor{findings: []model.Finding{finding("a:1", "eng", "t", true, false)}})
	// Before any refresh: not ready.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz before assessment: got %d, want 503", rec.Code)
	}
	// After a refresh: ready.
	s.Refresh(context.Background())
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("readyz after assessment: got %d, want 200", rec.Code)
	}
}

func TestRefreshErrorKeepsLastGood(t *testing.T) {
	// A failing assessor after a good one should not wipe the cached data.
	good := stubAssessor{findings: []model.Finding{finding("a:1", "eng", "t", true, false)}}
	s := New(good)
	s.Refresh(context.Background())

	s.assessor = stubAssessor{err: context.DeadlineExceeded}
	s.Refresh(context.Background())

	if s.latest == nil || s.latest.views == nil {
		t.Fatal("last good views should be retained after a failed refresh")
	}
	if s.latest.err == "" {
		t.Error("the error should be surfaced in the meta")
	}
}

// assessedFinding builds a finding the provider actually assessed, with a
// resolved upgrade. The default `finding` helper has neither, which is itself the
// point: an unassessed finding is the shape the API must not present as healthy.
func assessedFinding(image, class, team string, actionable bool) model.Finding {
	f := finding(image, class, team, actionable, false)
	f.Occurrences = []model.Occurrence{{Assessed: true}}
	f.Counts = model.Counts{model.SeverityCritical: 2}
	f.RemediationChecked = true
	f.Upgrade = &model.Upgrade{
		Current: "1.0.0", Latest: "2.0.0", Available: true, Resolved: true, Actionable: true,
	}
	return f
}

// A client reading only the summary must be able to tell a healthy estate from
// one nothing has looked at. Without coverage counts, "1 actionable" reads the
// same either way.
func TestSummaryReportsCoverage(t *testing.T) {
	s := New(stubAssessor{findings: []model.Finding{
		assessedFinding("acr.io/seen:1", "engineering", "orders", true),
		finding("acr.io/unseen:2", "engineering", "orders", false, false),
		finding("acr.io/unseen:3", "engineering", "orders", false, false),
		finding("mcr.io/managed:4", "cloud-provider", "aks", false, true),
	}})
	s.Refresh(context.Background())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Summary summaryView `json:"summary"`
	}
	decodeInto(t, rec, &body)
	got := body.Summary

	if got.ProviderAssessed != 1 {
		t.Errorf("provider_assessed = %d, want 1", got.ProviderAssessed)
	}
	if got.ProviderUnassessed != 2 {
		t.Errorf("provider_unassessed = %d, want 2", got.ProviderUnassessed)
	}
	// The documented invariant: the two coverage counts partition Findings, so a
	// client can check the arithmetic instead of guessing the denominator.
	if got.ProviderAssessed+got.ProviderUnassessed != got.Findings {
		t.Errorf("assessed(%d) + unassessed(%d) != findings(%d)",
			got.ProviderAssessed, got.ProviderUnassessed, got.Findings)
	}
	// Only the assessed finding has a resolved upgrade.
	if got.RemediationUnresolved != 2 {
		t.Errorf("remediation_unresolved = %d, want 2", got.RemediationUnresolved)
	}
}

// The opposite error to the one the coverage counts prevent: concluding that the
// actionable queue describes only the assessed findings. A vulnerability scanner
// can find fixable CVEs the provider never looked for, and on a real estate 14 of
// 35 actionable findings came from that alone, so the figure has to be reported.
func TestSummaryCountsActionableFoundOnlyByTheScanner(t *testing.T) {
	scannerOnly := finding("acr.io/scanner-only:1", "platform", "cpo-team", true, false)
	scannerOnly.Vulns = []model.Vulnerability{
		{ID: "CVE-1", Severity: model.SeverityCritical, FixAvailable: true},
	}
	scannerOnly.Scanned = true // scanned, but the provider never assessed it

	s := New(stubAssessor{findings: []model.Finding{
		scannerOnly,
		assessedFinding("acr.io/assessed:1", "platform", "cpo-team", true),
		finding("acr.io/quiet:1", "platform", "cpo-team", false, false),
	}})
	s.Refresh(context.Background())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil))
	var body struct {
		Summary summaryView `json:"summary"`
	}
	decodeInto(t, rec, &body)

	if body.Summary.ActionableUnassessed != 1 {
		t.Errorf("actionable_unassessed = %d, want 1", body.Summary.ActionableUnassessed)
	}
	// It must be a subset of both, or the banner arithmetic misleads.
	if body.Summary.ActionableUnassessed > body.Summary.Actionable ||
		body.Summary.ActionableUnassessed > body.Summary.ProviderUnassessed {
		t.Errorf("actionable_unassessed=%d must not exceed actionable=%d or unassessed=%d",
			body.Summary.ActionableUnassessed, body.Summary.Actionable, body.Summary.ProviderUnassessed)
	}
}

// Coverage is uneven by team in practice, and a team that looks quiet because
// nothing scanned its images must not be indistinguishable from a healthy one.
func TestOwnersReportUnassessed(t *testing.T) {
	s := New(stubAssessor{findings: []model.Finding{
		assessedFinding("acr.io/a:1", "platform", "platform-team", true),
		finding("acr.io/b:2", "engineering", "orders", false, false),
		finding("acr.io/c:3", "engineering", "orders", false, false),
	}})
	s.Refresh(context.Background())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil))
	var body struct {
		Owners []ownerStats `json:"owners"`
	}
	decodeInto(t, rec, &body)

	byTeam := map[string]ownerStats{}
	for _, o := range body.Owners {
		byTeam[o.Team] = o
	}
	if got := byTeam["orders"].Unassessed; got != 2 {
		t.Errorf("orders unassessed = %d, want 2", got)
	}
	if got := byTeam["platform-team"].Unassessed; got != 0 {
		t.Errorf("platform-team unassessed = %d, want 0", got)
	}
}

// "Show me what nothing has looked at" is a first-class question, not something a
// client should have to derive by fetching everything and filtering locally.
func TestCoverageFilters(t *testing.T) {
	s := New(stubAssessor{findings: []model.Finding{
		assessedFinding("acr.io/seen:1", "engineering", "orders", true),
		finding("acr.io/unseen:2", "engineering", "orders", false, false),
	}})
	s.Refresh(context.Background())

	cases := map[string]int{
		"provider_assessed=true":    1,
		"provider_assessed=false":   1,
		"remediation_checked=true":  1,
		"remediation_checked=false": 1,
		"upgrade_resolved=true":     1,
		"upgrade_resolved=false":    1,
	}
	for query, want := range cases {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings?"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", query, rec.Code)
		}
		var body struct {
			Findings []sink.FindingView `json:"findings"`
		}
		decodeInto(t, rec, &body)
		if len(body.Findings) != want {
			t.Errorf("%s: got %d findings, want %d", query, len(body.Findings), want)
		}
	}
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// The page ships embedded with the binary, so a rollout cannot leave the UI and
// the API it reads out of step.
func TestUIServesPage(t *testing.T) {
	h := newTestServer(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
	body := rec.Body.String()

	// The page must read the API rather than embed numbers, so the two cannot
	// disagree about what is true.
	for _, want := range []string{"/api/v1/summary", "/api/v1/owners", "/api/v1/findings"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not call %s", want)
		}
	}
	// It must lead with coverage: a dashboard that renders absent data as zero is
	// the failure this feature exists to prevent.
	if !strings.Contains(body, "provider_unassessed") {
		t.Error("page does not surface coverage")
	}
	// The banner must not claim the actionable figure covers only assessed
	// findings; it reports the scanner-only share instead.
	if !strings.Contains(body, "actionable_unassessed") {
		t.Error("page does not report actionable findings the provider never assessed")
	}
	// The page must distinguish when the provider last looked from when this
	// assessment ran, or a stale export looks current.
	if !strings.Contains(body, "provider_data_newest") {
		t.Error("page does not surface the age of the provider's data")
	}
	// Sorting must respect the domain rather than the alphabet, and unknowns must
	// sink rather than sort as zero. These assertions only prove the machinery is
	// present; the ordering itself is JavaScript and is not exercised by Go tests.
	// "?" for unknown ticket state, never "-": absent Jira config is not evidence
	// that no ticket exists.
	if !strings.Contains(body, "ticketsByRepo") {
		t.Error("page does not render ticket state")
	}
	// Actionability is coloured consistently wherever it appears, so Fix and
	// Upgrade cannot imply different things about the same finding.
	// Every state that could be misread as "fine" carries an explanation, since
	// those are exactly the ones mistaken for good news.
	for _, want := range []string{"FIX_HELP", "absent, not zero", "onlyFixable",
		"fixFilter", "haystack", `id="search"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	for _, want := range []string{"act-direct", "act-managed", "act-none", "act-unknown"} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing the actionability class %s", want)
		}
	}
	for _, want := range []string{"FIX_RANK", "PRI_RANK", "UNKNOWN", "sortable"} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing sorting machinery: %s", want)
		}
	}
	// Fixed-height scroll areas with a pinned header, so a long queue does not
	// push the rest of the page out of reach.
	if !strings.Contains(body, "max-height") || !strings.Contains(body, "position: sticky") {
		t.Error("tables are not fixed-height with a sticky header")
	}
}

// A mistyped API path must not return HTML to a JSON client, which "GET /" as a
// catch-all would otherwise do.
func TestUnknownPathIsNotThePage(t *testing.T) {
	h := newTestServer(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findingz", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Error("unknown path served the HTML page")
	}
}

// A first full run takes minutes. Without knowing when it started, a client can
// only show an empty page, which is indistinguishable from a broken one.
func TestAssessmentMetaReportsStartWhileRunning(t *testing.T) {
	release := make(chan struct{})
	s := New(blockingAssessor{release: release})

	go s.Refresh(context.Background())

	// Wait for the refresh to be in flight.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if m := s.meta(); m.Running {
			if m.StartedAt == nil {
				t.Fatal("running assessment does not report started_at")
			}
			if time.Since(*m.StartedAt) > time.Minute {
				t.Errorf("started_at is not recent: %v", m.StartedAt)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh never reported running")
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(release)
	// Once complete, started_at is dropped: it describes an in-flight run only.
	for i := 0; i < 200; i++ {
		if m := s.meta(); !m.Running {
			if m.StartedAt != nil {
				t.Error("started_at should be absent when no assessment is running")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("refresh did not finish")
}

// blockingAssessor holds a run open until released, so the in-flight state is
// observable.
type blockingAssessor struct{ release chan struct{} }

func (b blockingAssessor) Run(context.Context) ([]model.Finding, error) {
	<-b.release
	return nil, nil
}

// stubTickets is a fixed open-ticket index.
type stubTickets struct {
	byImage map[string][]ticket.Existing
	err     error
}

func (s stubTickets) OpenByImage(context.Context) (map[string][]ticket.Existing, error) {
	return s.byImage, s.err
}

// Tickets ride alongside the findings, keyed by repository, so a client can show
// whether someone is already on a finding.
func TestFindingsIncludeOpenTickets(t *testing.T) {
	s := New(stubAssessor{findings: []model.Finding{
		finding("acr.io/app:1", "engineering", "orders", true, false),
		finding("acr.io/other:2", "engineering", "orders", true, false),
	}}).WithTickets(stubTickets{byImage: map[string][]ticket.Existing{
		"app": {{Key: "PROJ-1", Status: "In Progress", Summary: "Upgrade app",
			Category: "indeterminate"}},
	}}, "https://example.atlassian.net/")
	s.Refresh(context.Background())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil))
	var body struct {
		Tickets map[string][]ticketRef `json:"tickets"`
	}
	decodeInto(t, rec, &body)

	refs := body.Tickets["app"]
	if len(refs) != 1 || refs[0].Key != "PROJ-1" {
		t.Fatalf("tickets = %+v, want PROJ-1 against app", body.Tickets)
	}
	// The category travels with the ticket: status names are per-project, so it is
	// the only portable way to tell "someone is on it" from "raised".
	if refs[0].Category != "indeterminate" {
		t.Errorf("category = %q, want indeterminate", refs[0].Category)
	}
	// A link is more useful than a key, and the base URL is not a secret.
	if want := "https://example.atlassian.net/browse/PROJ-1"; refs[0].URL != want {
		t.Errorf("url = %q, want %q", refs[0].URL, want)
	}
	if _, ok := body.Tickets["other"]; ok {
		t.Error("an image with no ticket must not appear in the index")
	}
}

// Without Jira configured the key is absent, which a client must read as "unknown"
// rather than "no ticket exists". Emitting an empty object would assert the latter.
func TestFindingsOmitTicketsWhenJiraIsNotConfigured(t *testing.T) {
	h := newTestServer(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil))

	var raw map[string]json.RawMessage
	decodeInto(t, rec, &raw)
	if _, present := raw["tickets"]; present {
		t.Error("tickets key should be absent when there is no index, not empty")
	}
}

// Findings are the point of the service: losing the ticket lookup must not cost
// the assessment.
func TestTicketLookupFailureDoesNotFailTheAssessment(t *testing.T) {
	s := New(stubAssessor{findings: []model.Finding{
		finding("acr.io/app:1", "engineering", "orders", true, false),
	}}).WithTickets(stubTickets{err: errors.New("jira unreachable")}, "https://example.atlassian.net")
	s.Refresh(context.Background())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Count   int                    `json:"count"`
		Tickets map[string][]ticketRef `json:"tickets"`
	}
	decodeInto(t, rec, &body)
	if body.Count != 1 {
		t.Errorf("count = %d, want the finding to survive a ticket lookup failure", body.Count)
	}
	if len(body.Tickets) != 0 {
		t.Errorf("tickets = %+v, want none after a failed lookup", body.Tickets)
	}
}

// When the provider last looked is a different question from when this pipeline
// ran. A server refreshing hourly over a mounted export reports a fresh assessment
// forever while the data underneath it ages, so the provider's own timestamps have
// to be surfaced or a week-old export looks current.
func TestSummaryReportsProviderDataAge(t *testing.T) {
	older := time.Now().Add(-7 * 24 * time.Hour).Truncate(time.Second)
	newer := time.Now().Add(-2 * 24 * time.Hour).Truncate(time.Second)

	withSeen := func(image string, seen time.Time) model.Finding {
		f := finding(image, "platform", "cpo-team", true, false)
		f.Occurrences = []model.Occurrence{{Assessed: true, LastSeen: seen}}
		return f
	}
	s := New(stubAssessor{findings: []model.Finding{
		withSeen("acr.io/a:1", older),
		withSeen("acr.io/b:1", newer),
		// Never assessed, so it carries no timestamp and must not skew the range.
		finding("acr.io/c:1", "platform", "cpo-team", false, false),
	}})
	s.Refresh(context.Background())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil))
	var body struct {
		Summary summaryView `json:"summary"`
	}
	decodeInto(t, rec, &body)

	if body.Summary.ProviderDataNewest == nil || body.Summary.ProviderDataOldest == nil {
		t.Fatalf("provider data range missing: %+v", body.Summary)
	}
	if !body.Summary.ProviderDataNewest.Equal(newer) {
		t.Errorf("newest = %v, want %v", body.Summary.ProviderDataNewest, newer)
	}
	if !body.Summary.ProviderDataOldest.Equal(older) {
		t.Errorf("oldest = %v, want %v", body.Summary.ProviderDataOldest, older)
	}
}

// With nothing assessed there is no timestamp to report, and inventing one (the
// zero time, or now) would be worse than saying nothing.
func TestSummaryOmitsProviderDataAgeWhenNothingWasAssessed(t *testing.T) {
	s := New(stubAssessor{findings: []model.Finding{
		finding("acr.io/a:1", "platform", "cpo-team", true, false),
	}})
	s.Refresh(context.Background())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil))
	var raw map[string]json.RawMessage
	decodeInto(t, rec, &raw)
	var summary map[string]json.RawMessage
	if err := json.Unmarshal(raw["summary"], &summary); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"provider_data_newest", "provider_data_oldest"} {
		if _, present := summary[k]; present {
			t.Errorf("%s should be absent when nothing was assessed", k)
		}
	}
}

// The breakdown is only meaningful if each team's fix split and tracking are
// reported, so the owner rollup has to carry them.
func TestOwnersReportFixSplitAndTicketing(t *testing.T) {
	direct := assessedFinding("acr.io/direct:1", "platform", "team", true)
	managed := assessedFinding("acr.io/managed:1", "platform", "team", true)
	managed.Upgrade.Actionable = false
	managed.Upgrade.Managed = "operator"
	// Actionable but with nothing to move to: counts in neither split.
	stuck := assessedFinding("acr.io/stuck:1", "platform", "team", true)
	stuck.Upgrade.Available = false

	s := New(stubAssessor{findings: []model.Finding{direct, managed, stuck}}).
		WithTickets(stubTickets{byImage: map[string][]ticket.Existing{
			"direct": {{Key: "PROJ-1", Status: "To Do"}},
		}}, "https://example.atlassian.net")
	s.Refresh(context.Background())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil))
	var body struct {
		Owners []ownerStats `json:"owners"`
	}
	decodeInto(t, rec, &body)
	if len(body.Owners) != 1 {
		t.Fatalf("got %d rows, want 1", len(body.Owners))
	}
	o := body.Owners[0]
	if o.Direct != 1 || o.Managed != 1 {
		t.Errorf("direct=%d managed=%d, want 1/1 (the stuck finding is in neither)", o.Direct, o.Managed)
	}
	if o.Ticketed != 1 {
		t.Errorf("ticketed = %d, want 1", o.Ticketed)
	}
	// The splits describe the actionable subset, so neither may exceed it.
	if o.Direct+o.Managed > o.Actionable || o.Ticketed > o.Actionable {
		t.Errorf("splits exceed actionable: %+v", o)
	}
}

// Non-actionable findings must not inflate a team's fix split: the breakdown reads
// as "of the work you have", not "of everything you own".
func TestOwnerFixSplitCountsOnlyActionableFindings(t *testing.T) {
	quiet := assessedFinding("acr.io/quiet:1", "platform", "team", false)
	s := New(stubAssessor{findings: []model.Finding{quiet}})
	s.Refresh(context.Background())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil))
	var body struct {
		Owners []ownerStats `json:"owners"`
	}
	decodeInto(t, rec, &body)
	if o := body.Owners[0]; o.Direct != 0 || o.Managed != 0 || o.Ticketed != 0 {
		t.Errorf("a non-actionable finding contributed to the split: %+v", o)
	}
}

// The CVE total is only interpretable next to how much of the row it was drawn
// from, and an unassessed row has no CVE data rather than no CVEs.
func TestOwnersReportCVECountsWithTheirCoverage(t *testing.T) {
	assessed := assessedFinding("acr.io/seen:1", "platform", "team", true)
	assessed.Counts = model.Counts{model.SeverityCritical: 3, model.SeverityHigh: 5}
	// Never assessed: its zero counts mean nobody looked, so they must not be
	// summed in as though the image were clean.
	blind := assessedFinding("acr.io/blind:1", "platform", "team", false)
	blind.Occurrences[0].Assessed = false
	blind.Counts = model.Counts{}

	s := New(stubAssessor{findings: []model.Finding{assessed, blind}})
	s.Refresh(context.Background())

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil))
	var body struct {
		Owners []ownerStats `json:"owners"`
	}
	decodeInto(t, rec, &body)
	o := body.Owners[0]
	if o.CVEs[model.SeverityCritical] != 3 || o.CVEs[model.SeverityHigh] != 5 {
		t.Errorf("cves = %v, want 3 critical / 5 high", o.CVEs)
	}
	if o.CVEsFrom != 1 {
		t.Errorf("cves_from = %d, want 1: the unassessed finding must not count as a source", o.CVEsFrom)
	}
	if o.CVEsFrom > o.Total-o.Unassessed {
		t.Errorf("cves_from %d exceeds the assessed findings %d", o.CVEsFrom, o.Total-o.Unassessed)
	}
	// Every standard severity is present so a client never has to tell "no
	// criticals" from "key absent".
	for _, sev := range []string{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		if _, ok := o.CVEs[sev]; !ok {
			t.Errorf("cves is missing the %q key", sev)
		}
	}
}
