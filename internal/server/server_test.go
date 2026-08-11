package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
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

// Coverage is uneven by team in practice, and a team that looks quiet because
// nothing scanned its images must not be indistinguishable from a healthy one.
func TestOwnersReportUnassessed(t *testing.T) {
	s := New(stubAssessor{findings: []model.Finding{
		assessedFinding("acr.io/a:1", "platform", "cpo", true),
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
	if got := byTeam["cpo"].Unassessed; got != 0 {
		t.Errorf("cpo unassessed = %d, want 0", got)
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
	// Sorting must respect the domain rather than the alphabet, and unknowns must
	// sink rather than sort as zero. These assertions only prove the machinery is
	// present; the ordering itself is JavaScript and is not exercised by Go tests.
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
