package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
