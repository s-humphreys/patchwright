package rapid7

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// The fixtures mirror the live API's shape, verified by probing it, with
// generic hosts and names. A real estate's registries and image names are not
// this repository's business.

// row builds one API row. status drives assessment_info, which is the field the
// CSV export does not have and most of this behaviour turns on.
func row(id int, image, status, reason string, crit, high int) map[string]any {
	info := map[string]any{
		"status":                  status,
		"error_reason":            nil,
		"assessment_completed_at": nil,
		"pulled_from":             nil,
	}
	if reason != "" {
		info["error_reason"] = reason
	}
	var lastAssessment any
	if status == assessmentCompleted {
		info["assessment_completed_at"] = "2026-08-10 19:57:44"
		lastAssessment = "2026-08-10 19:57:44"
	}
	return map[string]any{
		"id": id, "image_id": image,
		"resource_id":   fmt.Sprintf("containerdeployment:44:apps:%s:", image),
		"resource_type": "containerdeployment", "resource_name": "web",
		"cloud": "AZURE_ARM", "account": "Production", "account_id": "acct-1",
		"platform": "linux", "report_id": "sha256:" + strings.Repeat("a", 64),
		"k8s_cluster_name": "rg-name|prod-aks", "public_accessible": false,
		"riskscore": 108.0, "critical_count": crit, "high_count": high,
		"medium_count": 0, "low_count": 0, "none_count": 0,
		"total_count": crit + high, "severity": "HIGH",
		"last_assessment": lastAssessment, "assessment_info": info,
	}
}

// apiServer serves the given pages, and records how it was called so the test
// can assert the request contract rather than assume it.
type apiServer struct {
	pages    [][]map[string]any
	requests []string
	keys     []string
	bodies   []string
}

func (a *apiServer) start(t *testing.T) *apiProvider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 64)
		n, _ := r.Body.Read(body)
		a.requests = append(a.requests, r.URL.String())
		a.keys = append(a.keys, r.Header.Get("Api-Key"))
		a.bodies = append(a.bodies, string(body[:n]))

		page := 1
		fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
		var data []map[string]any
		if page >= 1 && page <= len(a.pages) {
			data = a.pages[page-1]
		}
		total := 0
		for _, p := range a.pages {
			total += len(p)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": data, "page": page, "page_size": apiPageSize,
			"total_count": total, "total_pages": len(a.pages),
		})
	}))
	t.Cleanup(srv.Close)
	// httptest is http, and newAPIProvider rightly refuses that, so the client is
	// built directly here. The URL check itself is covered separately below.
	return &apiProvider{baseURL: srv.URL, apiKey: "test-key", client: srv.Client()}
}

func TestFetchPagesUntilTheLastPage(t *testing.T) {
	a := &apiServer{pages: [][]map[string]any{
		{row(1, "reg.example.com/a:1", assessmentCompleted, "", 2, 3)},
		{row(2, "reg.example.com/b:1", assessmentCompleted, "", 0, 1)},
		{row(3, "reg.example.com/c:1", assessmentCompleted, "", 0, 0)},
	}}
	occ, err := a.start(t).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(occ) != 3 {
		t.Fatalf("got %d occurrences, want 3 (one per page): %+v", len(occ), occ)
	}
	if len(a.requests) != 3 {
		t.Errorf("made %d requests, want 3: %v", len(a.requests), a.requests)
	}
	// Every page is asked for, but no longer in order: pages after the first are
	// fetched concurrently, because sweeping them one at a time was minutes of a
	// startup already measured in tens of them. Order of REQUESTS is not a
	// contract; covering every page is, and so is the order of the RESULT, which
	// the occurrence check above pins.
	asked := map[string]bool{}
	for _, req := range a.requests {
		for page := 1; page <= len(a.pages); page++ {
			if strings.Contains(req, fmt.Sprintf("page=%d&", page)) ||
				strings.HasSuffix(req, fmt.Sprintf("page=%d", page)) {
				asked[fmt.Sprintf("%d", page)] = true
			}
		}
	}
	for page := 1; page <= len(a.pages); page++ {
		if !asked[fmt.Sprintf("%d", page)] {
			t.Errorf("page %d was never requested: %v", page, a.requests)
		}
	}
	// The rest of the contract this API enforces: the maximum page size, an empty
	// JSON object as the body, and the key in Api-Key.
	for i, req := range a.requests {
		if !strings.Contains(req, fmt.Sprintf("page_size=%d", apiPageSize)) {
			t.Errorf("request %d did not use the maximum page size: %s", i, req)
		}
		if a.bodies[i] != "{}" {
			t.Errorf("request %d body = %q, want {}: filters in the body are rejected", i, a.bodies[i])
		}
		if a.keys[i] != "test-key" {
			t.Errorf("request %d sent Api-Key %q", i, a.keys[i])
		}
	}
}

// A completed assessment is the only status whose zero counts are a measurement.
func TestCompletedAssessmentIsAssessed(t *testing.T) {
	a := &apiServer{pages: [][]map[string]any{
		{row(1, "reg.example.com/clean:1", assessmentCompleted, "", 0, 0)},
	}}
	occ, err := a.start(t).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	o := occ[0]
	if !o.Assessed {
		t.Error("a COMPLETED row is not marked assessed, so a genuinely clean image reads as unknown")
	}
	if o.AssessmentError != "" {
		t.Errorf("assessed row carries an error: %q", o.AssessmentError)
	}
	if o.LastSeen.IsZero() {
		t.Error("assessed row has no timestamp, so nothing can report when the provider last looked")
	}
	if o.Image.Digest == "" {
		t.Error("assessed row dropped report_id, so the result is pinned to a mutable tag")
	}
}

// The whole point of preferring the API: an unassessed image says why.
func TestFailedAssessmentReportsTheProvidersReason(t *testing.T) {
	const reason = "Can't authenticate to registry. Unable to obtain refresh token"
	a := &apiServer{pages: [][]map[string]any{
		{row(1, "reg.example.com/private:1", assessmentFailed, reason, 0, 0)},
	}}
	occ, err := a.start(t).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	o := occ[0]
	if o.Assessed {
		t.Fatal("a FAILED row is marked assessed, so its zero counts would read as clean")
	}
	if o.AssessmentError != reason {
		t.Errorf("AssessmentError = %q, want the provider's reason", o.AssessmentError)
	}
	if o.AssessmentStatus != assessmentFailed {
		t.Errorf("AssessmentStatus = %q, want %q", o.AssessmentStatus, assessmentFailed)
	}
	// A failed row's digest names an image nothing was read from.
	if o.Image.Digest != "" {
		t.Errorf("unassessed row kept a digest %q from a failed assessment", o.Image.Digest)
	}
	if !o.LastSeen.IsZero() {
		t.Error("unassessed row has a timestamp, which would claim the provider looked")
	}
}

// Statuses other than FAILED still have to explain themselves: silence reads as
// "no reason to worry", which is the opposite of the truth.
func TestEveryUnassessedStatusExplainsItself(t *testing.T) {
	for _, tc := range []struct{ status, want string }{
		{assessmentQueued, "queued"},
		{assessmentFailed, "no reason given"},
		{"", "no status reported"},
		{"SOMETHING_NEW", "SOMETHING_NEW"},
	} {
		a := &apiServer{pages: [][]map[string]any{
			{row(1, "reg.example.com/x:1", tc.status, "", 0, 0)},
		}}
		occ, err := a.start(t).Fetch(context.Background())
		if err != nil {
			t.Fatalf("status %q: Fetch: %v", tc.status, err)
		}
		if occ[0].Assessed {
			t.Errorf("status %q was treated as assessed", tc.status)
		}
		if !strings.Contains(occ[0].AssessmentError, tc.want) {
			t.Errorf("status %q: AssessmentError = %q, want it to mention %q",
				tc.status, occ[0].AssessmentError, tc.want)
		}
	}
}

func TestRowMapsCountsDimensionsAndCluster(t *testing.T) {
	a := &apiServer{pages: [][]map[string]any{
		{row(1, "reg.example.com/web:2.1", assessmentCompleted, "", 2, 5)},
	}}
	occ, err := a.start(t).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	o := occ[0]
	if o.Counts[model.SeverityCritical] != 2 || o.Counts[model.SeverityHigh] != 5 {
		t.Errorf("counts = %v, want 2 critical / 5 high", o.Counts)
	}
	// Zero buckets are left absent rather than stored as 0, matching the CSV
	// provider, so a normalized read is the single place zeros appear.
	if _, ok := o.Counts[model.SeverityLow]; ok {
		t.Errorf("a zero bucket was stored: %v", o.Counts)
	}
	// The cluster is trimmed of the platform's "<resource group>|" prefix.
	if got := o.Resource.Dimensions["cluster"]; got != "prod-aks" {
		t.Errorf("cluster = %q, want %q", got, "prod-aks")
	}
	if got := o.Resource.Dimensions["namespace"]; got != "apps" {
		t.Errorf("namespace = %q, want %q from the resource_id encoding", got, "apps")
	}
	if o.Image.Repository != "web" || o.Image.Tag != "2.1" {
		t.Errorf("image parsed as %+v", o.Image)
	}
}

// A page failing mid-run must not return a short estate: every count drawn from
// it would be wrong in the direction of "better".
func TestFetchFailsRatherThanReturningAPartialEstate(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"messages":{"error":"upstream exploded"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":        []map[string]any{row(1, "reg.example.com/a:1", assessmentCompleted, "", 1, 1)},
			"page":        1,
			"page_size":   apiPageSize,
			"total_count": 2,
			"total_pages": 2,
		})
	}))
	defer srv.Close()

	p := &apiProvider{baseURL: srv.URL, apiKey: "k", client: srv.Client()}
	occ, err := p.Fetch(context.Background())
	if err == nil {
		t.Fatalf("Fetch succeeded with a failed page, returning %d occurrences", len(occ))
	}
	if occ != nil {
		t.Errorf("Fetch returned %d occurrences alongside the error", len(occ))
	}
	// The API explains rejections in the body, so the body has to reach the user.
	if !strings.Contains(err.Error(), "upstream exploded") {
		t.Errorf("error dropped the API's own message: %v", err)
	}
	if !strings.Contains(err.Error(), "page 2") {
		t.Errorf("error does not say which page failed: %v", err)
	}
}

// An auth failure is the most likely operational error, and the API's own
// message for it does not mention the key.
func TestUnauthorizedNamesTheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := &apiProvider{baseURL: srv.URL, apiKey: "stale", client: srv.Client()}
	_, err := p.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "RAPID7_API_KEY") {
		t.Errorf("error = %v, want it to name RAPID7_API_KEY", err)
	}
}

func TestNewAPIProviderValidatesItsInputs(t *testing.T) {
	for _, tc := range []struct{ name, base, key, want string }{
		{"no base url", "", "k", "base-url"},
		{"no key", "https://example.com", "", "RAPID7_API_KEY"},
		{"not a url", "not a url", "k", "absolute URL"},
		// The key is sent on every request, so plaintext is refused outright
		// rather than warned about.
		{"plain http", "http://example.com", "k", "https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newAPIProvider(tc.base, tc.key)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	if _, err := newAPIProvider("https://example.customer.divvycloud.com/", "k"); err != nil {
		t.Errorf("a valid configuration was rejected: %v", err)
	}
}

// The reason has to survive the trip to a finding, or none of this is visible.
func TestAssessmentIssuesReachTheFinding(t *testing.T) {
	f := model.Finding{Occurrences: []model.Occurrence{
		{Assessed: false, AssessmentError: "Can't authenticate to registry"},
		{Assessed: false, AssessmentError: "Can't authenticate to registry"},
		{Assessed: false, AssessmentError: "Unable to pull an image"},
		{Assessed: true},
	}}
	got := f.AssessmentIssues()
	want := []string{"Can't authenticate to registry", "Unable to pull an image"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// Most common first, so the biggest fixable cause leads.
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("issue %d = %q, want %q", i, got[i], want[i])
		}
	}
	if len(model.Finding{Occurrences: []model.Occurrence{{Assessed: true}}}.AssessmentIssues()) != 0 {
		t.Error("a fully assessed finding reported issues")
	}
}

func TestSweepFetchesPagesConcurrently(t *testing.T) {
	// The sweeps are the slowest thing in a run - the risk-score one walks the
	// estate's whole CVE catalogue a hundred rows at a time - and serially they
	// were minutes of a startup already measured in tens of them.
	//
	// Pages after the first must overlap. Fetched one at a time this deadlocks
	// rather than merely running slowly, which is the point: a timing assertion
	// would pass on a fast machine whatever the code did.
	const pages = 4
	var mu sync.Mutex
	inFlight, peak := 0, 0
	gate := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := 1
		fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
		if page > 1 {
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			reached := inFlight == pages-1
			mu.Unlock()
			if reached {
				close(gate)
			}
			<-gate
			mu.Lock()
			inFlight--
			mu.Unlock()
		}
		fmt.Fprintf(w, `{"data":[{"cve_id":"CVE-%d"}],"page":%d,"page_size":1,"total_count":%d,"total_pages":%d}`,
			page, page, pages, pages)
	}))
	defer srv.Close()

	p := &apiProvider{baseURL: srv.URL, apiKey: "k", client: srv.Client()}
	rows, err := sweep[exploitVulnRow](context.Background(), p, func(page int) string {
		return fmt.Sprintf("/v3/cvm/vulnerabilities?page=%d&page_size=1", page)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != pages {
		t.Errorf("got %d rows, want one per page (%d)", len(rows), pages)
	}
	// Result order must still be page order, whatever order the network answered.
	for i, r := range rows {
		if want := fmt.Sprintf("CVE-%d", i+1); r.CVEID != want {
			t.Errorf("row %d = %q, want %q: the sweep must reassemble pages in order", i, r.CVEID, want)
		}
	}
	if peak < 2 {
		t.Errorf("peak concurrent page requests = %d, want the pages after the first to overlap", peak)
	}
}
