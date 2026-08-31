package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

func gzipped(t *testing.T, body []byte) string {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("response is not gzip: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read gzip: %v", err)
	}
	return string(out)
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	compress(h).ServeHTTP(rec, req)
	return rec
}

func jsonHandler(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func gzipRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	return r
}

func TestLargeJSONIsCompressed(t *testing.T) {
	body := `{"findings":[` + strings.Repeat(`{"image":"reg/app:1.0.0","priority":"high"},`, 500) + `{}]}`
	rec := serve(jsonHandler(http.StatusOK, body), gzipRequest())

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := gzipped(t, rec.Body.Bytes()); got != body {
		t.Error("the decompressed body is not what the handler wrote")
	}
	if rec.Body.Len() >= len(body) {
		t.Errorf("compressed body (%d) is not smaller than the original (%d)", rec.Body.Len(), len(body))
	}
	// A cache keyed without this would serve one client's copy to another that cannot
	// decode it.
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Error("want Vary: Accept-Encoding")
	}
	if rec.Header().Get("Content-Length") != "" {
		t.Error("Content-Length describes the uncompressed body and would truncate the response")
	}
}

// The regression this file exists for. Holding the status alongside the body let the
// first Write default it to 200 without checking, so every 403 from the sign-in flow
// was served as a 200 containing a 403-shaped body.
func TestAnExplicitStatusSurvivesBufferingTheBody(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusNotFound} {
		rec := serve(jsonHandler(status, `{"error":"nope"}`), gzipRequest())
		if rec.Code != status {
			t.Errorf("status = %d, want %d", rec.Code, status)
		}
		if rec.Body.String() != `{"error":"nope"}` {
			t.Errorf("body = %q, want it passed through unchanged", rec.Body.String())
		}
	}
}

// Long enough to compress AND a deliberate status: both have to survive together.
func TestAStatusSurvivesCompression(t *testing.T) {
	body := `{"error":"` + strings.Repeat("x", 4000) + `"}`
	rec := serve(jsonHandler(http.StatusServiceUnavailable, body), gzipRequest())
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if got := gzipped(t, rec.Body.Bytes()); got != body {
		t.Error("body changed under compression")
	}
}

func TestShortBodiesAreLeftAlone(t *testing.T) {
	rec := serve(jsonHandler(http.StatusOK, `{"status":"ok"}`), gzipRequest())
	if rec.Header().Get("Content-Encoding") != "" {
		t.Error("a 15-byte body should not be gzipped")
	}
	if rec.Body.String() != `{"status":"ok"}` {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestAClientThatCannotDecodeGetsPlainBytes(t *testing.T) {
	body := strings.Repeat("a", 4000)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil) // no Accept-Encoding
	rec := serve(jsonHandler(http.StatusOK, body), req)
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatal("must not compress for a client that did not ask")
	}
	if rec.Body.String() != body {
		t.Error("body changed for an uncompressed client")
	}
}

// The metrics handler negotiates its own encoding. Compressing it again would produce
// a body no client can read.
func TestAnAlreadyEncodedBodyIsNotCompressedTwice(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("already-gzip"), 500))
	})
	rec := serve(h, gzipRequest())
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q", got)
	}
	if bytes.HasPrefix(rec.Body.Bytes(), []byte{0x1f, 0x8b}) {
		t.Error("the body was gzipped a second time")
	}
}

func TestNonTextIsLeftAlone(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(bytes.Repeat([]byte{1, 2, 3, 4}, 1000))
	})
	rec := serve(h, gzipRequest())
	if rec.Header().Get("Content-Encoding") != "" {
		t.Error("a PNG is already compressed; gzipping it wastes CPU and grows it")
	}
}

// A streaming handler must keep streaming: the MCP endpoint's event stream depends on
// a flush reaching the client rather than being held in the buffer.
func TestFlushReachesTheClient(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for i := 0; i < 3; i++ {
			_, _ = w.Write([]byte(strings.Repeat("event: message\n", 100)))
			w.(http.Flusher).Flush()
		}
	})
	rec := serve(h, gzipRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := gzipped(t, rec.Body.Bytes()); strings.Count(got, "event: message") != 300 {
		t.Errorf("want every flushed chunk delivered, got %d", strings.Count(got, "event: message"))
	}
}

func TestAHandlerThatWritesNothingStillAnswers(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
	})
	rec := serve(h, gzipRequest())
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// Revalidation.

func revalidatingServer(t *testing.T, generated time.Time) *Server {
	t.Helper()
	s := New(nil)
	s.latest = &snapshot{generatedAt: generated, views: nil}
	return s
}

func TestUnchangedDataAnswers304(t *testing.T) {
	s := revalidatingServer(t, time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC))
	h := s.revalidate(jsonHandler(http.StatusOK, `{"count":1}`))

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil))
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatal("want an ETag on a read of the cached assessment")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req.Header.Set("If-None-Match", tag)
	second := httptest.NewRecorder()
	h.ServeHTTP(second, req)
	if second.Code != http.StatusNotModified {
		t.Errorf("status = %d, want 304 for an unchanged assessment", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Error("a 304 must carry no body: sending it is the cost this avoids")
	}
}

// The validator has to change when the data does, or a client polls forever against a
// stale copy and the page silently stops updating - which is worse than being slow.
func TestANewAssessmentInvalidatesTheTag(t *testing.T) {
	before := revalidatingServer(t, time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC))
	after := revalidatingServer(t, time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	if before.etag(req) == after.etag(req) {
		t.Error("two different assessments must not share an ETag")
	}
}

// Different query, different answer. Serving a filtered request from an unfiltered
// entity would hand back the wrong rows.
func TestAQueryStringIsPartOfTheIdentity(t *testing.T) {
	s := revalidatingServer(t, time.Now())
	plain := s.etag(httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil))
	filtered := s.etag(httptest.NewRequest(http.MethodGet, "/api/v1/findings?team=payments", nil))
	if plain == filtered || plain == "" || filtered == "" {
		t.Errorf("want distinct tags per query, got %q and %q", plain, filtered)
	}
}

// While a run is in progress the page is showing progress from the meta. A 304 would
// freeze it.
func TestAnInFlightAssessmentIsNotRevalidated(t *testing.T) {
	s := revalidatingServer(t, time.Now())
	s.running = true
	if tag := s.etag(httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil)); tag != "" {
		t.Errorf("want no ETag during a run, got %q", tag)
	}
}

func TestWritesAndProbesAreNotRevalidated(t *testing.T) {
	s := revalidatingServer(t, time.Now())
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/v1/assessments", nil),
		httptest.NewRequest(http.MethodGet, "/healthz", nil),
		httptest.NewRequest(http.MethodGet, "/metrics", nil),
	} {
		if tag := s.etag(r); tag != "" {
			t.Errorf("%s %s got ETag %q, want none", r.Method, r.URL.Path, tag)
		}
	}
}

// An asset is identified by its bytes, so a rollout that did not change a module
// leaves it cached - and an assessment completing does not invalidate the page's
// JavaScript.
func TestAssetsAreValidatedByContentNotByAssessment(t *testing.T) {
	early := revalidatingServer(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	late := revalidatingServer(t, time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC))
	req := httptest.NewRequest(http.MethodGet, "/static/app/main.js", nil)
	tag := early.etag(req)
	if tag == "" {
		t.Fatal("want an ETag for an embedded module")
	}
	if late.etag(req) != tag {
		t.Error("an asset's validator must not change when an assessment completes")
	}

	other := late.etag(httptest.NewRequest(http.MethodGet, "/static/app/table.js", nil))
	if other == tag {
		t.Error("two different modules must not share a validator")
	}
}

func TestNoAssessmentMeansNoValidator(t *testing.T) {
	s := New(nil)
	if tag := s.etag(httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)); tag != "" {
		t.Errorf("want no ETag before the first assessment, got %q", tag)
	}
}

// A 304 is only correct for a caller entitled to the data. Serving one to an
// unauthenticated caller would confirm the resource exists and is unchanged.
func TestRevalidationSitsBehindAuthentication(t *testing.T) {
	s := New(nil).WithAuth("secret")
	s.latest = &snapshot{generatedAt: time.Now()}
	h := s.authorize(s.revalidate(jsonHandler(http.StatusOK, `{"count":1}`)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	req.Header.Set("If-None-Match", `"anything"`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 without a token", rec.Code)
	}
	if rec.Header().Get("ETag") != "" {
		t.Error("an unauthenticated caller must not be handed a validator")
	}
}

// The payload projection.
//
// These pin the property the page depends on: with vulns dropped, everything a list
// column shows is still in the answer. Losing that quietly would trade a slow page
// for a wrong one.

func projectionServer(t *testing.T) *Server {
	t.Helper()
	s := New(nil)
	full := sink.FindingView{
		Image: "reg/app:1.0.0", Repository: "app", Scanned: true, ProviderAssessed: true,
		KnownExploited: true, VulnCount: 2, TopEPSS: 0.91, TopEPSSPercentile: 0.99,
		TopRiskScore: 812,
		Vulns: []sink.VulnView{
			{ID: "CVE-2026-1", EPSS: 0.91, EPSSPercentile: 0.99, RiskScore: 812, KEV: true},
			{ID: "CVE-2026-2", EPSS: 0.02},
		},
	}
	s.latest = &snapshot{
		generatedAt: time.Now(), views: []sink.FindingView{full},
		byImage: map[string]sink.FindingView{full.Image: full},
	}
	return s
}

func TestVulnsFalseKeepsEveryFactTheQueueShows(t *testing.T) {
	s := projectionServer(t)
	rec := httptest.NewRecorder()
	s.handleFindings(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings?vulns=false", nil))

	var got struct {
		Findings []sink.FindingView `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("want one finding, got %d", len(got.Findings))
	}
	f := got.Findings[0]
	if len(f.Vulns) != 0 {
		t.Error("vulns=false must drop the per-CVE arrays")
	}
	// Everything the queue's columns and filters read.
	if f.VulnCount != 2 || f.TopEPSS != 0.91 || f.TopEPSSPercentile != 0.99 ||
		f.TopRiskScore != 812 || !f.KnownExploited || !f.Scanned {
		t.Errorf("an aggregate the page renders was lost: %+v", f)
	}
}

func TestVulnsAreIncludedByDefault(t *testing.T) {
	s := projectionServer(t)
	for _, query := range []string{"", "?vulns=true"} {
		rec := httptest.NewRecorder()
		s.handleFindings(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings"+query, nil))
		var got struct {
			Findings []sink.FindingView `json:"findings"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if len(got.Findings) != 1 || len(got.Findings[0].Vulns) != 2 {
			t.Errorf("query %q dropped vulns; the default must stay compatible", query)
		}
	}
}

// The projection copies. Mutating the cache would serve every later reader, and every
// other endpoint, a finding with its CVEs silently removed.
func TestTheProjectionDoesNotMutateTheCache(t *testing.T) {
	s := projectionServer(t)
	rec := httptest.NewRecorder()
	s.handleFindings(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings?vulns=false", nil))

	if n := len(s.latest.views[0].Vulns); n != 2 {
		t.Fatalf("the cached snapshot lost its vulns: %d left", n)
	}
	after := httptest.NewRecorder()
	s.handleFindings(after, httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil))
	var got struct {
		Findings []sink.FindingView `json:"findings"`
	}
	_ = json.Unmarshal(after.Body.Bytes(), &got)
	if len(got.Findings[0].Vulns) != 2 {
		t.Error("a later unfiltered read came back without vulns")
	}
}

// The aggregates have to be computed from the model, not trusted from a fixture: this
// is what the page falls back on when vulns are absent.
func TestAggregatesComeFromTheWorstCVE(t *testing.T) {
	f := model.Finding{
		Image: model.Image{Ref: "reg/app:1.0.0"},
		Vulns: []model.Vulnerability{
			{ID: "CVE-1", EPSS: 0.10, EPSSPercentile: 0.50, RiskScore: 100},
			{ID: "CVE-2", EPSS: 0.90, EPSSPercentile: 0.97, RiskScore: 300},
			{ID: "CVE-3", EPSS: 0.20, EPSSPercentile: 0.99, RiskScore: 200},
		},
	}
	v := sink.ToFindingView(f)
	if v.VulnCount != 3 {
		t.Errorf("vuln_count = %d, want 3", v.VulnCount)
	}
	if v.TopEPSS != 0.90 {
		t.Errorf("top_epss = %v, want the highest score", v.TopEPSS)
	}
	// The percentile of the worst-scoring CVE, not the highest percentile present:
	// 0.99 belongs to a CVE scoring 0.20, and reporting the pair as one CVE's
	// numbers would describe a vulnerability that does not exist.
	if v.TopEPSSPercentile != 0.97 {
		t.Errorf("top_epss_percentile = %v, want 0.97 (the worst score's own percentile)", v.TopEPSSPercentile)
	}
	if v.TopRiskScore != 300 {
		t.Errorf("top_risk_score = %v, want 300", v.TopRiskScore)
	}
}
