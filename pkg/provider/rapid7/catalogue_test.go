package rapid7

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/enrich"
)

// The duplication this exists to remove: ages and exploit intelligence read the same
// endpoint, and on a real estate each sweep was about two minutes of a ten-minute
// assessment.

// catalogueServer answers the vulnerability listing and counts how many times the
// whole thing was swept.
func catalogueServer(t *testing.T, requests *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"data":[
			{"cve_id":"CVE-2026-1","first_found":"2026-01-15T00:00:00Z","riskscore":812,"has_exploits":true},
			{"cve_id":"CVE-2026-2","first_found":"2026-06-01T00:00:00Z","riskscore":140}
		],"page":1,"page_size":2,"total_count":2,"total_pages":1}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestBothSourcesShareOneSweepWithinARun(t *testing.T) {
	var requests atomic.Int64
	srv := catalogueServer(t, &requests)
	api := &apiProvider{baseURL: srv.URL, apiKey: "k", client: srv.Client()}
	ages := &ageSource{api: api}
	exploits := &exploitSource{api: api}

	ctx := enrich.WithRunCache(context.Background())
	ids := []string{"CVE-2026-1", "CVE-2026-2"}

	seen, err := ages.FirstSeen(ctx, ids)
	if err != nil {
		t.Fatalf("ages: %v", err)
	}
	info, err := exploits.Lookup(ctx, ids)
	if err != nil {
		t.Fatalf("exploits: %v", err)
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("the catalogue was swept %d times in one run, want 1", got)
	}
	// And both still get their own fields out of it.
	if len(seen) != 2 || seen["CVE-2026-1"].Year() != 2026 {
		t.Errorf("ages lost data when sharing the sweep: %+v", seen)
	}
	if info["CVE-2026-1"].RiskScore != 812 || !info["CVE-2026-1"].ExploitKnown {
		t.Errorf("exploit intel lost data when sharing the sweep: %+v", info["CVE-2026-1"])
	}
	if info["CVE-2026-2"].RiskScore != 140 || info["CVE-2026-2"].ExploitKnown {
		t.Errorf("wrong row read for the second CVE: %+v", info["CVE-2026-2"])
	}
}

// The memo is per RUN, not per process. A cache with its own lifetime would need a
// time-to-live, and a stale one would report last hour's exploit intelligence as this
// hour's - which is exactly the kind of quiet ageing this tool exists to expose.
func TestASecondRunSweepsAgain(t *testing.T) {
	var requests atomic.Int64
	srv := catalogueServer(t, &requests)
	api := &apiProvider{baseURL: srv.URL, apiKey: "k", client: srv.Client()}
	exploits := &exploitSource{api: api}

	for run := 0; run < 3; run++ {
		if _, err := exploits.Lookup(enrich.WithRunCache(context.Background()), []string{"CVE-2026-1"}); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
	}
	if got := requests.Load(); got != 3 {
		t.Errorf("three runs made %d sweeps, want one each: a run must not reuse another's data", got)
	}
}

// Used outside a pipeline - a one-off command, a test - there is no memo on the
// context, and the source has to work exactly as it did before.
func TestASourceWithoutARunCacheStillWorks(t *testing.T) {
	var requests atomic.Int64
	srv := catalogueServer(t, &requests)
	api := &apiProvider{baseURL: srv.URL, apiKey: "k", client: srv.Client()}

	seen, err := (&ageSource{api: api}).FirstSeen(context.Background(), []string{"CVE-2026-2"})
	if err != nil {
		t.Fatalf("ages: %v", err)
	}
	if len(seen) != 1 {
		t.Errorf("got %d dated CVEs, want 1", len(seen))
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("swept %d times, want 1", got)
	}
}

// Two platforms must not share an answer. The key includes the base URL for exactly
// this reason.
func TestDifferentPlatformsDoNotShareASweep(t *testing.T) {
	var a, b atomic.Int64
	srvA, srvB := catalogueServer(t, &a), catalogueServer(t, &b)
	ctx := enrich.WithRunCache(context.Background())

	if _, err := (&ageSource{api: &apiProvider{baseURL: srvA.URL, apiKey: "k", client: srvA.Client()}}).
		FirstSeen(ctx, []string{"CVE-2026-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&ageSource{api: &apiProvider{baseURL: srvB.URL, apiKey: "k", client: srvB.Client()}}).
		FirstSeen(ctx, []string{"CVE-2026-1"}); err != nil {
		t.Fatal(err)
	}
	if a.Load() != 1 || b.Load() != 1 {
		t.Errorf("each platform should have been swept once, got %d and %d", a.Load(), b.Load())
	}
}

// A failed sweep is remembered for the run rather than repeated by the next stage.
// Both stages want the same answer, and a platform that has just refused one
// two-minute sweep is not more likely to satisfy a second.
func TestAFailedSweepIsNotRepeatedWithinARun(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	api := &apiProvider{baseURL: srv.URL, apiKey: "k", client: srv.Client()}

	ctx := enrich.WithRunCache(context.Background())
	if _, err := (&ageSource{api: api}).FirstSeen(ctx, []string{"CVE-2026-1"}); err == nil {
		t.Fatal("want an error from a failing platform")
	}
	if _, err := (&exploitSource{api: api}).Lookup(ctx, []string{"CVE-2026-1"}); err == nil {
		t.Fatal("the second stage must still see the failure, not an empty success")
	}
	// The retries inside the client are its own business; what matters is that the
	// second stage did not start a fresh sweep.
	before := requests.Load()
	if _, err := (&exploitSource{api: api}).Lookup(ctx, []string{"CVE-2026-1"}); err == nil {
		t.Fatal("want the remembered failure")
	}
	if requests.Load() != before {
		t.Errorf("a third caller re-requested: %d then %d", before, requests.Load())
	}
}
