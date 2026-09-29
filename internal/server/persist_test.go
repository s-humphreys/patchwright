package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
	"github.com/s-humphreys/patchwright/pkg/history/postgres"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

// sourcedAssessor reports its configured sources, so the stored payload carries them.
type sourcedAssessor struct {
	stubAssessor
	sources model.Sources
}

func (s sourcedAssessor) Sources() model.Sources { return s.sources }

// persistStores runs a test against memStore and, when a database is available,
// against postgres.Lazy on a database of its own.
func persistStores(t *testing.T, run func(t *testing.T, store history.Store)) {
	t.Helper()
	t.Run("memStore", func(t *testing.T) { run(t, newMemStore()) })
	t.Run("postgres.Lazy", func(t *testing.T) {
		store := postgres.NewLazy(postgres.Options{DSN: isolatedPostgres(t)})
		t.Cleanup(store.Close)
		run(t, store)
	})
}

func estateFindings() []model.Finding {
	a := upgradable("acr.io/orders/app:1.0", "orders")
	a.Vulns = []model.Vulnerability{{ID: "CVE-2026-0001", Severity: model.SeverityCritical, FixAvailable: true, FixedVersion: "1.1", KEV: true, EPSS: 0.93}}
	b := assessedFinding("acr.io/billing/lib:2", "engineering", "billing", false)
	return []model.Finding{a, b, finding("mcr.io/managed:4", "cloud-provider", "aks", false, true)}
}

// waitFor polls until cond holds or fails the test.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func readyCode(h http.Handler) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return rec.Code
}

// withoutMeta decodes a response and drops the assessment block, which says when
// and by whom rather than what.
func withoutMeta(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	var body map[string]any
	if code := getJSON(t, h, path, &body); code != http.StatusOK {
		t.Fatalf("%s = %d", path, code)
	}
	delete(body, "assessment")
	out, _ := json.Marshal(body)
	return string(out)
}

// A restarted process serves what the last one stored, answer for answer, until its
// own first run completes, and says so.
func TestRestartServesTheStoredAssessment(t *testing.T) {
	persistStores(t, func(t *testing.T, store history.Store) {
		ctx := context.Background()
		before := New(sourcedAssessor{
			stubAssessor: stubAssessor{findings: estateFindings()},
			sources:      model.Sources{Provider: "rapid7", VulnSource: "trivy", Remediation: true},
		}).WithTickets(stubTickets{byImage: map[string][]ticket.Existing{
			"orders/app": {{Key: "DVOP-1", Status: "To Do", Category: "new"}},
		}}, "https://jira.example.com").WithHistory(store, 90*24*time.Hour)
		before.Refresh(ctx)
		original := before.meta()

		release := make(chan struct{})
		after := New(blockingAssessor{release: release}).WithHistory(store, 90*24*time.Hour)
		h := after.Handler()
		if readyCode(h) != http.StatusServiceUnavailable {
			t.Fatal("ready before anything was loaded")
		}
		runCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		done := make(chan struct{})
		go func() { after.Start(runCtx, 0); close(done) }()
		waitFor(t, "the stored assessment to be served", func() bool { return readyCode(h) == http.StatusOK })

		var got struct {
			Assessment map[string]any `json:"assessment"`
		}
		getJSON(t, h, "/api/v1/summary", &got)
		if got.Assessment["loaded_from_store"] != true || got.Assessment["running"] != true {
			t.Errorf("meta = %v, want loaded_from_store and running while the first run is in flight", got.Assessment)
		}
		stamp, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(got.Assessment["generated_at"]))
		if !stamp.Equal(original.GeneratedAt.Truncate(time.Microsecond)) && !stamp.Equal(*original.GeneratedAt) {
			t.Errorf("generated_at = %v, want the stored assessment's own %v", stamp, original.GeneratedAt)
		}

		bh := before.Handler()
		for _, path := range []string{
			"/api/v1/findings", "/api/v1/findings?vulns=false&team=orders", "/api/v1/finding?image=acr.io/orders/app:1.0",
			"/api/v1/owners", "/api/v1/summary", "/api/v1/analytics", "/api/v1/items", "/api/v1/cves",
			"/api/v1/service?repository=orders/app",
		} {
			if want, got := withoutMeta(t, bh, path), withoutMeta(t, h, path); want != got {
				t.Errorf("%s differs after the restart:\n got %s\nwant %s", path, got, want)
			}
		}
		// The MCP tools read the same projection.
		wantA, gotA := before.assessment(), after.assessment()
		for name, pair := range map[string][2]any{
			"findings": {wantA.Findings, gotA.Findings}, "analytics": {wantA.Analytics, gotA.Analytics},
			"sources": {wantA.Sources, gotA.Sources}, "provider_data_newest": {wantA.ProviderDataNewest, gotA.ProviderDataNewest},
		} {
			w, _ := json.Marshal(pair[0])
			g, _ := json.Marshal(pair[1])
			if !bytes.Equal(w, g) {
				t.Errorf("MCP assessment %s differs:\n got %s\nwant %s", name, g, w)
			}
		}

		// The first run replaces it, and the flag goes.
		close(release)
		<-done
		if after.meta().LoadedFromStore {
			t.Error("still marked loaded after a fresh run")
		}
		if m := after.meta(); m.GeneratedAt == nil || !m.GeneratedAt.After(*original.GeneratedAt) {
			t.Errorf("after the fresh run generated_at = %v, want later than %v", m.GeneratedAt, original.GeneratedAt)
		}
	})
}

// Ticket reconciliation and the history record act only on assessments this process
// ran: reconciling against data from before a restart could close a ticket on the
// strength of a fix since rolled back.
func TestLoadedAssessmentIsNeitherTicketedNorRecorded(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()
	New(stubAssessor{findings: estateFindings()}).WithHistory(store, 90*24*time.Hour).Refresh(ctx)
	recorded := len(store.assessments)

	st := newStubTicketer(draft("Upgrade app to 1.1", "orders/app"))
	release := make(chan struct{})
	s := New(blockingAssessor{release: release}).WithHistory(store, 90*24*time.Hour).WithTicketing(st, true)
	h := s.Handler()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { s.Start(runCtx, 0); close(done) }()
	waitFor(t, "the stored assessment", func() bool { return s.meta().LoadedFromStore })

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/tickets", strings.NewReader(`{"confirm": true}`)))
	if rec.Code != http.StatusConflict {
		t.Errorf("POST /api/v1/tickets on a loaded assessment = %d, want 409 (%s)", rec.Code, rec.Body)
	}
	// The plan is still readable: it writes nothing.
	if code := getJSON(t, h, "/api/v1/tickets", nil); code != http.StatusOK {
		t.Errorf("GET /api/v1/tickets = %d, want the plan", code)
	}
	if len(st.created) != 0 || len(store.assessments) != recorded {
		t.Fatalf("a loaded assessment was acted on: %d created, %d recorded (was %d)", len(st.created), len(store.assessments), recorded)
	}

	// With no interval, Start returns once the first run and everything after it is done.
	close(release)
	<-done
	if len(st.created) != 1 || len(store.assessments) != recorded+1 {
		t.Errorf("after a fresh run: %d created, %d recorded; want 1 and %d", len(st.created), len(store.assessments), recorded+1)
	}
}

// A failed first run does not dress the stored data up as new: it keeps the time it
// was made, stays marked as loaded, and states the failure.
func TestFailedRunKeepsTheLoadedAssessmentsAge(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()
	first := New(stubAssessor{findings: estateFindings()}).WithHistory(store, 90*24*time.Hour)
	first.Refresh(ctx)
	made := *first.meta().GeneratedAt

	s := New(stubAssessor{err: errors.New("provider unreachable")}).WithHistory(store, 90*24*time.Hour)
	s.restoreServed(ctx)
	s.Refresh(ctx)
	m := s.meta()
	if !m.LoadedFromStore || m.Error == "" || m.GeneratedAt == nil || !m.GeneratedAt.Equal(made) {
		t.Errorf("meta = %+v, want the loaded assessment of %v with the error stated", m, made)
	}
	if readyCode(s.Handler()) != http.StatusOK {
		t.Error("a failed run made a loaded assessment unready")
	}
}

// A fresh assessment that lands before the store answers wins.
func TestFreshAssessmentIsNotReplacedByALateLoad(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()
	New(stubAssessor{findings: estateFindings()}).WithHistory(store, 90*24*time.Hour).Refresh(ctx)

	s := New(stubAssessor{findings: []model.Finding{finding("acr.io/new:1", "engineering", "orders", true, false)}}).
		WithHistory(store, 90*24*time.Hour)
	s.Refresh(ctx)
	s.restoreServed(ctx)
	if s.meta().LoadedFromStore || len(s.snapshot().views) != 1 {
		t.Errorf("a late load replaced the fresh assessment: loaded=%v views=%d", s.meta().LoadedFromStore, len(s.snapshot().views))
	}
}

// Anything the store hands back that this build cannot read is ignored, and the
// process starts as it did before there was a store.
func TestUnreadableStoredAssessmentsAreIgnored(t *testing.T) {
	good, err := encodeServed(&snapshot{views: []sink.FindingView{}})
	if err != nil {
		t.Fatal(err)
	}
	var notJSON bytes.Buffer
	zw := gzip.NewWriter(&notJSON)
	_, _ = zw.Write([]byte("{not json"))
	_ = zw.Close()
	var noViews bytes.Buffer
	zw = gzip.NewWriter(&noViews)
	_, _ = zw.Write([]byte(`{"summary":{}}`))
	_ = zw.Close()

	for name, row := range map[string]history.ServedAssessment{
		"another schema":      {SchemaVersion: servedSchemaVersion + 1, Payload: good},
		"not gzip":            {SchemaVersion: servedSchemaVersion, Payload: []byte("plain")},
		"not json":            {SchemaVersion: servedSchemaVersion, Payload: notJSON.Bytes()},
		"no findings list":    {SchemaVersion: servedSchemaVersion, Payload: noViews.Bytes()},
		"empty payload":       {SchemaVersion: servedSchemaVersion},
		"an older build's v0": {SchemaVersion: 0, Payload: good},
	} {
		t.Run(name, func(t *testing.T) {
			store := newMemStore()
			row.GeneratedAt, row.Version = time.Now().Add(-time.Hour), "v0.0.1"
			if err := store.SaveServed(context.Background(), row, servedKeep); err != nil {
				t.Fatal(err)
			}
			s := New(stubAssessor{}).WithHistory(store, 90*24*time.Hour)
			s.restoreServed(context.Background())
			if s.snapshot() != nil || s.meta().LoadedFromStore || readyCode(s.Handler()) != http.StatusServiceUnavailable {
				t.Errorf("an unreadable stored assessment was served")
			}
		})
	}
}

// An unreachable database at start costs the fast start and nothing else.
func TestUnreachableStoreFallsBackToAColdStart(t *testing.T) {
	for name, store := range map[string]history.Store{
		"store error": func() history.Store { m := newMemStore(); m.err = errors.New("connection refused"); return m }(),
		// Nothing listens on port 1, so this fails at once rather than timing out.
		"postgres.Lazy": postgres.NewLazy(postgres.Options{DSN: "postgres://patchwright@127.0.0.1:1/patchwright?sslmode=disable&connect_timeout=2"}),
	} {
		t.Run(name, func(t *testing.T) {
			s := New(stubAssessor{findings: estateFindings()}).WithHistory(store, 90*24*time.Hour)
			done := make(chan struct{})
			go func() { s.restoreServed(context.Background()); close(done) }()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				t.Fatal("restoring from an unreachable store did not return")
			}
			if s.snapshot() != nil {
				t.Fatal("something was served from an unreachable store")
			}
			s.Refresh(context.Background())
			if readyCode(s.Handler()) != http.StatusOK || s.meta().LoadedFromStore {
				t.Errorf("the assessment did not serve as before with the store down")
			}
		})
	}
}

// Without a store nothing is persisted or loaded, and the API says nothing about it.
func TestNoStoreMeansNoLoadedFlag(t *testing.T) {
	s := New(stubAssessor{findings: estateFindings()})
	s.restoreServed(context.Background())
	if s.snapshot() != nil {
		t.Fatal("loaded something without a store")
	}
	s.Refresh(context.Background())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil))
	if strings.Contains(rec.Body.String(), "loaded_from_store") {
		t.Errorf("loaded_from_store appears without a store: %s", rec.Body)
	}
}

// productionShaped builds views the size of the estate the transport comments
// measured: 612 findings carrying 208,697 CVEs, drawn from a shared pool the way
// real images share their CVEs.
func productionShaped() *snapshot {
	const findings, cves, pool = 612, 208697, 24000
	rng := rand.New(rand.NewSource(1))
	severities := []string{"critical", "high", "medium", "low"}
	seen := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	views := make([]sink.FindingView, 0, findings)
	for i := 0; i < findings; i++ {
		n := cves / findings
		if i < cves%findings {
			n++
		}
		vulns := make([]sink.VulnView, n)
		for j := range vulns {
			id := rng.Intn(pool)
			first := seen.Add(time.Duration(id) * time.Hour)
			vulns[j] = sink.VulnView{
				ID: fmt.Sprintf("CVE-20%02d-%05d", 18+id%8, id), Severity: severities[id%4], FirstSeen: &first,
				CVSS: float64(id%100) / 10, FixAvailable: id%3 != 0, FixedVersion: fmt.Sprintf("%d.%d.%d", id%5, id%17, id%29),
				EPSS: float64(id%10000) / 10000, EPSSPercentile: float64(id%1000) / 1000, KEV: id%97 == 0,
				RiskScore: float64(id % 1000), Origin: []string{"base", "app"}[id%2], OriginDetermined: true,
				Packages: []sink.PackageView{{Name: fmt.Sprintf("pkg-%d", id%400), Ecosystem: "deb", FixedIn: fmt.Sprintf("%d.%d", id%7, id%11)}},
			}
		}
		team := fmt.Sprintf("team-%d", i%40)
		views = append(views, sink.FindingView{
			Image: fmt.Sprintf("acr.example.io/%s/svc-%d:1.%d.%d", team, i, i%9, i%13), Registry: "acr.example.io",
			Repository: fmt.Sprintf("%s/svc-%d", team, i), Tag: fmt.Sprintf("1.%d.%d", i%9, i%13),
			Owner: sink.OwnerView{Class: "engineering", Team: team, Rule: "namespace"}, Counts: map[string]int{"critical": n / 10, "high": n / 4},
			Risk: float64(i), Actionable: i%2 == 0, Priority: "high", Reasons: []string{"fixable critical"}, Rule: "any-critical",
			WorkloadCount: 1 + i%5, VulnCount: n, ProviderAssessed: true, Scanned: true, ExploitChecked: true,
			RemediationChecked: true, Upgrade: &sink.UpgradeView{Kind: "helm", Name: "svc", Current: "1.0", Latest: "1.1", Available: true, Resolved: true},
			Dimensions: map[string][]string{"cluster": {"uks-prod"}, "namespace": {team}}, Vulns: vulns,
		})
	}
	return &snapshot{views: views, summary: summaryView{Findings: findings}}
}

// The payload is measured at production scale, and stored compressed because of what
// the measurement says: tens of megabytes as JSON, a few once gzipped.
func TestServedPayloadSizeAtProductionScale(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a production-sized payload")
	}
	snap := productionShaped()
	raw, err := json.Marshal(servedPayload{Views: snap.views, Summary: snap.summary})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	payload, err := encodeServed(snap)
	if err != nil {
		t.Fatal(err)
	}
	encoded := time.Since(start)
	start = time.Now()
	back, err := decodeServed(payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded := time.Since(start)
	t.Logf("production-shaped payload: %d findings, %.1f MB JSON, %.2f MB gzipped (%.0fx); encode %v, decode %v",
		len(snap.views), float64(len(raw))/1e6, float64(len(payload))/1e6, float64(len(raw))/float64(len(payload)),
		encoded.Round(time.Millisecond), decoded.Round(time.Millisecond))
	if len(raw) < 20e6 {
		t.Errorf("the fixture is %d bytes of JSON, smaller than the estate it stands in for", len(raw))
	}
	if len(payload) > len(raw)/5 {
		t.Errorf("gzip only took %d bytes to %d", len(raw), len(payload))
	}
	if !reflect.DeepEqual(back.views, snap.views) {
		t.Error("the production-shaped views did not survive the round trip")
	}

	// And a real database takes it inside the query timeout.
	t.Run("postgres", func(t *testing.T) {
		store := postgres.NewLazy(postgres.Options{DSN: isolatedPostgres(t)})
		defer store.Close()
		ctx := context.Background()
		at := time.Now().UTC().Truncate(time.Microsecond)
		if err := store.SaveServed(ctx, history.ServedAssessment{GeneratedAt: at, Version: "test", SchemaVersion: servedSchemaVersion, Payload: payload}, servedKeep); err != nil {
			t.Fatalf("save: %v", err)
		}
		row, err := store.LatestServed(ctx, time.Time{})
		if err != nil || row == nil || !bytes.Equal(row.Payload, payload) {
			t.Fatalf("read back %v, %v", row != nil, err)
		}
	})
}
