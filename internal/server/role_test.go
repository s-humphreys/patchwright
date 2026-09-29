package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
	"github.com/s-humphreys/patchwright/pkg/history/postgres"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// countingAssessor counts runs, so a test can prove none happened.
type countingAssessor struct{ runs *atomic.Int32 }

func (c countingAssessor) Run(context.Context) ([]model.Finding, error) {
	c.runs.Add(1)
	return estateFindings(), nil
}

// gatedAssessor holds each run until the test sends the findings it should return.
type gatedAssessor struct{ gate chan []model.Finding }

func (g gatedAssessor) Run(ctx context.Context) ([]model.Finding, error) {
	select {
	case f := <-g.gate:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *memStore) servedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.served)
}

func (m *memStore) assessmentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.assessments)
}

func (m *memStore) workerRow() history.WorkerState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.worker
}

func post(h http.Handler, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

func TestParseRole(t *testing.T) {
	for in, want := range map[string]Role{"": RoleAll, "all": RoleAll, "worker": RoleWorker, "web": RoleWeb} {
		if got, err := ParseRole(in); err != nil || got != want {
			t.Errorf("ParseRole(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseRole("Web"); err == nil {
		t.Error("an unknown role was accepted")
	}
}

// A web replica never runs the assessor, whatever it is asked: on its schedule, by
// the Refresh button, or directly.
func TestWebNeverAssesses(t *testing.T) {
	var runs atomic.Int32
	store := newMemStore()
	web := New(countingAssessor{&runs}).WithRole(RoleWeb).WithHistory(store, 90*24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { web.Start(ctx, time.Millisecond); close(done) }()

	rec := post(web.Handler(), "/api/v1/assessments", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/v1/assessments = %d (%s)", rec.Code, rec.Body)
	}
	web.Refresh(ctx)
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if n := runs.Load(); n != 0 {
		t.Errorf("a web replica ran %d assessments", n)
	}
	if store.workerRow().RefreshRequested == nil {
		t.Error("the refresh request was not recorded for the worker")
	}
	if store.assessmentCount() != 0 || store.servedCount() != 0 {
		t.Error("a web replica wrote to the record")
	}
}

// A web replica never writes to a tracker: applying is refused, the plan is still
// shown, and nothing is created.
func TestWebNeverWritesTickets(t *testing.T) {
	store := newMemStore()
	New(stubAssessor{findings: estateFindings()}).WithRole(RoleWorker).WithHistory(store, 90*24*time.Hour).Refresh(context.Background())

	st := newStubTicketer(draft("Upgrade app to 1.1", "orders/app"))
	web := New(nil).WithRole(RoleWeb).WithHistory(store, 90*24*time.Hour).WithTicketing(st, false)
	web.webTick(context.Background(), true)
	h := web.Handler()
	if rec := post(h, "/api/v1/tickets", `{"confirm": true}`); rec.Code != http.StatusConflict {
		t.Errorf("POST /api/v1/tickets on a web replica = %d, want 409 (%s)", rec.Code, rec.Body)
	}
	if code := getJSON(t, h, "/api/v1/tickets", nil); code != http.StatusOK {
		t.Errorf("GET /api/v1/tickets = %d, want the plan", code)
	}
	if len(st.created)+len(st.closed)+len(st.updated)+len(st.comments)+len(st.extended) != 0 {
		t.Errorf("a web replica wrote to the tracker: %+v", st)
	}
}

// The worker serves its probes and its metrics, and nothing that reads the
// assessment: that is the web replicas' job.
func TestWorkerServesOnlyProbesAndMetrics(t *testing.T) {
	store := newMemStore()
	worker := New(stubAssessor{findings: estateFindings()}).WithRole(RoleWorker).WithHistory(store, 90*24*time.Hour)
	worker.Refresh(context.Background())
	h := worker.Handler()
	for path, want := range map[string]int{
		"/healthz": http.StatusOK, "/readyz": http.StatusOK, "/metrics": http.StatusOK,
		"/api/v1/findings": http.StatusNotFound, "/": http.StatusNotFound, "/api/v1/summary": http.StatusNotFound,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("worker GET %s = %d, want %d", path, rec.Code, want)
		}
	}
	if rec := post(h, "/api/v1/assessments", ""); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("worker POST /api/v1/assessments = %d, want it not served", rec.Code)
	}
	if store.servedCount() != 1 {
		t.Errorf("the worker stored %d assessments, want 1", store.servedCount())
	}
	if w := store.workerRow(); w.Heartbeat.IsZero() || w.Running || w.Version == "" {
		t.Errorf("worker state = %+v, want a heartbeat, not running, and a version", w)
	}
}

// A request made before the worker started is answered by the run it starts with,
// not by a second one straight after.
func TestWorkerTakesEarlierRequestsAsHandled(t *testing.T) {
	var runs atomic.Int32
	store := newMemStore()
	_ = store.RequestRefresh(context.Background(), time.Now().Add(-time.Minute))
	worker := New(countingAssessor{&runs}).WithRole(RoleWorker).WithHistory(store, 90*24*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	worker.runWorker(ctx)
	if worker.workerTick(context.Background()) {
		t.Error("a request from before the worker started triggered a run")
	}
	if w := store.workerRow(); w.RefreshHandled == nil || !w.RefreshHandled.Equal(*w.RefreshRequested) {
		t.Errorf("worker state = %+v, want the earlier request reported as handled", w)
	}
}

// Two processes and one store, as the chart deploys them: the worker's runs reach
// the web replica, the web replica's Refresh reaches the worker, and the running flag
// the page shows is the worker's. On postgres each side has its own connection pool,
// as two pods would.
func TestSplitWorkerAndWebEndToEnd(t *testing.T) {
	t.Run("memStore", func(t *testing.T) {
		store := newMemStore()
		splitEndToEnd(t, store, store)
	})
	t.Run("postgres.Lazy", func(t *testing.T) {
		dsn := isolatedPostgres(t)
		workerStore, webStore := postgres.NewLazy(postgres.Options{DSN: dsn}), postgres.NewLazy(postgres.Options{DSN: dsn})
		t.Cleanup(workerStore.Close)
		t.Cleanup(webStore.Close)
		splitEndToEnd(t, workerStore, webStore)
	})
}

func splitEndToEnd(t *testing.T, workerStore, webStore history.Store) {
	ctx := context.Background()
	gate := make(chan []model.Finding)
	worker := New(gatedAssessor{gate}).WithRole(RoleWorker).WithHistory(workerStore, 90*24*time.Hour)
	web := New(nil).WithRole(RoleWeb).WithHistory(webStore, 90*24*time.Hour)
	wh := web.Handler()
	row := func() history.WorkerState {
		t.Helper()
		st, err := webStore.WorkerState(ctx)
		if err != nil {
			t.Fatalf("worker state: %v", err)
		}
		return st
	}
	summary := func() assessmentMeta {
		t.Helper()
		var body struct {
			Assessment assessmentMeta `json:"assessment"`
		}
		getJSON(t, wh, "/api/v1/summary", &body)
		return body.Assessment
	}

	// The worker's first run: the web replica has nothing to serve yet, and says the
	// worker is running.
	go worker.Refresh(ctx)
	waitFor(t, "the worker to report running", func() bool { return row().Running })
	web.webTick(ctx, true)
	if m := summary(); !m.Running || m.StartedAt == nil {
		t.Errorf("web meta = %+v, want the worker's run shown as running with its start", m)
	}
	if readyCode(wh) != http.StatusServiceUnavailable {
		t.Error("the web replica is ready with nothing stored")
	}

	gate <- estateFindings()
	waitFor(t, "the worker to finish", func() bool { return !row().Running })
	web.webTick(ctx, false) // the finished run is seen, and prompts a look for its assessment
	if readyCode(wh) != http.StatusOK {
		t.Fatal("the web replica is not serving the worker's assessment")
	}
	first := summary()
	if first.Running || first.GeneratedAt == nil || first.LoadedFromStore {
		t.Errorf("web meta after the run = %+v", first)
	}
	var findings struct {
		Count int `json:"count"`
	}
	getJSON(t, wh, "/api/v1/findings", &findings)
	if findings.Count != 2 {
		t.Errorf("web serves %d findings, want the worker's 2 unsuppressed", findings.Count)
	}

	// The Refresh button on the web replica: accepted, shown as running at once, and
	// picked up by the worker's next poll.
	rec := post(wh, "/api/v1/assessments", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/v1/assessments = %d (%s)", rec.Code, rec.Body)
	}
	if m := summary(); !m.Running {
		t.Error("a pending request did not read as running")
	}
	if !worker.workerTick(ctx) {
		t.Fatal("the worker did not pick up the request")
	}
	waitFor(t, "the requested run to start", func() bool { return row().Running })
	web.webTick(ctx, false)
	if m := summary(); !m.Running || m.StartedAt == nil {
		t.Errorf("web meta during the requested run = %+v", m)
	}
	if worker.workerTick(ctx) {
		t.Error("the worker acted on the same request twice")
	}

	gate <- append(estateFindings(), finding("acr.io/new:1", "engineering", "orders", true, false))
	waitFor(t, "the requested run to finish", func() bool { return !row().Running })
	web.webTick(ctx, false)
	second := summary()
	if second.Running || second.GeneratedAt == nil || !second.GeneratedAt.After(*first.GeneratedAt) {
		t.Errorf("web meta after the requested run = %+v, want a newer assessment than %v", second, first.GeneratedAt)
	}
	getJSON(t, wh, "/api/v1/findings", &findings)
	if findings.Count != 3 {
		t.Errorf("web serves %d findings, want the second run's 3", findings.Count)
	}

	// Only the worker recorded anything.
	waitFor(t, "the worker's history record", func() bool {
		got, err := webStore.Assessments(ctx, time.Time{}, time.Now().Add(time.Hour))
		return err == nil && len(got) == 2
	})

	// A worker that stops reporting is not believed: not running, and said so.
	stale := row()
	stale.Heartbeat, stale.Running = time.Now().Add(-2*workerStale), true
	if err := workerStore.SaveWorkerState(ctx, stale); err != nil {
		t.Fatal(err)
	}
	web.webTick(ctx, false)
	if m := summary(); m.Running || !strings.Contains(m.Error, "has not reported") {
		t.Errorf("web meta with a silent worker = %+v", m)
	}
	if readyCode(wh) != http.StatusOK {
		t.Error("a silent worker made the web replica unready; it should keep serving what is stored")
	}
}

// The history status a web replica reports is the worker's: it records nothing of its own.
func TestWebReportsTheWorkersHistoryStatus(t *testing.T) {
	store := newMemStore()
	worker := New(stubAssessor{findings: estateFindings()}).WithRole(RoleWorker).WithHistory(store, 90*24*time.Hour)
	worker.Refresh(context.Background())
	worker.reportWorkerState(context.Background())
	web := New(nil).WithRole(RoleWeb).WithHistory(store, 90*24*time.Hour)
	web.webTick(context.Background(), true)
	if st := web.historyStatus(); !st.Enabled || st.LastRecorded == nil || st.RetentionDays != 90 {
		t.Errorf("web history status = %+v, want the worker's last record", st)
	}
}

// The plan a web replica previews holds tickets for items in their grace period, as
// the worker's would: it reads them from the record rather than from its own memory,
// which holds none.
func TestWebReadsRecentlyMissingFromTheRecord(t *testing.T) {
	store := newMemStore()
	store.items[1] = &history.State{ID: 1, Missing: 1, Current: history.Snapshot{Repository: "orders/app"}}
	store.items[2] = &history.State{ID: 2, Current: history.Snapshot{Repository: "billing/lib"}}
	web := New(nil).WithRole(RoleWeb).WithHistory(store, 90*24*time.Hour)
	got := web.recentlyMissingFromStore(context.Background())
	if !got["orders/app"] || got["billing/lib"] || len(got) != 1 {
		t.Errorf("recently missing = %v, want orders/app only", got)
	}
}
