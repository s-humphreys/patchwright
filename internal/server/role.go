package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/s-humphreys/patchwright/internal/version"
	"github.com/s-humphreys/patchwright/pkg/history"
)

// Splitting the process in two.
//
// By default one process assesses and serves (RoleAll), and that stays the default:
// it is the whole tool with no database. With a history store, a deployment can run
// the two halves apart. The worker assesses, reconciles tickets, records history and
// stores each assessment; it serves only its probes and /metrics. Web replicas never
// assess and never write to a tracker or the record: they serve the page, the API and
// MCP from the newest stored assessment and the record, and hand requests for a fresh
// assessment to the worker through the store.
//
// Everything between them goes through the database both already need, rather than
// over HTTP between the pods. A refresh request is a timestamp the worker polls for,
// so a request made while the worker is restarting is waiting for it when it comes
// back, instead of failing against a Service with no endpoints; and neither side needs
// a route, a credential or a NetworkPolicy rule to reach the other.

// Role is which half of the work a process does.
type Role string

const (
	RoleAll    Role = "all"
	RoleWorker Role = "worker"
	RoleWeb    Role = "web"
)

// ParseRole reads a --role value. Empty is RoleAll.
func ParseRole(v string) (Role, error) {
	switch Role(v) {
	case "", RoleAll:
		return RoleAll, nil
	case RoleWorker, RoleWeb:
		return Role(v), nil
	}
	return "", fmt.Errorf("unknown role %q: want all, worker or web", v)
}

// WithRole sets which half of the work this process does. Worker and web need a
// history store, which the caller checks: it is the only thing between them.
func (s *Server) WithRole(r Role) *Server {
	s.role = r
	return s
}

var (
	// workerPoll is how often the worker reports a heartbeat and looks for a refresh
	// request, so a request waits at most this long.
	workerPoll = 10 * time.Second
	// workerStale is how long without a heartbeat before a web replica stops
	// believing the worker's row. Several polls, so one slow write is not an outage.
	workerStale = 6 * workerPoll
	// webStatePoll is how often a web replica reads the worker's row: one small row,
	// read often so the Refresh button and the running flag feel immediate.
	webStatePoll = 5 * time.Second
	// webServedPoll is how often a web replica asks whether a newer assessment has
	// been stored, beside the check made whenever the worker reports a run finished.
	// An indexed query that returns nothing unless there is something new.
	webServedPoll = 30 * time.Second
)

// workerRoutes are all a worker serves: the probes for its own pod, and the metrics,
// which describe the runs it makes.
var workerRoutes = map[string]bool{"GET /healthz": true, "GET /readyz": true, "GET /metrics": true}

// runWorker heartbeats and picks up refresh requests until ctx ends.
func (s *Server) runWorker(ctx context.Context) {
	// A request made before this process started is answered by the run it starts
	// with, so it is taken as handled rather than triggering a second.
	if st, err := s.history.store.WorkerState(ctx); err == nil {
		s.mu.Lock()
		s.refreshHandled = st.RefreshRequested
		s.mu.Unlock()
	}
	t := time.NewTicker(workerPoll)
	defer t.Stop()
	for {
		s.workerTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// workerTick is one poll: start an assessment if one was asked for, then report.
// It returns whether it started one.
func (s *Server) workerTick(ctx context.Context) bool {
	started := false
	st, err := s.history.store.WorkerState(ctx)
	if err != nil {
		s.storeTrouble(ctx, "read refresh requests", err)
	} else if req := st.RefreshRequested; req != nil {
		s.mu.Lock()
		pending := s.refreshHandled == nil || req.After(*s.refreshHandled)
		if pending {
			// Handled whether or not a run starts: one already in flight answers it,
			// as a second POST during a run does in a single process.
			t := *req
			s.refreshHandled = &t
		}
		s.mu.Unlock()
		if pending {
			slog.InfoContext(ctx, "server: assessment requested through the store", "requested_at", req.Format(time.RFC3339))
			started = true
			go s.Refresh(ctx)
		}
	}
	s.reportWorkerState(ctx)
	return started
}

// reportWorkerState writes the worker's row. A no-op outside the worker role.
func (s *Server) reportWorkerState(ctx context.Context) {
	if s.role != RoleWorker || s.history == nil {
		return
	}
	// Held from reading the state to writing it, so a report read before a run
	// started cannot land after the run's own and put "not running" back.
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	st := history.WorkerState{Heartbeat: time.Now().UTC(), Version: version.String()}
	s.mu.RLock()
	st.Running = s.running
	if s.running {
		t := s.startedAt
		st.StartedAt = &t
	}
	if s.latest != nil {
		st.LastError = s.latest.err
	}
	st.RefreshHandled = s.refreshHandled
	s.mu.RUnlock()
	hs := s.historyStatus()
	st.HistoryRecorded, st.HistoryError = hs.LastRecorded, hs.LastError
	if err := s.history.store.SaveWorkerState(ctx, st); err != nil {
		s.storeTrouble(ctx, "report the worker's state", err)
	}
}

// runWeb keeps a web replica's copy of the assessment and the worker's state current
// until ctx ends. It never assesses.
func (s *Server) runWeb(ctx context.Context) {
	s.webTick(ctx, true)
	state := time.NewTicker(webStatePoll)
	defer state.Stop()
	served := time.NewTicker(webServedPoll)
	defer served.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-state.C:
			s.webTick(ctx, false)
		case <-served.C:
			s.webTick(ctx, true)
		}
	}
}

// webTick reads the worker's row and, when asked or when the worker has just
// finished a run, looks for a newer stored assessment.
func (s *Server) webTick(ctx context.Context, checkServed bool) {
	st, err := s.history.store.WorkerState(ctx)
	if err != nil {
		s.storeTrouble(ctx, "read the worker's state", err)
	} else {
		s.mu.Lock()
		finished := s.worker.Running && !st.Running
		// A request this replica has just recorded may not be in what it read back if
		// the read raced the write; keep the newer.
		if mine := s.worker.RefreshRequested; mine != nil && (st.RefreshRequested == nil || mine.After(*st.RefreshRequested)) {
			st.RefreshRequested = mine
		}
		s.worker = st
		s.mu.Unlock()
		checkServed = checkServed || finished
	}
	if checkServed {
		s.loadNewerServed(ctx)
	}
}

// loadNewerServed swaps in a stored assessment newer than the one held.
func (s *Server) loadNewerServed(ctx context.Context) {
	var after time.Time
	if snap := s.snapshot(); snap != nil {
		after = snap.generatedAt
	}
	snap, row := s.latestServed(ctx, after)
	if snap == nil {
		return
	}
	s.mu.Lock()
	if s.latest != nil && !snap.generatedAt.After(s.latest.generatedAt) {
		s.mu.Unlock()
		return
	}
	s.latest = snap
	s.mu.Unlock()
	slog.InfoContext(ctx, "server: serving a newer stored assessment",
		"generated_at", row.GeneratedAt.Format(time.RFC3339), "stored_by", row.Version, "findings", len(snap.views))
}

// webMeta fills the parts of the meta a web replica learns from the worker's row:
// whether an assessment is running, and how the last one ended. Called with s.mu
// held for reading.
func (s *Server) webMeta(m *assessmentMeta, now time.Time) {
	w := s.worker
	alive := !w.Heartbeat.IsZero() && now.Sub(w.Heartbeat) < workerStale
	pending := w.RefreshRequested != nil && (w.RefreshHandled == nil || w.RefreshRequested.After(*w.RefreshHandled))
	// A request not yet picked up reads as running, so the Refresh button does not
	// flick back to idle for the few seconds before the worker's next poll.
	m.Running = alive && (w.Running || pending)
	m.StartedAt = nil
	if alive && w.Running && w.StartedAt != nil {
		t := *w.StartedAt
		m.StartedAt = &t
	}
	m.Error = w.LastError
	if !alive && !w.Heartbeat.IsZero() {
		m.Error = fmt.Sprintf("the assessment worker has not reported since %s; what is served is the last assessment it stored",
			w.Heartbeat.UTC().Format(time.RFC3339))
	}
}

// requestRefresh is POST /api/v1/assessments on a web replica: record the request
// for the worker rather than run anything here.
func (s *Server) requestRefresh(w http.ResponseWriter, r *http.Request) {
	// Microseconds, which is what postgres keeps: the copy held here is compared with
	// the worker's handled time read back from the store, and a nanosecond remainder
	// would leave the request looking pending for ever.
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.history.store.RequestRefresh(r.Context(), now); err != nil {
		writeError(w, http.StatusServiceUnavailable, "could not pass the request to the assessment worker: "+err.Error())
		return
	}
	s.mu.Lock()
	s.worker.RefreshRequested = &now
	s.mu.Unlock()
	writeJSON(w, http.StatusAccepted, struct {
		Assessment assessmentMeta `json:"assessment"`
		Message    string         `json:"message"`
	}{s.meta(), "assessment requested; the worker picks requests up within " + workerPoll.String()})
}

// recentlyMissingFromStore is recentlyMissing for a web replica, which records
// nothing and so holds no open items of its own: the worker's, read from the record,
// so the plan a web replica previews is the plan the worker would apply.
func (s *Server) recentlyMissingFromStore(ctx context.Context) map[string]bool {
	open, err := s.history.store.Open(ctx)
	if err != nil {
		slog.WarnContext(ctx, "server: could not read open items for the ticket plan; items in their grace period are not held", "error", err)
		return nil
	}
	out := map[string]bool{}
	for _, st := range open {
		if st.Missing > 0 {
			out[st.Current.Repository] = true
		}
	}
	return out
}
