package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/s-humphreys/patchwright/internal/mcp"
	"github.com/s-humphreys/patchwright/pkg/history"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

// History wiring: after each successful assessment the server diffs the queue
// against the items the store holds open and records the transitions, then
// attributes any tickets reconciliation raised to those items. Failures are logged
// and dropped, like ticketing: the assessment is the service's job, and an outage
// of the record must not become an outage of the queue.

// defaultHistorySince is the range the API reports when none is asked for: the
// three-month lookback the design was asked for.
const defaultHistorySince = 90 * 24 * time.Hour

type historyRecorder struct {
	store      history.Store
	retention  time.Duration
	lapseAfter int

	mu sync.Mutex
	// assessmentID and open are from the most recent record, so ticket events
	// written after reconciliation attach to the same run and the same items.
	assessmentID int64
	open         []history.State
	// closedReasons are the tickets the last reconciliation closed and why, so the
	// next diff can say a ticket left the index because patchwright closed it.
	closedReasons map[string]string
	lastErr       string
	lastRecorded  time.Time
	lastPruned    history.Pruned
}

// WithHistory attaches a store. retention bounds what Prune keeps; it is required
// by configuration, so zero here is a programming error rather than "forever".
func (s *Server) WithHistory(store history.Store, retention time.Duration) *Server {
	if store == nil {
		return s
	}
	s.history = &historyRecorder{store: store, retention: retention, lapseAfter: history.DefaultLapseAfter}
	return s
}

// WithLapseAfter sets the grace period before an absent item lapses.
func (s *Server) WithLapseAfter(runs int) *Server {
	if s.history != nil && runs > 0 {
		s.history.lapseAfter = runs
	}
	return s
}

// recentlyMissing lists the repositories of open items that were absent from the
// latest assessment but are still inside the grace period. Ticket reconciliation
// holds tickets for those rather than telling them coverage is gone.
func (s *Server) recentlyMissing() map[string]bool {
	if s.history == nil {
		return nil
	}
	s.history.mu.Lock()
	defer s.history.mu.Unlock()
	out := map[string]bool{}
	for _, st := range s.history.open {
		if st.Missing > 0 {
			out[st.Current.Repository] = true
		}
	}
	return out
}

// recordHistory diffs a published snapshot against the open items and writes the
// result. started is when the assessment began.
func (s *Server) recordHistory(ctx context.Context, snap *snapshot, started time.Time) {
	rec := s.history
	if rec == nil || snap == nil || snap.err != "" {
		return
	}
	tickets := openTicketKeys(snap.tickets)
	rec.mu.Lock()
	closedReasons := rec.closedReasons
	rec.closedReasons = nil
	rec.mu.Unlock()
	open, err := rec.store.Open(ctx)
	if err != nil {
		rec.fail(ctx, "list open items", err)
		return
	}
	// The store answered, so a failure reported earlier is over. Cleared here rather
	// than only after a successful record, or the status would keep showing an
	// error the grant had already fixed.
	rec.clearError()
	current := history.Snapshots(snap.views, tickets)
	events, marks := history.Diff(history.Input{
		Open: open, Current: current, Views: snap.views, OpenTickets: tickets,
		ClosedReasons: closedReasons, LapseAfter: rec.lapseAfter, Now: snap.generatedAt,
	})
	a := history.Summarise(started, snap.generatedAt, snap.views, current, snap.summary)
	id, err := rec.store.Record(ctx, a, events, marks)
	if err != nil {
		rec.fail(ctx, "record assessment", err)
		return
	}
	// Re-read rather than patch the list in memory: opened events have ids only
	// the store knows, and this is what ticket attribution needs.
	open, err = rec.store.Open(ctx)
	if err != nil {
		rec.fail(ctx, "list open items after recording", err)
		return
	}
	counts := map[history.Kind]int{}
	for _, e := range events {
		counts[e.Kind]++
	}
	missing := 0
	for _, m := range marks {
		if m.Missing > 0 {
			missing++
		}
	}
	slog.InfoContext(ctx, "history: recorded assessment",
		"assessment_id", id, "items", len(current), "missing", missing,
		"opened", counts[history.KindOpened], "resolved", counts[history.KindResolved],
		"lapsed", counts[history.KindLapsed], "changed", counts[history.KindChanged],
		"reassigned", counts[history.KindReassigned], "tickets_closed", counts[history.KindTicketClosed])

	pruned, perr := rec.store.Prune(ctx, snap.generatedAt.Add(-rec.retention))
	if perr != nil {
		slog.WarnContext(ctx, "history: retention pass failed", "error", perr)
	} else if pruned.Events+pruned.Items+pruned.Assessments > 0 {
		slog.InfoContext(ctx, "history: retention applied",
			"events", pruned.Events, "items", pruned.Items, "assessments", pruned.Assessments,
			"before", snap.generatedAt.Add(-rec.retention).Format(time.RFC3339))
	}

	rec.mu.Lock()
	rec.assessmentID, rec.open, rec.lastErr, rec.lastRecorded, rec.lastPruned = id, open, "", snap.generatedAt, pruned
	rec.mu.Unlock()
}

// recordTicketWrites attributes successful creates and extends to the open items
// whose images they cover.
func (s *Server) recordTicketWrites(ctx context.Context, results []ticket.Result) {
	rec := s.history
	if rec == nil || len(results) == 0 {
		return
	}
	var writes []history.TicketWrite
	closed := map[string]string{}
	for _, r := range results {
		if r.Err != nil || r.Key == "" {
			continue
		}
		switch r.Action.Kind {
		case ticket.ActionCreate:
			writes = append(writes, history.TicketWrite{Key: r.Key, Action: string(r.Action.Kind), Images: r.Action.Draft.Images, DueDate: r.DueDate})
		case ticket.ActionExtend:
			writes = append(writes, history.TicketWrite{Key: r.Key, Action: string(r.Action.Kind), Images: r.Action.Images})
		case ticket.ActionClose:
			closed[r.Key] = r.Action.Reason
		}
	}
	if len(closed) > 0 {
		rec.mu.Lock()
		rec.closedReasons = closed
		rec.mu.Unlock()
	}
	if len(writes) == 0 {
		return
	}
	rec.mu.Lock()
	id, open := rec.assessmentID, rec.open
	rec.mu.Unlock()
	if id == 0 {
		return
	}
	events := history.TicketEvents(open, writes, time.Now())
	if err := rec.store.Append(ctx, id, events); err != nil {
		rec.fail(ctx, "record ticket events", err)
		return
	}
	slog.InfoContext(ctx, "history: recorded ticket events", "events", len(events))
}

func (r *historyRecorder) clearError() {
	r.mu.Lock()
	r.lastErr = ""
	r.mu.Unlock()
}

func (r *historyRecorder) fail(ctx context.Context, what string, err error) {
	slog.WarnContext(ctx, "history: "+what+" failed; the assessment is unaffected", "error", err)
	r.mu.Lock()
	r.lastErr = err.Error()
	r.mu.Unlock()
}

// openTicketKeys flattens the snapshot's ticket index to repository -> keys.
func openTicketKeys(tickets map[string][]ticketRef) map[string][]string {
	if len(tickets) == 0 {
		return nil
	}
	out := make(map[string][]string, len(tickets))
	for repo, refs := range tickets {
		for _, r := range refs {
			out[repo] = append(out[repo], r.Key)
		}
	}
	return out
}

// historyStatus is what the API says about the record itself.
type historyStatus struct {
	Enabled       bool       `json:"enabled"`
	LastRecorded  *time.Time `json:"last_recorded,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	RetentionDays int        `json:"retention_days,omitempty"`
}

func (s *Server) historyStatus() historyStatus {
	if s.history == nil {
		return historyStatus{}
	}
	s.history.mu.Lock()
	defer s.history.mu.Unlock()
	st := historyStatus{Enabled: true, LastError: s.history.lastErr, RetentionDays: int(s.history.retention.Hours() / 24)}
	if !s.history.lastRecorded.IsZero() {
		t := s.history.lastRecorded
		st.LastRecorded = &t
	}
	return st
}

// handleHistory serves GET /api/v1/history: movement and risk by period.
//
//	since   RFC3339 timestamp, or a number of days back ("90d"). Default 90d.
//	until   RFC3339 timestamp. Default now.
//	bucket  month (default) or week.
//
// With no store configured it answers 200 with enabled=false rather than 404: the
// route exists, the feature is off, and a consumer should be told which.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	rng, err := parseHistoryRange(r, now)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	type response struct {
		Assessment assessmentMeta `json:"assessment"`
		Status     historyStatus  `json:"status"`
		History    history.Report `json:"history"`
	}
	if s.history == nil {
		writeJSON(w, http.StatusOK, response{s.meta(), s.historyStatus(), history.Report{
			SchemaVersion: history.SchemaVersion, Since: rng.Since, Until: rng.Until, Bucket: rng.Bucket,
			Risk: []history.RiskPoint{}, Movement: []history.Movement{},
			Caveats: []string{"history is not enabled: no store is configured, so nothing here is recorded"},
		}})
		return
	}
	rep, err := s.historyReport(r.Context(), rng, now)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "history store: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, response{s.meta(), s.historyStatus(), rep})
}

// historyReport builds the report the API, the page and the MCP tool all read, so
// none of them can disagree about a period.
func (s *Server) historyReport(ctx context.Context, rng history.Range, now time.Time) (history.Report, error) {
	store := s.history.store
	assessments, err := store.Assessments(ctx, rng.Since, rng.Until)
	if err != nil {
		return history.Report{}, err
	}
	events, err := store.Events(ctx, rng.Since, rng.Until)
	if err != nil {
		return history.Report{}, err
	}
	open, err := store.Open(ctx)
	if err != nil {
		return history.Report{}, err
	}
	first, ok, ferr := store.First(ctx)
	if ferr != nil {
		return history.Report{}, ferr
	}
	if !ok {
		first = time.Time{}
	}
	rep := history.Aggregate(rng, assessments, events, open, first, now)
	rep.RetentionDays = int(s.history.retention.Hours() / 24)
	switch {
	case !ok:
		rep.Caveats = append(rep.Caveats, "the record is empty: no assessment has been recorded yet")
	case first.After(rng.Since):
		rep.Caveats = append(rep.Caveats, fmt.Sprintf(
			"the record begins %s; periods before it are empty because nothing was watching, not because nothing happened",
			first.Format("2006-01-02")))
	}
	if rep.Baseline > 0 {
		rep.Caveats = append(rep.Caveats, fmt.Sprintf(
			"%d work items were already open when the record began and are counted as the baseline, not as opened", rep.Baseline))
	}
	rep.Caveats = append(rep.Caveats,
		"counts are work items, classified by how each looked when the record first saw it",
		"resolved requires evidence the work is done; lapsed is everything else, and is never remediation")
	return rep, nil
}

// historySource hands the MCP tools the same report builder, or nil when history
// is off.
func (s *Server) historySource() mcp.HistorySource {
	if s.history == nil {
		return nil
	}
	return func(ctx context.Context, since, until time.Time, bucket history.Bucket) (history.Report, error) {
		return s.historyReport(ctx, history.Range{Since: since, Until: until, Bucket: bucket}, time.Now().UTC())
	}
}

// handleHistoryItem serves GET /api/v1/history/item?key=: one work item's record.
func (s *Server) handleHistoryItem(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if key == "" {
		writeError(w, http.StatusBadRequest, "key is required: the work item key from /api/v1/history or the queue")
		return
	}
	if s.history == nil {
		writeError(w, http.StatusNotFound, "history is not enabled")
		return
	}
	item, err := s.history.store.Item(r.Context(), key)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "history store: "+err.Error())
		return
	}
	if item == nil {
		writeError(w, http.StatusNotFound, "no history for "+key)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta       `json:"assessment"`
		Item       *history.ItemHistory `json:"item"`
	}{s.meta(), item})
}

func parseHistoryRange(r *http.Request, now time.Time) (history.Range, error) {
	q := r.URL.Query()
	bucket, err := history.ParseBucket(q.Get("bucket"))
	if err != nil {
		return history.Range{}, err
	}
	until := now
	if raw := q.Get("until"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return history.Range{}, fmt.Errorf("until must be RFC3339: %v", err)
		}
		until = t.UTC()
	}
	since := until.Add(-defaultHistorySince)
	if raw := q.Get("since"); raw != "" {
		switch {
		case strings.HasSuffix(raw, "d"):
			n, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
			if err != nil || n <= 0 {
				return history.Range{}, fmt.Errorf("since must be a number of days like 90d, or RFC3339")
			}
			since = until.Add(-time.Duration(n) * 24 * time.Hour)
		default:
			t, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return history.Range{}, fmt.Errorf("since must be a number of days like 90d, or RFC3339: %v", err)
			}
			since = t.UTC()
		}
	}
	if !since.Before(until) {
		return history.Range{}, fmt.Errorf("since must be before until")
	}
	return history.Range{Since: since, Until: until, Bucket: bucket}, nil
}
