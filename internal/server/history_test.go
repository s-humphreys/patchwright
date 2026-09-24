package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

// memStore is a history.Store in memory, enough to drive the server paths: it
// applies events to an items map the way the real store does, so a second refresh
// sees what the first recorded.
type memStore struct {
	nextItem, nextAssessment int64
	items                    map[int64]*history.State
	closed                   map[int64]history.Kind
	events                   []history.Event
	assessments              []history.Assessment
	tickets                  map[string]history.TrackerTicket
	err                      error
}

func newMemStore() *memStore {
	return &memStore{items: map[int64]*history.State{}, closed: map[int64]history.Kind{}, tickets: map[string]history.TrackerTicket{}}
}

func (m *memStore) Open(context.Context) ([]history.State, error) {
	if m.err != nil {
		return nil, m.err
	}
	var out []history.State
	for id, st := range m.items {
		if _, closed := m.closed[id]; !closed {
			out = append(out, *st)
		}
	}
	return out, nil
}

func (m *memStore) Record(_ context.Context, a history.Assessment, events []history.Event, marks []history.Mark) (int64, error) {
	if m.err != nil {
		return 0, m.err
	}
	m.nextAssessment++
	a.ID = m.nextAssessment
	m.assessments = append(m.assessments, a)
	for _, mk := range marks {
		if st := m.items[mk.ItemID]; st != nil {
			st.Missing, st.MissingSince = mk.Missing, mk.MissingSince
		}
	}
	return a.ID, m.apply(events)
}

func (m *memStore) Append(_ context.Context, _ int64, events []history.Event) error {
	if m.err != nil {
		return m.err
	}
	return m.apply(events)
}

func (m *memStore) apply(events []history.Event) error {
	for _, e := range events {
		switch e.Kind {
		case history.KindOpened:
			m.nextItem++
			e.ItemID = m.nextItem
			m.items[e.ItemID] = &history.State{ID: e.ItemID, OpenedAt: e.At, Opened: *e.Payload.Snapshot, Current: *e.Payload.Snapshot}
		case history.KindResolved, history.KindLapsed:
			m.closed[e.ItemID] = e.Kind
		case history.KindChanged, history.KindReassigned:
			m.items[e.ItemID].Current = *e.Payload.Snapshot
		case history.KindTicketRaised:
			if st := m.items[e.ItemID]; st != nil && e.Payload.DueDate != nil {
				if _, ok := st.TicketDue[e.Payload.Ticket]; !ok {
					if st.TicketDue == nil {
						st.TicketDue = map[string]time.Time{}
					}
					st.TicketDue[e.Payload.Ticket] = *e.Payload.DueDate
				}
			}
		}
		if e.ItemID == 0 {
			return errors.New("event without item")
		}
		m.events = append(m.events, e)
	}
	return nil
}

func (m *memStore) Events(_ context.Context, since, until time.Time) ([]history.Event, error) {
	if m.err != nil {
		return nil, m.err
	}
	var out []history.Event
	for _, e := range m.events {
		if !e.At.Before(since) && e.At.Before(until) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memStore) Assessments(_ context.Context, since, until time.Time) ([]history.Assessment, error) {
	if m.err != nil {
		return nil, m.err
	}
	var out []history.Assessment
	for _, a := range m.assessments {
		if !a.FinishedAt.Before(since) && a.FinishedAt.Before(until) {
			// Like the real store: the item list is read one run at a time.
			a.Items = nil
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *memStore) AssessmentItems(_ context.Context, id int64) ([]history.Snapshot, error) {
	for _, a := range m.assessments {
		if a.ID == id {
			return a.Items, nil
		}
	}
	return nil, nil
}

func (m *memStore) Item(_ context.Context, key string) (*history.ItemHistory, error) {
	out := &history.ItemHistory{Key: key}
	for _, st := range m.items {
		if st.Current.Key == key {
			out.Items = append(out.Items, history.ItemRow{ID: st.ID, Key: key, OpenedAt: st.OpenedAt, Opened: st.Opened, Current: st.Current})
		}
	}
	if len(out.Items) == 0 {
		return nil, nil
	}
	for _, e := range m.events {
		if e.Key == key {
			out.Events = append(out.Events, e)
		}
	}
	return out, nil
}

func (m *memStore) First(context.Context) (time.Time, bool, error) {
	if len(m.assessments) == 0 {
		return time.Time{}, false, nil
	}
	return m.assessments[0].FinishedAt, true, nil
}

// Prune only mirrors the tickets part of the postgres store: nothing here reads
// pruned events or items back.
func (m *memStore) Prune(_ context.Context, before time.Time) (history.Pruned, error) {
	var p history.Pruned
	for k, t := range m.tickets {
		if t.ResolvedAt != nil && t.ResolvedAt.Before(before) {
			delete(m.tickets, k)
			p.Tickets++
		}
	}
	return p, nil
}
func (m *memStore) Close() {}

func (m *memStore) UpsertTickets(_ context.Context, tickets []history.TrackerTicket) error {
	if m.err != nil {
		return m.err
	}
	// The same merge as the postgres upsert: a match is held once made, a changelog
	// start survives a weaker or missing one, and a missing title keeps the old one.
	for _, t := range tickets {
		if prev, ok := m.tickets[t.Key]; ok {
			if prev.ItemKey != "" {
				t.ItemKey, t.ItemOpenedAt = prev.ItemKey, prev.ItemOpenedAt
			}
			if t.Summary == "" {
				t.Summary = prev.Summary
			}
			keepStart := (prev.StartedFrom == history.StartedFromChangelog && t.StartedFrom != history.StartedFromChangelog) ||
				t.StartedAt == nil
			if keepStart {
				t.StartedAt, t.StartedFrom = prev.StartedAt, prev.StartedFrom
			}
		}
		m.tickets[t.Key] = t
	}
	return nil
}

func (m *memStore) Tickets(_ context.Context, since, until time.Time) ([]history.TrackerTicket, error) {
	if m.err != nil {
		return nil, m.err
	}
	in := func(t time.Time) bool { return !t.Before(since) && t.Before(until) }
	var out []history.TrackerTicket
	for _, t := range m.tickets {
		if in(t.CreatedAt) || (t.ResolvedAt != nil && (in(*t.ResolvedAt) || t.ItemKey != "")) {
			out = append(out, t)
		}
	}
	return out, nil
}

func (m *memStore) TicketsIndexed(context.Context) (history.TicketIndexState, error) {
	if m.err != nil {
		return history.TicketIndexState{}, m.err
	}
	st := history.TicketIndexState{Tickets: len(m.tickets)}
	for _, t := range m.tickets {
		if st.FirstCreated.IsZero() || t.CreatedAt.Before(st.FirstCreated) {
			st.FirstCreated = t.CreatedAt
		}
		if t.LastSeenAt.After(st.LastSynced) {
			st.LastSynced = t.LastSeenAt
		}
	}
	return st, nil
}

func (m *memStore) kinds() map[history.Kind]int {
	out := map[history.Kind]int{}
	for _, e := range m.events {
		out[e.Kind]++
	}
	return out
}

// upgradable is a finding whose work is not done: an upgrade is available.
func upgradable(image, team string) model.Finding {
	f := finding(image, "engineering", team, true, false)
	f.Priority = "high"
	f.Rule = "any-critical"
	f.Counts = model.Counts{"critical": 1}
	f.RemediationChecked = true
	f.Upgrade = &model.Upgrade{Kind: "helm", Name: "svc", Current: "1.0", Latest: "1.1", Available: true, Resolved: true}
	f.Reconciled, f.Live = true, true
	return f
}

// upgraded is the same service after the upgrade landed: nothing actionable, and
// every piece of evidence auto-close would demand.
func upgraded(image, team string) model.Finding {
	f := upgradable(image, team)
	f.Actionable = false
	f.Priority = ""
	f.Counts = model.Counts{}
	f.Upgrade = &model.Upgrade{Kind: "helm", Name: "svc", Current: "1.1", Latest: "1.1", Available: false, Resolved: true}
	return f
}

func TestHistoryDisabledIsExplicit(t *testing.T) {
	h := newTestServer(t)
	var resp struct {
		Status  historyStatus  `json:"status"`
		History history.Report `json:"history"`
	}
	if code := getJSON(t, h, "/api/v1/history", &resp); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if resp.Status.Enabled || resp.History.Enabled || len(resp.History.Caveats) == 0 {
		t.Errorf("disabled history must say so: %+v", resp)
	}
	if resp.History.Movement == nil || resp.History.Risk == nil {
		t.Errorf("arrays should be empty, not null, so a page can iterate them")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/history/item?key=x", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("item lookup with history off: %d", rec.Code)
	}
}

func TestHistoryRecordsAcrossRefreshes(t *testing.T) {
	store := newMemStore()
	a := &stubAssessor{findings: []model.Finding{upgradable("acr.io/app:1", "orders"), upgradable("acr.io/lib:1", "billing")}}
	s := New(a).WithHistory(store, 30*24*time.Hour).WithLapseAfter(1)
	s.Refresh(context.Background())

	if k := store.kinds(); k[history.KindOpened] != 2 || len(store.assessments) != 1 {
		t.Fatalf("first refresh should open two items and record one assessment: %v", k)
	}
	if a := store.assessments[0]; a.ItemCount != 2 || a.Risk.Items != 2 || len(a.Items) != 2 || a.Counts["critical"] != 2 || a.Summary == nil {
		t.Errorf("assessment row = %+v", a)
	}
	openBySignal := func() map[string]int {
		t.Helper()
		var resp struct {
			History history.Report `json:"history"`
		}
		if code := getJSON(t, s.Handler(), "/api/v1/history?since=30d", &resp); code != http.StatusOK || len(resp.History.Risk) != 1 {
			t.Fatalf("status %d, risk %+v", code, resp.History.Risk)
		}
		return resp.History.Risk[0].OpenBySignal
	}
	// Read from the stored item list, which Assessments does not return.
	if got := openBySignal(); len(got) != len(history.OpenSignals) {
		t.Errorf("open by signal after the first run = %v, want every signal counted", got)
	}

	// The orders upgrade lands; billing disappears from the scan entirely.
	a.findings = []model.Finding{upgraded("acr.io/app:1", "orders")}
	s.Refresh(context.Background())
	k := store.kinds()
	if k[history.KindResolved] != 1 || k[history.KindLapsed] != 1 {
		t.Fatalf("want one resolved and one lapsed, got %v", k)
	}
	for _, e := range store.events {
		switch e.Kind {
		case history.KindResolved:
			if !strings.Contains(e.Payload.Evidence, "app is on 1.1") || e.Payload.Opened == nil {
				t.Errorf("resolved payload = %+v", e.Payload)
			}
		case history.KindLapsed:
			if !strings.Contains(e.Payload.Reason, "no longer reported") {
				t.Errorf("lapsed reason = %q", e.Payload.Reason)
			}
		}
	}

	var resp struct {
		Status  historyStatus  `json:"status"`
		History history.Report `json:"history"`
	}
	if code := getJSON(t, s.Handler(), "/api/v1/history?since=30d", &resp); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if !resp.Status.Enabled || resp.Status.RetentionDays != 30 || resp.Status.LastRecorded == nil {
		t.Errorf("status = %+v", resp.Status)
	}
	var baseline, opened, resolved, lapsed int
	for _, m := range resp.History.Movement {
		baseline, opened, resolved, lapsed = baseline+m.Baseline, opened+m.Opened, resolved+m.Resolved, lapsed+m.Lapsed
	}
	// The first run's items are the baseline: they were already open when the
	// record began, and nothing "opened" that hour except the watching.
	if baseline != 2 || opened != 0 || resolved != 1 || lapsed != 1 {
		t.Errorf("movement totals = baseline %d opened %d resolved %d lapsed %d", baseline, opened, resolved, lapsed)
	}
	if resp.History.Assessments != 2 || len(resp.History.Risk) == 0 || resp.History.FirstRecorded == nil {
		t.Errorf("report header = %+v", resp.History)
	}
	// The queue is empty now: zeros, not an absence that reads as "not counted".
	if got := openBySignal(); !reflect.DeepEqual(got, map[string]int{"kev": 0, "epss-high": 0, "fixable-critical": 0, "end-of-life": 0}) {
		t.Errorf("open by signal with an empty queue = %v", got)
	}

	var item struct {
		Item history.ItemHistory `json:"item"`
	}
	key := history.Key("engineering", "orders", "app", "svc")
	if code := getJSON(t, s.Handler(), "/api/v1/history/item?key="+key, &item); code != http.StatusOK {
		t.Fatalf("item status %d", code)
	}
	if len(item.Item.Events) != 2 || item.Item.Events[1].Kind != history.KindResolved {
		t.Errorf("item events = %+v", item.Item.Events)
	}
}

func TestHistoryAttributesTicketWrites(t *testing.T) {
	store := newMemStore()
	s := New(&stubAssessor{findings: []model.Finding{upgradable("acr.io/app:1", "orders")}}).WithHistory(store, 24*time.Hour)
	s.Refresh(context.Background())

	s.recordTicketWrites(context.Background(), []ticket.Result{
		{Action: ticket.Action{Kind: ticket.ActionCreate, Draft: ticket.Draft{Images: []string{"acr.io/app:1"}}}, Key: "DVOP-1"},
		{Action: ticket.Action{Kind: ticket.ActionCreate, Draft: ticket.Draft{Images: []string{"acr.io/other:1"}}}, Key: "DVOP-2"},
		{Action: ticket.Action{Kind: ticket.ActionCreate, Draft: ticket.Draft{Images: []string{"acr.io/app:1"}}}, Err: errors.New("boom")},
		{Action: ticket.Action{Kind: ticket.ActionSkip}, Key: "DVOP-3"},
	})
	var raised []history.Event
	for _, e := range store.events {
		if e.Kind == history.KindTicketRaised {
			raised = append(raised, e)
		}
	}
	if len(raised) != 1 || raised[0].Payload.Ticket != "DVOP-1" || raised[0].Payload.Action != "create" {
		t.Errorf("want one ticket_raised for DVOP-1, got %+v", raised)
	}
}

// The due date a create set has to reach the record, and the item, so the close
// can be measured against it later. An extend carries none.
func TestHistoryRecordsTheDueDateOfACreate(t *testing.T) {
	store := newMemStore()
	s := New(&stubAssessor{findings: []model.Finding{upgradable("acr.io/app:1", "orders")}}).WithHistory(store, 24*time.Hour)
	s.Refresh(context.Background())

	due := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	s.recordTicketWrites(context.Background(), []ticket.Result{
		{Action: ticket.Action{Kind: ticket.ActionCreate, Draft: ticket.Draft{Images: []string{"acr.io/app:1"}}}, Key: "DVOP-1", DueDate: &due},
		{Action: ticket.Action{Kind: ticket.ActionExtend, Images: []string{"acr.io/app:1"}}, Key: "DVOP-2"},
	})
	for _, e := range store.events {
		if e.Kind != history.KindTicketRaised {
			continue
		}
		switch e.Payload.Ticket {
		case "DVOP-1":
			if e.Payload.DueDate == nil || !e.Payload.DueDate.Equal(due) {
				t.Errorf("create due_date = %v, want %v", e.Payload.DueDate, due)
			}
		case "DVOP-2":
			if e.Payload.DueDate != nil {
				t.Errorf("extend due_date = %v, want absent", e.Payload.DueDate)
			}
		}
	}
	open, _ := store.Open(context.Background())
	if len(open) != 1 || !open[0].TicketDue["DVOP-1"].Equal(due) || len(open[0].TicketDue) != 1 {
		t.Errorf("item should hold DVOP-1's due date only: %+v", open)
	}
}

func TestHistoryStoreFailureDoesNotCostTheAssessment(t *testing.T) {
	store := newMemStore()
	store.err = errors.New("connection refused")
	s := New(&stubAssessor{findings: []model.Finding{upgradable("acr.io/app:1", "orders")}}).WithHistory(store, 24*time.Hour)
	s.Refresh(context.Background())

	var findings struct {
		Count int `json:"count"`
	}
	if code := getJSON(t, s.Handler(), "/api/v1/findings", &findings); code != http.StatusOK || findings.Count != 1 {
		t.Fatalf("the queue must still serve: %d %+v", code, findings)
	}
	var resp struct {
		Status historyStatus `json:"status"`
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/history", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("history with a broken store should be 503, got %d", rec.Code)
	}
	_ = resp
	if st := s.historyStatus(); !st.Enabled || !strings.Contains(st.LastError, "connection refused") {
		t.Errorf("status should carry the error: %+v", st)
	}
}

func TestParseHistoryRange(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	req := func(q string) *http.Request { return httptest.NewRequest(http.MethodGet, "/api/v1/history?"+q, nil) }

	r, err := parseHistoryRange(req(""), now)
	if err != nil || r.Bucket != history.BucketMonth || !r.Since.Equal(now.Add(-90*24*time.Hour)) {
		t.Errorf("default range = %+v (%v)", r, err)
	}
	r, err = parseHistoryRange(req("since=7d&bucket=week"), now)
	if err != nil || r.Bucket != history.BucketWeek || !r.Since.Equal(now.AddDate(0, 0, -7)) {
		t.Errorf("7d/week = %+v (%v)", r, err)
	}
	r, err = parseHistoryRange(req("since=2026-06-01T00:00:00Z&until=2026-07-01T00:00:00Z"), now)
	if err != nil || r.Since.Month() != time.June || r.Until.Month() != time.July {
		t.Errorf("explicit = %+v (%v)", r, err)
	}
	for _, bad := range []string{"since=yesterday", "since=0d", "bucket=day", "until=notatime", "since=2026-08-01T00:00:00Z&until=2026-07-01T00:00:00Z"} {
		if _, err := parseHistoryRange(req(bad), now); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// A repository missing from one assessment is neither lapsed nor told its coverage
// is gone until the grace period is spent; the ticket for it is held meanwhile.
func TestHistoryGraceHoldsTicketsAndDelaysLapse(t *testing.T) {
	store := newMemStore()
	a := &stubAssessor{findings: []model.Finding{upgradable("acr.io/app:1", "orders")}}
	s := New(a).WithHistory(store, 30*24*time.Hour).WithLapseAfter(3)
	s.Refresh(context.Background())

	// The provider drops the image for one run.
	a.findings = nil
	s.Refresh(context.Background())
	if k := store.kinds(); k[history.KindLapsed] != 0 {
		t.Fatalf("one absent run must not lapse: %v", k)
	}
	recent := s.recentlyMissing()
	if !recent["app"] {
		t.Fatalf("the missing repository should be reported as recently seen: %v", recent)
	}
	actions := ticket.Reconcile(ticket.ReconcileInput{
		OpenByImage:      map[string][]ticket.Existing{"app": {{Key: "PROJ-1", Category: "new"}}},
		RecentlyReported: recent,
	})
	if len(actions) != 1 || actions[0].Kind != ticket.ActionHold || !strings.Contains(actions[0].Why, "within the last few assessments") {
		t.Fatalf("a ticket for a recently seen image is held, not told coverage is gone: %+v", actions)
	}

	// Two more absent runs and the grace period is spent.
	s.Refresh(context.Background())
	s.Refresh(context.Background())
	k := store.kinds()
	if k[history.KindLapsed] != 1 || k[history.KindOpened] != 1 {
		t.Fatalf("after the grace period the item lapses once: %v", k)
	}
	if s.recentlyMissing()["app"] {
		t.Errorf("a lapsed item is no longer recently seen")
	}
}

// trackerIndex is an open-ticket index that can also date the tracker's tickets,
// as *ticket.Jira does.
type trackerIndex struct {
	stubTickets
	dated   []ticket.Dated
	err     error
	windows []time.Duration
}

func (t *trackerIndex) DatedTickets(_ context.Context, within time.Duration) ([]ticket.Dated, error) {
	t.windows = append(t.windows, within)
	return t.dated, t.err
}

// After each run the tracker is read into the record: everything the first time,
// incrementally after, and the report carries the tracker's figures marked as such.
func TestHistorySyncsTheTrackerAfterEachRun(t *testing.T) {
	store := newMemStore()
	now := time.Now().UTC()
	created, started := now.Add(-72*time.Hour), now.Add(-48*time.Hour)
	idx := &trackerIndex{dated: []ticket.Dated{
		{Key: "DVOP-1", Project: "DVOP", Images: []string{"app"}, Status: "In Progress", Category: "indeterminate",
			Created: created, Started: &started, StartedFrom: ticket.StartedFromChangelog},
		{Key: "DVOP-9", Project: "DVOP", Images: []string{"elsewhere"}, Status: "To Do", Category: "new", Created: created},
	}}
	s := New(&stubAssessor{findings: []model.Finding{upgradable("acr.io/app:1", "orders")}}).
		WithHistory(store, 400*24*time.Hour).WithTickets(idx, "")
	s.Refresh(context.Background())

	// Somebody closes DVOP-1 while the image still runs.
	resolved := time.Now().UTC()
	idx.dated[0].Status, idx.dated[0].Category, idx.dated[0].Resolved = "Done", "done", &resolved
	s.Refresh(context.Background())

	if len(idx.windows) != 2 || idx.windows[0] != 0 || idx.windows[1] != 48*time.Hour {
		t.Fatalf("windows = %v, want a backfill then two days", idx.windows)
	}
	got := store.tickets["DVOP-1"]
	if got.ItemKey != history.Key("engineering", "orders", "app", "svc") || got.ItemOpenedAt == nil || got.StartedAt == nil || got.ResolvedAt == nil {
		t.Errorf("DVOP-1 stored as %+v, want matched to the app item", got)
	}
	if store.tickets["DVOP-9"].ItemKey != "" {
		t.Errorf("DVOP-9 covers nothing open and must stay unmatched")
	}

	var resp struct {
		History history.Report `json:"history"`
	}
	if code := getJSON(t, s.Handler(), "/api/v1/history?since=30d", &resp); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	rep := resp.History
	if rep.Tracker == nil || rep.Tracker.Source != "tracker" || rep.Tracker.Tickets != 2 {
		t.Fatalf("tracker summary = %+v", rep.Tracker)
	}
	var raised, closed, worked int
	for _, m := range rep.Movement {
		if m.TrackerTicketsRaised != nil {
			raised += *m.TrackerTicketsRaised
		}
		if m.TrackerTicketsClosed != nil {
			closed += *m.TrackerTicketsClosed
		}
		worked += m.MedianDaysWorkedN
	}
	if raised != 2 || closed != 1 || worked != 1 {
		t.Errorf("tracker raised/closed/worked n = %d/%d/%d, want 2/1/1", raised, closed, worked)
	}
	// DVOP-1 closed while the app item is still open and no ticket covers it now.
	if rep.Open.ClosedTicketFindingOpen == nil || *rep.Open.ClosedTicketFindingOpen != 1 {
		t.Errorf("closed ticket, finding open = %v, want 1", rep.Open.ClosedTicketFindingOpen)
	} else if rep.Open.ClosedTicketAgeDays["0-7"] != 1 {
		t.Errorf("closed ticket ages = %v, want one closed today", rep.Open.ClosedTicketAgeDays)
	}
	found := false
	for _, c := range rep.Caveats {
		if strings.Contains(c, "tickets, not resolutions") {
			found = true
		}
	}
	if !found {
		t.Errorf("caveats must say tracker counts are tickets, not resolutions: %v", rep.Caveats)
	}
}

func TestHistoryTrackerFailureDoesNotCostTheAssessment(t *testing.T) {
	store := newMemStore()
	idx := &trackerIndex{err: errors.New("jira: 401")}
	s := New(&stubAssessor{findings: []model.Finding{upgradable("acr.io/app:1", "orders")}}).
		WithHistory(store, 24*time.Hour).WithTickets(idx, "")
	s.Refresh(context.Background())

	if k := store.kinds(); k[history.KindOpened] != 1 {
		t.Fatalf("the assessment must still be recorded: %v", k)
	}
	if st := s.historyStatus(); !strings.Contains(st.LastError, "401") {
		t.Errorf("status should carry the tracker error: %+v", st)
	}
	var resp struct {
		History history.Report `json:"history"`
	}
	if code := getJSON(t, s.Handler(), "/api/v1/history", &resp); code != http.StatusOK || resp.History.Tracker != nil {
		t.Errorf("never read, so no tracker block: %d %+v", code, resp.History.Tracker)
	}
}

type ticketsPerDayResponse struct {
	Status  historyStatus `json:"status"`
	Tickets ticketsPerDay `json:"tickets"`
}

func TestHistoryTicketsDisabledIsExplicit(t *testing.T) {
	var resp ticketsPerDayResponse
	if code := getJSON(t, newTestServer(t), "/api/v1/history/tickets?since=30d", &resp); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if resp.Status.Enabled || resp.Tickets.Days == nil || len(resp.Tickets.Days) != 0 || resp.Tickets.Total != 0 {
		t.Errorf("disabled history must say so with an empty, non-null list: %+v", resp)
	}
	if len(resp.Tickets.Caveats) == 0 || !strings.Contains(resp.Tickets.Caveats[0], "not enabled") {
		t.Errorf("caveats = %v", resp.Tickets.Caveats)
	}
}

// Every UTC day of the range is present, the first one whole; only creations count,
// in created order; and each ticket links to the tracker when its base URL is known.
func TestHistoryTicketsPerDay(t *testing.T) {
	store := newMemStore()
	sep := func(d, h, m int) time.Time { return time.Date(2026, 9, d, h, m, 0, 0, time.UTC) }
	resolved := sep(2, 12, 0)
	opened := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	for _, tk := range []history.TrackerTicket{
		{Key: "DVOP-1", Project: "DVOP", Summary: "Upgrade app", CreatedAt: sep(1, 3, 0), Status: "To Do", StatusCategory: "new"},
		{Key: "DVOP-2", Project: "DVOP", Summary: "Upgrade lib", CreatedAt: sep(3, 10, 0), Status: "In Progress",
			StatusCategory: "indeterminate", ItemKey: "engineering|orders|lib|svc", ItemOpenedAt: &opened},
		// Created in a different zone: the day is the UTC one.
		{Key: "SEC-3", Project: "SEC", CreatedAt: time.Date(2026, 9, 3, 10, 0, 0, 0, time.FixedZone("BST", 3600))},
		{Key: "DVOP-4", Project: "DVOP", CreatedAt: sep(1, 0, 0).Add(-time.Minute)},
		{Key: "DVOP-5", Project: "DVOP", CreatedAt: sep(5, 7, 0)},
		// Resolved in the range and matched: the store returns it, but it was not
		// created in the range.
		{Key: "DVOP-6", Project: "DVOP", CreatedAt: time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC), ResolvedAt: &resolved,
			ItemKey: "engineering|orders|app|svc", ItemOpenedAt: &opened, LastSeenAt: sep(4, 0, 0)},
	} {
		store.tickets[tk.Key] = tk
	}
	s := New(&stubAssessor{}).WithHistory(store, 400*24*time.Hour).WithTickets(stubTickets{}, "https://jira.example.com/")

	var resp ticketsPerDayResponse
	path := "/api/v1/history/tickets?since=2026-09-01T12:00:00Z&until=2026-09-05T06:00:00Z"
	if code := getJSON(t, s.Handler(), path, &resp); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	got := resp.Tickets
	if !got.Since.Equal(sep(1, 0, 0)) || !got.Until.Equal(sep(5, 6, 0)) {
		t.Errorf("range = %v to %v, want the first day whole", got.Since, got.Until)
	}
	var dates []string
	var counts []int
	for _, d := range got.Days {
		dates = append(dates, d.Date)
		counts = append(counts, d.Created)
		if d.Tickets == nil || len(d.Tickets) != d.Created {
			t.Errorf("%s: %d created but %d listed", d.Date, d.Created, len(d.Tickets))
		}
	}
	if joined := strings.Join(dates, ","); joined != "2026-09-01,2026-09-02,2026-09-03,2026-09-04,2026-09-05" {
		t.Errorf("days = %s, want every day of the range", joined)
	}
	if want := []int{1, 0, 2, 0, 0}; !equalInts(counts, want) {
		t.Errorf("created per day = %v, want %v", counts, want)
	}
	if got.Total != 3 {
		t.Errorf("total = %d, want 3", got.Total)
	}
	third := got.Days[2].Tickets
	if third[0].Key != "SEC-3" || third[1].Key != "DVOP-2" {
		t.Fatalf("3 September = %+v, want SEC-3 (09:00 UTC) before DVOP-2", third)
	}
	d2 := third[1]
	if d2.URL != "https://jira.example.com/browse/DVOP-2" || d2.Summary != "Upgrade lib" || d2.Status != "In Progress" ||
		d2.StatusCategory != "indeterminate" || d2.Item != "engineering|orders|lib|svc" || d2.Project != "DVOP" {
		t.Errorf("DVOP-2 = %+v", d2)
	}
	if got.FirstCreated == nil || !got.FirstCreated.Equal(time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)) || got.LastSynced == nil {
		t.Errorf("index = %v %v", got.FirstCreated, got.LastSynced)
	}
	if len(got.Caveats) != 0 {
		t.Errorf("tickets predate the range, so no caveat: %v", got.Caveats)
	}

	// Without a base URL there is no link rather than a broken one.
	s = New(&stubAssessor{}).WithHistory(store, 400*24*time.Hour)
	var bare ticketsPerDayResponse
	if code := getJSON(t, s.Handler(), path, &bare); code != http.StatusOK || bare.Tickets.Days[0].Tickets[0].URL != "" {
		t.Errorf("url without a base = %q (%d)", bare.Tickets.Days[0].Tickets[0].URL, code)
	}
}

func TestHistoryTicketsRange(t *testing.T) {
	store := newMemStore()
	s := New(&stubAssessor{}).WithHistory(store, 400*24*time.Hour)
	h := s.Handler()

	var resp ticketsPerDayResponse
	before := time.Now().UTC()
	if code := getJSON(t, h, "/api/v1/history/tickets?since=7d", &resp); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	// Seven days back from now, from the start of that day: eight days, today partial.
	if n := len(resp.Tickets.Days); n != 8 {
		t.Errorf("7d = %d days, want 8", n)
	}
	if want := before.Add(-7 * 24 * time.Hour).Truncate(24 * time.Hour).Format(time.DateOnly); resp.Tickets.Days[0].Date != want {
		t.Errorf("first day = %s, want %s", resp.Tickets.Days[0].Date, want)
	}
	if len(resp.Tickets.Caveats) != 1 || !strings.Contains(resp.Tickets.Caveats[0], "not been read") {
		t.Errorf("an unread tracker must say so: %v", resp.Tickets.Caveats)
	}
	if resp.Tickets.FirstCreated != nil || resp.Tickets.LastSynced != nil {
		t.Errorf("nothing indexed, so no index dates: %+v", resp.Tickets)
	}

	// A ticketed estate whose tracker starts inside the range says the days before
	// it are before ticketing.
	store.tickets["DVOP-1"] = history.TrackerTicket{Key: "DVOP-1", Project: "DVOP", CreatedAt: before.Add(-24 * time.Hour), LastSeenAt: before}
	resp = ticketsPerDayResponse{}
	if code := getJSON(t, h, "/api/v1/history/tickets?since=7d", &resp); code != http.StatusOK || resp.Tickets.Total != 1 {
		t.Fatalf("status %d, total %d", code, resp.Tickets.Total)
	}
	if len(resp.Tickets.Caveats) != 1 || !strings.Contains(resp.Tickets.Caveats[0], "before ticketing") {
		t.Errorf("caveats = %v", resp.Tickets.Caveats)
	}

	for _, bad := range []string{"since=yesterday", "since=0d", "until=notatime", "since=2026-08-01T00:00:00Z&until=2026-07-01T00:00:00Z"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/history/tickets?"+bad, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q = %d, want 400", bad, rec.Code)
		}
	}

	store.err = errors.New("connection refused")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/history/tickets", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("store failure = %d %s", rec.Code, rec.Body.String())
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
