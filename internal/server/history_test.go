package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	err                      error
}

func newMemStore() *memStore {
	return &memStore{items: map[int64]*history.State{}, closed: map[int64]history.Kind{}}
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

func (m *memStore) Prune(context.Context, time.Time) (history.Pruned, error) {
	return history.Pruned{}, nil
}
func (m *memStore) Close() {}

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
