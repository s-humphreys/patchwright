package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
)

// The store is exercised against a real PostgreSQL named by
// PATCHWRIGHT_TEST_POSTGRES_DSN, and skipped without one. Mocking a driver would
// test the mock; what matters here is that the SQL and the partial unique index do
// what the comments say.
//
//	docker run -d --rm -e POSTGRES_PASSWORD=pw -p 55432:5432 postgres:17-alpine
//	PATCHWRIGHT_TEST_POSTGRES_DSN=postgres://postgres:pw@localhost:55432/postgres go test ./pkg/history/postgres
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("PATCHWRIGHT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PATCHWRIGHT_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	s, err := Open(ctx, Options{DSN: dsn})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.pool.Exec(ctx, `TRUNCATE events, items, assessments, tickets RESTART IDENTITY`)
		s.Close()
	})
	if _, err := s.pool.Exec(ctx, `TRUNCATE events, items, assessments, tickets RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

func snap(key, repo, team string, tickets ...string) history.Snapshot {
	return history.Snapshot{
		Key: key, Repository: repo, Class: "eng", Team: team, Target: "svc", TargetVersion: "1.1",
		Rule: "any-critical", Priority: "high", Signals: []string{"kev"}, Risk: 500,
		Images: []string{repo + ":1"}, Tickets: tickets,
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	s := testStore(t)
	if err := s.migrate(context.Background()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var v int
	if err := s.pool.QueryRow(context.Background(), `SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil || v != 5 {
		t.Errorf("schema version = %d (%v)", v, err)
	}
}

func TestLifecycleRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	a := snap("eng|orders|app|svc", "app", "orders")
	b := snap("eng|billing|lib|svc", "lib", "billing", "DVOP-1")
	id1, err := s.Record(ctx, history.Assessment{StartedAt: t0, FinishedAt: t0.Add(time.Minute), ItemCount: 2, Risk: history.RiskStats{Items: 2, Sum: 1000},
		ByClass: map[string]history.RiskStats{"eng": {Items: 2}},
		Counts:  map[string]int{"critical": 7}, DistinctKEV: 3, Summary: map[string]any{"findings": 905}, Items: []history.Snapshot{a, b}},
		[]history.Event{
			{Key: a.Key, Kind: history.KindOpened, At: t0, Payload: history.Payload{Snapshot: &a}},
			{Key: b.Key, Kind: history.KindOpened, At: t0, Payload: history.Payload{Snapshot: &b}},
		}, nil)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	open, err := s.Open(ctx)
	if err != nil || len(open) != 2 {
		t.Fatalf("open = %d items, %v", len(open), err)
	}
	if open[0].Opened.Key != b.Key || open[0].Current.Signals[0] != "kev" || !open[0].OpenedAt.Equal(t0) {
		t.Errorf("open[0] = %+v", open[0])
	}

	// Ticket raised against the first assessment; appending twice inserts once.
	raised := []history.Event{{ItemID: open[1].ID, Key: a.Key, Kind: history.KindTicketRaised, At: t0, Payload: history.Payload{Ticket: "DVOP-2", Action: "create"}}}
	if err := s.Append(ctx, id1, raised); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Append(ctx, id1, raised); err != nil {
		t.Fatalf("append again: %v", err)
	}

	// Second run: a changes, b resolves.
	t1 := t0.AddDate(0, 0, 20)
	a2 := a
	a2.Priority = "urgent"
	opened := open[0].Opened
	days := 20
	_, err = s.Record(ctx, history.Assessment{StartedAt: t1, FinishedAt: t1.Add(time.Minute), ItemCount: 1, Risk: history.RiskStats{Items: 1, Sum: 500}},
		[]history.Event{
			{ItemID: open[1].ID, Key: a.Key, Kind: history.KindChanged, At: t1, Payload: history.Payload{Snapshot: &a2, Changes: []string{"priority: high -> urgent"}}},
			{ItemID: open[0].ID, Key: b.Key, Kind: history.KindResolved, At: t1, Payload: history.Payload{Opened: &opened, OpenedAt: &t0, DaysOpen: &days, Ticketed: true, Evidence: "lib is on 1.1."}},
		}, nil)
	if err != nil {
		t.Fatalf("record 2: %v", err)
	}
	open, _ = s.Open(ctx)
	if len(open) != 1 || open[0].Current.Priority != "urgent" || open[0].Opened.Priority != "high" {
		t.Errorf("after run 2, open = %+v", open)
	}

	events, err := s.Events(ctx, t0, t1.Add(time.Hour))
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	kinds := map[history.Kind]int{}
	for _, e := range events {
		kinds[e.Kind]++
	}
	if kinds[history.KindOpened] != 2 || kinds[history.KindTicketRaised] != 1 || kinds[history.KindChanged] != 1 || kinds[history.KindResolved] != 1 {
		t.Errorf("kinds = %v", kinds)
	}
	for _, e := range events {
		if e.Kind == history.KindResolved && (e.Payload.Opened == nil || !e.Payload.Ticketed || *e.Payload.DaysOpen != 20) {
			t.Errorf("resolved payload lost fields: %+v", e.Payload)
		}
	}

	as, err := s.Assessments(ctx, t0, t1.Add(time.Hour))
	if err != nil || len(as) != 2 || as[0].Risk.Sum != 1000 || as[0].ByClass["eng"].Items != 2 {
		t.Errorf("assessments = %+v (%v)", as, err)
	}
	if as[0].Counts["critical"] != 7 || as[0].DistinctKEV != 3 || as[0].Summary == nil || as[0].Items != nil {
		t.Errorf("assessment detail = counts %v kev %d summary %v items %v (items are read separately)", as[0].Counts, as[0].DistinctKEV, as[0].Summary, as[0].Items)
	}
	if items, err := s.AssessmentItems(ctx, id1); err != nil || len(items) != 2 || items[0].Key != a.Key {
		t.Errorf("assessment items = %+v (%v)", items, err)
	}
	if items, err := s.AssessmentItems(ctx, 9999); err != nil || items != nil {
		t.Errorf("unknown assessment items should be nil, nil: %+v %v", items, err)
	}
	first, ok, err := s.First(ctx)
	if err != nil || !ok || !first.Equal(t0.Add(time.Minute)) {
		t.Errorf("first = %v %v %v", first, ok, err)
	}

	item, err := s.Item(ctx, b.Key)
	if err != nil || item == nil || len(item.Items) != 1 || item.Items[0].ClosedKind != history.KindResolved || len(item.Events) != 2 {
		t.Errorf("item = %+v (%v)", item, err)
	}
	if none, err := s.Item(ctx, "never|seen"); err != nil || none != nil {
		t.Errorf("unknown key should be nil, nil: %+v %v", none, err)
	}

	// A recurrence after a close is a new row under the same key.
	t2 := t1.AddDate(0, 0, 5)
	if _, err := s.Record(ctx, history.Assessment{StartedAt: t2, FinishedAt: t2},
		[]history.Event{{Key: b.Key, Kind: history.KindOpened, At: t2, Payload: history.Payload{Snapshot: &b}}}, nil); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	item, _ = s.Item(ctx, b.Key)
	if len(item.Items) != 2 || item.Items[1].ClosedAt != nil {
		t.Errorf("recurrence should be a second span: %+v", item.Items)
	}

	// Retention: everything before t1 goes, open items stay.
	pruned, err := s.Prune(ctx, t1)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned.Events != 3 || pruned.Assessments != 1 || pruned.Items != 0 {
		t.Errorf("pruned = %+v (opened x2 + ticket_raised at t0; the item closed at t1 is kept)", pruned)
	}
	if open, _ = s.Open(ctx); len(open) != 2 {
		t.Errorf("open items must survive retention: %d", len(open))
	}
}

func TestReassignmentMovesTheKey(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)
	a := snap("eng|orders|app|svc", "app", "orders")
	if _, err := s.Record(ctx, history.Assessment{StartedAt: t0, FinishedAt: t0},
		[]history.Event{{Key: a.Key, Kind: history.KindOpened, At: t0, Payload: history.Payload{Snapshot: &a}}}, nil); err != nil {
		t.Fatal(err)
	}
	open, _ := s.Open(ctx)
	moved := a
	moved.Team, moved.Key = "payments", "eng|payments|app|svc"
	if _, err := s.Record(ctx, history.Assessment{StartedAt: t0, FinishedAt: t0.Add(time.Hour)},
		[]history.Event{{ItemID: open[0].ID, Key: a.Key, Kind: history.KindReassigned, At: t0.Add(time.Hour),
			Payload: history.Payload{Snapshot: &moved, From: &history.Owner{Class: "eng", Team: "orders"}, To: &history.Owner{Class: "eng", Team: "payments"}}}}, nil); err != nil {
		t.Fatal(err)
	}
	open, _ = s.Open(ctx)
	if len(open) != 1 || open[0].Current.Key != moved.Key || open[0].Opened.Key != a.Key {
		t.Errorf("reassigned item = %+v", open)
	}
	events, _ := s.Events(ctx, t0, t0.Add(2*time.Hour))
	for _, e := range events {
		if e.Key != moved.Key {
			t.Errorf("events report under the current key, got %q", e.Key)
		}
	}
}

func TestOpenRejectsUnknownAuth(t *testing.T) {
	_, err := Open(context.Background(), Options{DSN: "postgres://x", Auth: "kerberos"})
	if err == nil {
		t.Fatal("unknown auth must be refused")
	}
	if _, err := Open(context.Background(), Options{}); err == nil {
		t.Fatal("empty DSN must be refused")
	}
}

func TestMarksPersistAndClearOnClose(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	a := snap("eng|orders|app|svc", "app", "orders")
	if _, err := s.Record(ctx, history.Assessment{StartedAt: t0, FinishedAt: t0},
		[]history.Event{{Key: a.Key, Kind: history.KindOpened, At: t0, Payload: history.Payload{Snapshot: &a}}}, nil); err != nil {
		t.Fatal(err)
	}
	open, _ := s.Open(ctx)
	since := t0.Add(time.Hour)
	if _, err := s.Record(ctx, history.Assessment{StartedAt: since, FinishedAt: since}, nil,
		[]history.Mark{{ItemID: open[0].ID, Missing: 2, MissingSince: &since}}); err != nil {
		t.Fatal(err)
	}
	open, _ = s.Open(ctx)
	if open[0].Missing != 2 || open[0].MissingSince == nil || !open[0].MissingSince.Equal(since) {
		t.Fatalf("mark should round-trip: %+v", open[0])
	}
	if _, err := s.Record(ctx, history.Assessment{StartedAt: since, FinishedAt: since}, nil,
		[]history.Mark{{ItemID: open[0].ID}}); err != nil {
		t.Fatal(err)
	}
	open, _ = s.Open(ctx)
	if open[0].Missing != 0 || open[0].MissingSince != nil {
		t.Fatalf("a zero mark clears: %+v", open[0])
	}
}

// A ticket's due date is held on the item so a close can be measured against it,
// and is never moved once recorded.
func TestTicketDueRoundTripsAndIsNeverMoved(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	a := snap("eng|orders|app|svc", "app", "orders")
	b := snap("eng|billing|lib|svc", "lib", "billing")
	id, err := s.Record(ctx, history.Assessment{StartedAt: t0, FinishedAt: t0}, []history.Event{
		{Key: a.Key, Kind: history.KindOpened, At: t0, Payload: history.Payload{Snapshot: &a}},
		{Key: b.Key, Kind: history.KindOpened, At: t0, Payload: history.Payload{Snapshot: &b}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := s.Open(ctx)
	byKey := map[string]history.State{}
	for _, st := range open {
		byKey[st.Current.Key] = st
	}
	due := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	if err := s.Append(ctx, id, []history.Event{
		{ItemID: byKey[a.Key].ID, Key: a.Key, Kind: history.KindTicketRaised, At: t0,
			Payload: history.Payload{Ticket: "DVOP-1", Action: "create", DueDate: &due}},
		{ItemID: byKey[b.Key].ID, Key: b.Key, Kind: history.KindTicketRaised, At: t0,
			Payload: history.Payload{Ticket: "DVOP-2", Action: "create"}},
	}); err != nil {
		t.Fatal(err)
	}

	// A later create for the same key, and an extend, must leave the date alone.
	t1 := t0.Add(time.Hour)
	id2, err := s.Record(ctx, history.Assessment{StartedAt: t1, FinishedAt: t1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	later := due.AddDate(0, 0, 30)
	if err := s.Append(ctx, id2, []history.Event{
		{ItemID: byKey[a.Key].ID, Key: a.Key, Kind: history.KindTicketRaised, At: t1,
			Payload: history.Payload{Ticket: "DVOP-1", Action: "create", DueDate: &later}},
		{ItemID: byKey[b.Key].ID, Key: b.Key, Kind: history.KindTicketRaised, At: t1,
			Payload: history.Payload{Ticket: "DVOP-1", Action: "extend"}},
	}); err != nil {
		t.Fatal(err)
	}

	open, _ = s.Open(ctx)
	for _, st := range open {
		switch st.Current.Key {
		case a.Key:
			if got, ok := st.TicketDue["DVOP-1"]; !ok || !got.Equal(due) || len(st.TicketDue) != 1 {
				t.Errorf("a.TicketDue = %v, want DVOP-1 due %v", st.TicketDue, due)
			}
		case b.Key:
			if st.TicketDue != nil {
				t.Errorf("b.TicketDue = %v, want nil: neither write carried a due date", st.TicketDue)
			}
		}
	}
	events, _ := s.Events(ctx, t0, t1.Add(time.Minute))
	var raised int
	for _, e := range events {
		if e.Kind == history.KindTicketRaised && e.Payload.Ticket == "DVOP-1" && e.Payload.Action == "create" {
			raised++
			if e.Payload.DueDate == nil {
				t.Errorf("ticket_raised create lost its due_date: %+v", e.Payload)
			}
		}
	}
	if raised != 2 {
		t.Errorf("recorded %d DVOP-1 creates, want 2", raised)
	}
}

// Tickets are rewritten from the tracker on every sync, except that a match to an
// item survives a sync that matched nothing, and a first In Progress read from the
// change history is not replaced by the status-category fallback.
func TestTrackerTicketsUpsertReadAndPrune(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	jul := func(d int) time.Time { return time.Date(2026, 7, d, 9, 0, 0, 0, time.UTC) }
	ptrT := func(t time.Time) *time.Time { return &t }

	idx, err := s.TicketsIndexed(ctx)
	if err != nil || idx.Tickets != 0 {
		t.Fatalf("empty index = %+v (%v)", idx, err)
	}
	opened := jul(1)
	if err := s.UpsertTickets(ctx, []history.TrackerTicket{
		{Key: "DVOP-1", Project: "DVOP", ItemKey: "eng|orders|app|svc", ItemOpenedAt: &opened, CreatedAt: jul(2),
			StartedAt: ptrT(jul(3)), StartedFrom: history.StartedFromChangelog, Status: "In Progress",
			StatusCategory: "indeterminate", LastSeenAt: jul(3), Raw: []byte(`{"customfield_1":["app"]}`)},
		{Key: "DVOP-2", Project: "DVOP", CreatedAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			ResolvedAt: ptrT(time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC)), Status: "Done", StatusCategory: "done", LastSeenAt: jul(3)},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// The next sync: DVOP-1 resolved, its item closed so nothing matched it, and the
	// history could not be read so only the fallback start is known.
	due := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	if err := s.UpsertTickets(ctx, []history.TrackerTicket{
		{Key: "DVOP-1", Project: "DVOP", CreatedAt: jul(2), StartedAt: ptrT(jul(8)), StartedFrom: history.StartedFromStatusCategory,
			ResolvedAt: ptrT(jul(10)), DueAt: &due, Status: "Done", StatusCategory: "done", LastSeenAt: jul(11)},
	}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, err := s.Tickets(ctx, jul(1), jul(31))
	if err != nil {
		t.Fatalf("tickets: %v", err)
	}
	if len(got) != 1 || got[0].Key != "DVOP-1" {
		t.Fatalf("July window = %+v, want DVOP-1 only: DVOP-2 was created and resolved in March and matched nothing", got)
	}
	d := got[0]
	if d.ItemKey != "eng|orders|app|svc" || d.ItemOpenedAt == nil || !d.ItemOpenedAt.Equal(opened) {
		t.Errorf("the item match was forgotten: %q %v", d.ItemKey, d.ItemOpenedAt)
	}
	if d.StartedAt == nil || !d.StartedAt.Equal(jul(3)) || d.StartedFrom != history.StartedFromChangelog {
		t.Errorf("started = %v from %q, want the changelog's %v", d.StartedAt, d.StartedFrom, jul(3))
	}
	if d.ResolvedAt == nil || !d.ResolvedAt.Equal(jul(10)) || d.DueAt == nil || !d.DueAt.Equal(due) || d.StatusCategory != "done" {
		t.Errorf("tracker fields not rewritten: %+v", d)
	}

	// A resolved ticket matched to an item is read whatever the window, so the open
	// summary can date a close older than the range.
	got, err = s.Tickets(ctx, jul(20), jul(31))
	if err != nil || len(got) != 1 || got[0].Key != "DVOP-1" {
		t.Errorf("a matched close outside the window should still be read: %+v (%v)", got, err)
	}

	idx, err = s.TicketsIndexed(ctx)
	if err != nil || idx.Tickets != 2 || !idx.FirstCreated.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)) || !idx.LastSynced.Equal(jul(11)) {
		t.Errorf("index = %+v (%v)", idx, err)
	}

	p, err := s.Prune(ctx, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || p.Tickets != 1 {
		t.Fatalf("prune = %+v (%v), want DVOP-2 only: resolved before the cutoff", p, err)
	}
	if idx, _ := s.TicketsIndexed(ctx); idx.Tickets != 1 {
		t.Errorf("after prune the index holds %d tickets, want 1", idx.Tickets)
	}
}
