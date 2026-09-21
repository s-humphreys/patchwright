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
		_, _ = s.pool.Exec(ctx, `TRUNCATE events, items, assessments RESTART IDENTITY`)
		s.Close()
	})
	if _, err := s.pool.Exec(ctx, `TRUNCATE events, items, assessments RESTART IDENTITY`); err != nil {
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
	if err := s.pool.QueryRow(context.Background(), `SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil || v != 1 {
		t.Errorf("schema version = %d (%v)", v, err)
	}
}

func TestLifecycleRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	a := snap("eng|orders|app|svc", "app", "orders")
	b := snap("eng|billing|lib|svc", "lib", "billing", "DVOP-1")
	id1, err := s.Record(ctx, history.Assessment{StartedAt: t0, FinishedAt: t0.Add(time.Minute), Items: 2, Risk: history.RiskStats{Items: 2, Sum: 1000},
		ByClass: map[string]history.RiskStats{"eng": {Items: 2}}},
		[]history.Event{
			{Key: a.Key, Kind: history.KindOpened, At: t0, Payload: history.Payload{Snapshot: &a}},
			{Key: b.Key, Kind: history.KindOpened, At: t0, Payload: history.Payload{Snapshot: &b}},
		})
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
	_, err = s.Record(ctx, history.Assessment{StartedAt: t1, FinishedAt: t1.Add(time.Minute), Items: 1, Risk: history.RiskStats{Items: 1, Sum: 500}},
		[]history.Event{
			{ItemID: open[1].ID, Key: a.Key, Kind: history.KindChanged, At: t1, Payload: history.Payload{Snapshot: &a2, Changes: []string{"priority: high -> urgent"}}},
			{ItemID: open[0].ID, Key: b.Key, Kind: history.KindResolved, At: t1, Payload: history.Payload{Opened: &opened, OpenedAt: &t0, DaysOpen: &days, Ticketed: true, Evidence: "lib is on 1.1."}},
		})
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
		[]history.Event{{Key: b.Key, Kind: history.KindOpened, At: t2, Payload: history.Payload{Snapshot: &b}}}); err != nil {
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
		[]history.Event{{Key: a.Key, Kind: history.KindOpened, At: t0, Payload: history.Payload{Snapshot: &a}}}); err != nil {
		t.Fatal(err)
	}
	open, _ := s.Open(ctx)
	moved := a
	moved.Team, moved.Key = "payments", "eng|payments|app|svc"
	if _, err := s.Record(ctx, history.Assessment{StartedAt: t0, FinishedAt: t0.Add(time.Hour)},
		[]history.Event{{ItemID: open[0].ID, Key: a.Key, Kind: history.KindReassigned, At: t0.Add(time.Hour),
			Payload: history.Payload{Snapshot: &moved, From: &history.Owner{Class: "eng", Team: "orders"}, To: &history.Owner{Class: "eng", Team: "payments"}}}}); err != nil {
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
