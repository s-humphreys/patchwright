package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
)

// A ticket's epic round-trips, and rows stored before it was read ask for one full
// read: only those the last read touched, so a ticket no read returns any more
// cannot ask again on every run.
func TestTicketParentRoundTripsAndAsksForOneFullRead(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	at := func(d int) time.Time { return time.Date(2026, 9, d, 9, 0, 0, 0, time.UTC) }
	// Rows as an earlier version stored them: no parent column written.
	for _, row := range []struct {
		key  string
		seen time.Time
	}{{"PROJ-1", at(1)}, {"PROJ-2", at(2)}, {"PROJ-3", at(2)}} {
		if _, err := s.pool.Exec(ctx, `INSERT INTO tickets (key, project, created_at, last_seen_at) VALUES ($1, 'PROJ', $2, $2)`,
			row.key, row.seen); err != nil {
			t.Fatal(err)
		}
	}
	idx, err := s.TicketsIndexed(ctx)
	if err != nil || idx.Unparented != 2 {
		t.Fatalf("unparented = %d (%v), want 2: the rows the last read touched", idx.Unparented, err)
	}
	// The full read returns PROJ-2 on an epic and PROJ-3 at the root; PROJ-1 is out
	// of scope now and is not returned.
	if err := s.UpsertTickets(ctx, []history.TrackerTicket{
		{Key: "PROJ-2", Project: "PROJ", Parent: "PROJ-9", CreatedAt: at(2), LastSeenAt: at(3)},
		{Key: "PROJ-3", Project: "PROJ", CreatedAt: at(2), LastSeenAt: at(3)},
	}); err != nil {
		t.Fatal(err)
	}
	if idx, err := s.TicketsIndexed(ctx); err != nil || idx.Unparented != 0 {
		t.Errorf("after the full read unparented = %d (%v), want 0", idx.Unparented, err)
	}
	got, err := s.Tickets(ctx, at(1), at(30))
	if err != nil {
		t.Fatal(err)
	}
	parents := map[string]string{}
	for _, tk := range got {
		parents[tk.Key] = tk.Parent
	}
	if parents["PROJ-2"] != "PROJ-9" || parents["PROJ-3"] != "" || parents["PROJ-1"] != "" {
		t.Errorf("parents = %v", parents)
	}
}
