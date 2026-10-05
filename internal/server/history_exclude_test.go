package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
)

// Tickets on a route configured out of the counts drop from every ticket count the
// history serves, and the report says how many and where from.
func TestHistoryLeavesExcludedTicketsOutOfTheCounts(t *testing.T) {
	sep := func(d int) time.Time { return time.Date(2026, 9, d, 12, 0, 0, 0, time.UTC) }
	resolved := sep(20)
	store := newMemStore()
	for _, tk := range []history.TrackerTicket{
		{Key: "PROJ-1", Project: "PROJ", Parent: "PROJ-100", CreatedAt: sep(2), ResolvedAt: &resolved, LastSeenAt: sep(21)},
		{Key: "PROJ-2", Project: "PROJ", Parent: "PROJ-9", CreatedAt: sep(3), ResolvedAt: &resolved, LastSeenAt: sep(21)},
		{Key: "PROJ-3", Project: "PROJ", Parent: "PROJ-9", CreatedAt: sep(4), LastSeenAt: sep(21)},
	} {
		store.tickets[tk.Key] = tk
	}
	item := history.Snapshot{Key: "k", Repository: "app"}
	if _, err := store.Record(context.Background(), history.Assessment{FinishedAt: sep(1)}, []history.Event{
		{Key: "k", Kind: history.KindOpened, At: sep(1), Payload: history.Payload{Snapshot: &item}},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(context.Background(), 1, []history.Event{
		{ItemID: 1, Key: "k", Kind: history.KindTicketRaised, At: sep(2), Payload: history.Payload{Ticket: "PROJ-1", Action: "create"}},
		{ItemID: 1, Key: "k", Kind: history.KindTicketRaised, At: sep(3), Payload: history.Payload{Ticket: "PROJ-2", Action: "create"}},
		{ItemID: 1, Key: "k", Kind: history.KindTicketRaised, At: sep(4), Payload: history.Payload{Ticket: "PROJ-3", Action: "create"}},
		{ItemID: 1, Key: "k", Kind: history.KindTicketClosed, At: sep(20), Payload: history.Payload{Ticket: "PROJ-2"}},
	}); err != nil {
		t.Fatal(err)
	}
	rng := history.Range{Since: sep(1), Until: sep(25), Bucket: history.BucketMonth}

	for _, tc := range []struct {
		name                           string
		scopes                         []history.TicketScope
		raised, closed, trackerRaised  int
		trackerClosed, perDay, dropped int
	}{
		{name: "nothing excluded", raised: 3, closed: 1, trackerRaised: 3, trackerClosed: 2, perDay: 3},
		{name: "a test epic", scopes: []history.TicketScope{{Route: "test", Project: "PROJ", Epic: "PROJ-9"}},
			raised: 1, trackerRaised: 1, trackerClosed: 1, perDay: 1, dropped: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(&stubAssessor{}).WithHistory(store, 400*24*time.Hour).WithTicketExclusions(tc.scopes)
			rep, err := s.historyReport(context.Background(), rng, sep(25))
			if err != nil {
				t.Fatal(err)
			}
			m := rep.Movement[0]
			if m.TicketsRaised != tc.raised || m.TicketsClosed != tc.closed ||
				*m.TrackerTicketsRaised != tc.trackerRaised || *m.TrackerTicketsClosed != tc.trackerClosed {
				t.Errorf("raised/closed %d/%d, tracker %d/%d; want %d/%d, %d/%d", m.TicketsRaised, m.TicketsClosed,
					*m.TrackerTicketsRaised, *m.TrackerTicketsClosed, tc.raised, tc.closed, tc.trackerRaised, tc.trackerClosed)
			}
			caveats := strings.Join(rep.Caveats, "\n")
			if tc.scopes == nil {
				if rep.TicketsExcluded != nil || strings.Contains(caveats, "leave out") {
					t.Errorf("nothing excluded, nothing said: %+v %s", rep.TicketsExcluded, caveats)
				}
			} else {
				ex := rep.TicketsExcluded
				if ex == nil || ex.Tickets != 2 || ex.TicketsRaised != 2 || ex.TicketsClosed != 1 || ex.TrackerTicketsRaised != 2 || ex.TrackerTicketsClosed != 1 {
					t.Errorf("excluded = %+v", ex)
				}
				if !strings.Contains(caveats, "the ticket counts leave out 2 tickets on test (project PROJ, epic PROJ-9)") {
					t.Errorf("caveats should say what was left out:\n%s", caveats)
				}
			}

			var resp ticketsPerDayResponse
			path := "/api/v1/history/tickets?since=" + sep(1).Format(time.RFC3339) + "&until=" + sep(25).Format(time.RFC3339)
			if code := getJSON(t, s.Handler(), path, &resp); code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			if resp.Tickets.Total != tc.perDay || resp.Tickets.Excluded != tc.dropped {
				t.Errorf("per day total %d excluded %d, want %d and %d", resp.Tickets.Total, resp.Tickets.Excluded, tc.perDay, tc.dropped)
			}
			if tc.dropped > 0 && !strings.Contains(strings.Join(resp.Tickets.Caveats, " "), "2 tickets created in the range on test") {
				t.Errorf("per-day caveats = %v", resp.Tickets.Caveats)
			}
		})
	}
}

// Before the tracker has been read nothing can be told apart, and the report says
// so rather than claiming to have left anything out.
func TestHistoryExclusionWithoutTheTracker(t *testing.T) {
	store := newMemStore()
	s := New(&stubAssessor{}).WithHistory(store, 400*24*time.Hour).
		WithTicketExclusions([]history.TicketScope{{Route: "test", Project: "PROJ", Epic: "PROJ-9"}})
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	rep, err := s.historyReport(context.Background(), history.Range{Since: now.AddDate(0, 0, -30), Until: now, Bucket: history.BucketMonth}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rep.Caveats, "\n"), "the tracker has not been read, so none could be told apart") {
		t.Errorf("caveats = %v", rep.Caveats)
	}
}
