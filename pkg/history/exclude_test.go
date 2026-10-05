package history

import (
	"testing"
	"time"
)

func TestExcludeTickets(t *testing.T) {
	r := Range{Since: day(2026, 9, 10), Until: day(2026, 10, 5), Bucket: BucketMonth}
	resolved := func(d time.Time) *time.Time { return &d }
	tickets := []TrackerTicket{
		{Key: "PROJ-1", Project: "PROJ", Parent: "PROJ-100", CreatedAt: day(2026, 9, 2), ResolvedAt: resolved(day(2026, 9, 20))},
		{Key: "PROJ-2", Project: "PROJ", Parent: "PROJ-9", CreatedAt: day(2026, 9, 3), ResolvedAt: resolved(day(2026, 9, 21))},
		{Key: "PROJ-3", Project: "PROJ", Parent: "PROJ-9", CreatedAt: day(2026, 9, 25)},
		// Raised long before the range, extended in it.
		{Key: "PROJ-4", Project: "PROJ", Parent: "PROJ-9", CreatedAt: day(2026, 3, 1)},
		{Key: "SAND-1", Project: "SAND", CreatedAt: day(2026, 9, 26)},
	}
	events := []Event{
		{ItemID: 1, Key: "a", Kind: KindTicketRaised, At: day(2026, 9, 2), Payload: Payload{Ticket: "PROJ-1", Action: "create"}},
		{ItemID: 2, Key: "b", Kind: KindTicketRaised, At: day(2026, 9, 3), Payload: Payload{Ticket: "PROJ-2", Action: "create"}},
		{ItemID: 2, Key: "b", Kind: KindTicketClosed, At: day(2026, 9, 21), Payload: Payload{Ticket: "PROJ-2"}},
		{ItemID: 3, Key: "c", Kind: KindTicketRaised, At: day(2026, 9, 25), Payload: Payload{Ticket: "PROJ-3", Action: "create"}},
		{ItemID: 4, Key: "d", Kind: KindTicketRaised, At: day(2026, 9, 26), Payload: Payload{Ticket: "PROJ-4", Action: "extend"}},
		{ItemID: 5, Key: "e", Kind: KindTicketRaised, At: day(2026, 9, 26), Payload: Payload{Ticket: "SAND-1", Action: "create"}},
		{ItemID: 1, Key: "a", Kind: KindOpened, At: day(2026, 9, 1), Payload: Payload{Snapshot: &Snapshot{Key: "a"}}},
	}
	cases := []struct {
		name        string
		scopes      []TicketScope
		keptEvents  int
		keptTickets []string
		want        *ExcludedTickets
	}{
		{name: "nothing configured leaves everything", keptEvents: 7, keptTickets: []string{"PROJ-1", "PROJ-2", "PROJ-3", "PROJ-4", "SAND-1"}},
		{name: "a test epic", scopes: []TicketScope{{Route: "test", Project: "PROJ", Epic: "PROJ-9"}},
			keptEvents: 3, keptTickets: []string{"PROJ-1", "SAND-1"},
			// tickets_raised counts the extend of PROJ-4 as the report does; the
			// tracker counts PROJ-4 nowhere, since it was raised in March.
			want: &ExcludedTickets{Routes: []string{"test (project PROJ, epic PROJ-9)"}, Tickets: 2,
				TicketsRaised: 3, TicketsClosed: 1, TrackerTicketsRaised: 2, TrackerTicketsClosed: 1}},
		{name: "a project of its own", scopes: []TicketScope{{Route: "sandbox", Project: "SAND"}},
			keptEvents: 6, keptTickets: []string{"PROJ-1", "PROJ-2", "PROJ-3", "PROJ-4"},
			want: &ExcludedTickets{Routes: []string{"sandbox (project SAND)"}, Tickets: 1, TicketsRaised: 1, TrackerTicketsRaised: 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evs, kept, ex := ExcludeTickets(r, events, tickets, c.scopes)
			if len(evs) != c.keptEvents {
				t.Errorf("kept %d events, want %d", len(evs), c.keptEvents)
			}
			var keys []string
			for _, tk := range kept {
				keys = append(keys, tk.Key)
			}
			if !equalStrings(keys, c.keptTickets) || len(keys) != len(c.keptTickets) {
				t.Errorf("kept tickets %v, want %v", keys, c.keptTickets)
			}
			switch {
			case c.want == nil && ex != nil:
				t.Errorf("excluded = %+v, want nil", ex)
			case c.want != nil && (ex == nil || !equalExcluded(*ex, *c.want)):
				t.Errorf("excluded = %+v, want %+v", ex, c.want)
			}
		})
	}
}

func equalExcluded(a, b ExcludedTickets) bool {
	return equalStrings(a.Routes, b.Routes) && len(a.Routes) == len(b.Routes) && a.Tickets == b.Tickets &&
		a.TicketsRaised == b.TicketsRaised && a.TicketsClosed == b.TicketsClosed &&
		a.TrackerTicketsRaised == b.TrackerTicketsRaised && a.TrackerTicketsClosed == b.TrackerTicketsClosed
}

// An item covered only by tickets on an excluded route was not ticketed work, for
// resolutions, clears and decommissions alike; one also covered by a counted ticket was.
func TestExcludedTicketsDoNotMakeAnItemTicketed(t *testing.T) {
	r := Range{Since: day(2026, 9, 1), Until: day(2026, 9, 30), Bucket: BucketMonth}
	tickets := []TrackerTicket{
		{Key: "T-1", Project: "PROJ", Parent: "PROJ-9", CreatedAt: day(2026, 9, 2)},
		{Key: "R-1", Project: "PROJ", Parent: "PROJ-1", CreatedAt: day(2026, 9, 2)},
	}
	cve := []CVE{{ID: "CVE-1", KEV: true}}
	events := []Event{
		{ItemID: 1, Key: "a", Kind: KindResolved, At: day(2026, 9, 5), Payload: Payload{Ticketed: true, Closed: &Snapshot{Key: "a", Tickets: []string{"T-1"}, CVEs: cve}}},
		{ItemID: 2, Key: "b", Kind: KindResolved, At: day(2026, 9, 5), Payload: Payload{Ticketed: true, Closed: &Snapshot{Key: "b", Tickets: []string{"T-1", "R-1"}}}},
		{ItemID: 3, Key: "c", Kind: KindChanged, At: day(2026, 9, 6), Payload: Payload{Ticketed: true, Tickets: []string{"T-1"}, CVEsCleared: []CVE{{ID: "CVE-2"}}}},
		{ItemID: 4, Key: "d", Kind: KindDecommissioned, At: day(2026, 9, 7), Payload: Payload{Ticketed: true, Tickets: []string{"T-1"}, Closed: &Snapshot{Key: "d", CVEs: []CVE{{ID: "CVE-3"}}}}},
	}
	evs, _, _ := ExcludeTickets(r, events, tickets, []TicketScope{{Route: "test", Project: "PROJ", Epic: "PROJ-9"}})
	m := Aggregate(r, nil, evs, nil, time.Time{}, r.Until).Movement[0]
	if m.ResolvedTicketed != 1 || m.ResolvedUnticketed != 1 {
		t.Errorf("resolved ticketed/unticketed = %d/%d, want 1/1", m.ResolvedTicketed, m.ResolvedUnticketed)
	}
	if m.ClearedTicketed.CVEs != 0 || m.ClearedUnticketed.CVEs != 2 {
		t.Errorf("cleared ticketed/unticketed = %+v / %+v, want 0 and 2", m.ClearedTicketed, m.ClearedUnticketed)
	}
	if m.Decommissioned.ItemsTicketed != 0 || m.Decommissioned.Ticketed.CVEs != 0 {
		t.Errorf("decommissioned = %+v, want nothing ticketed", m.Decommissioned)
	}
	if events[0].Payload.Ticketed != true {
		t.Errorf("the caller's events were modified")
	}
}
