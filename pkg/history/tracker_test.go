package history

import (
	"context"
	"testing"
	"time"
)

func TestMatchTicketsByImage(t *testing.T) {
	early, late := day(2026, 7, 1), day(2026, 7, 5)
	open := []State{
		{ID: 1, OpenedAt: late, Current: Snapshot{Key: "eng|orders|app|svc", Repository: "app"}},
		{ID: 2, OpenedAt: early, Current: Snapshot{Key: "eng|billing|app|svc", Repository: "app"}},
		{ID: 3, OpenedAt: late, Current: Snapshot{Key: "eng|orders|lib|base", Repository: "lib", Tickets: []string{"DVOP-2"}}},
		{ID: 4, OpenedAt: early, Current: Snapshot{Key: "eng|billing|lib|base", Repository: "lib"}},
	}
	got := MatchTickets([]TrackerTicket{
		{Key: "DVOP-1", Images: []string{"app"}},
		{Key: "DVOP-2", Images: []string{"lib"}},
		{Key: "DVOP-3", Images: []string{"gone"}},
	}, open)

	// Two items share the repository: the one opened first, absent a better claim.
	if got[0].ItemKey != "eng|billing|app|svc" || !got[0].ItemOpenedAt.Equal(early) {
		t.Errorf("DVOP-1 matched %q at %v", got[0].ItemKey, got[0].ItemOpenedAt)
	}
	// The item whose snapshot already lists the ticket wins over an older one.
	if got[1].ItemKey != "eng|orders|lib|base" || !got[1].ItemOpenedAt.Equal(late) {
		t.Errorf("DVOP-2 matched %q at %v, want the item that lists it", got[1].ItemKey, got[1].ItemOpenedAt)
	}
	if got[2].ItemKey != "" || got[2].ItemOpenedAt != nil {
		t.Errorf("DVOP-3 matches nothing open: %+v", got[2])
	}
}

func TestAggregateCycleTimeFromTheTracker(t *testing.T) {
	r := Range{Since: day(2026, 6, 1), Until: day(2026, 9, 21), Bucket: BucketMonth}
	first := time.Date(2026, 6, 10, 9, 0, 0, 0, time.UTC)
	now := day(2026, 9, 21)
	h := func(d time.Time, hours int) time.Time { return d.Add(time.Duration(hours) * time.Hour) }
	opened := day(2026, 7, 1)
	tickets := []TrackerTicket{
		// July: told 1 day, to start 2 days, worked 3 days.
		{Key: "T-1", ItemKey: "a", ItemOpenedAt: &opened, CreatedAt: day(2026, 7, 2),
			StartedAt: ptr(day(2026, 7, 4)), ResolvedAt: ptr(day(2026, 7, 7))},
		// July: told 3 days, to start half a day, worked 5 days.
		{Key: "T-2", ItemKey: "b", ItemOpenedAt: &opened, CreatedAt: day(2026, 7, 4),
			StartedAt: ptr(h(day(2026, 7, 4), 12)), ResolvedAt: ptr(h(day(2026, 7, 9), 12))},
		// July: a baseline item, whose opening is when the watching began, so its
		// told is unknown; never In Progress, so neither other interval either.
		{Key: "T-3", ItemKey: "c", ItemOpenedAt: &first, CreatedAt: day(2026, 6, 20), ResolvedAt: ptr(day(2026, 7, 20))},
		// July: raised before the item's current span opened, so told is unknown.
		{Key: "T-4", ItemKey: "d", ItemOpenedAt: ptr(day(2026, 7, 15)), CreatedAt: day(2026, 7, 10),
			StartedAt: ptr(day(2026, 7, 16)), ResolvedAt: ptr(day(2026, 7, 26)), StartedFrom: StartedFromStatusCategory},
		// August: raised, not resolved.
		{Key: "T-5", CreatedAt: day(2026, 8, 3)},
		// Before the range: counted nowhere.
		{Key: "T-6", CreatedAt: day(2026, 1, 3), ResolvedAt: ptr(day(2026, 2, 3))},
	}
	idx := TicketIndexState{Tickets: 6, FirstCreated: day(2026, 1, 3), LastSynced: now}

	rep := Aggregate(r, nil, nil, nil, first, now)
	rep.AddTracker(tickets, idx, nil, first, now)

	if rep.Tracker == nil || rep.Tracker.Source != "tracker" || rep.Tracker.Tickets != 6 || rep.Tracker.StartedFromStatusCategory != 1 {
		t.Fatalf("tracker summary = %+v", rep.Tracker)
	}
	jun, jul, aug, sep := rep.Movement[0], rep.Movement[1], rep.Movement[2], rep.Movement[3]
	if *jun.TrackerTicketsRaised != 1 || *jun.TrackerTicketsClosed != 0 {
		t.Errorf("June raised/closed = %d/%d, want 1/0", *jun.TrackerTicketsRaised, *jun.TrackerTicketsClosed)
	}
	if *jul.TrackerTicketsRaised != 3 || *jul.TrackerTicketsClosed != 4 {
		t.Errorf("July raised/closed = %d/%d, want 3/4", *jul.TrackerTicketsRaised, *jul.TrackerTicketsClosed)
	}
	if *aug.TrackerTicketsRaised != 1 || *aug.TrackerTicketsClosed != 0 || *sep.TrackerTicketsRaised != 0 {
		t.Errorf("August/September = %d/%d/%d", *aug.TrackerTicketsRaised, *aug.TrackerTicketsClosed, *sep.TrackerTicketsRaised)
	}
	check := func(name string, got *float64, n int, want float64, wantN int) {
		t.Helper()
		if got == nil || *got != want || n != wantN {
			t.Errorf("%s = %v over %d, want %v over %d", name, got, n, want, wantN)
		}
	}
	check("told", jul.MedianDaysTold, jul.MedianDaysToldN, 2, 2)
	// 0.5, 2 and 6 days.
	check("to start", jul.MedianDaysToStart, jul.MedianDaysToStartN, 2, 3)
	// 3, 5 and 10 days.
	check("worked", jul.MedianDaysWorked, jul.MedianDaysWorkedN, 5, 3)
	if aug.MedianDaysTold != nil || aug.MedianDaysToStartN != 0 || aug.MedianDaysWorked != nil {
		t.Errorf("August resolved nothing, so no cycle time: %+v", aug)
	}
}

// A period before the first ticket is before ticketing, not a period in which none
// were raised; a report with no tracker reads carries nothing from it at all.
func TestAggregateTrackerFieldsAbsentWithoutData(t *testing.T) {
	r := Range{Since: day(2026, 6, 1), Until: day(2026, 8, 21), Bucket: BucketMonth}
	now := day(2026, 8, 21)

	rep := Aggregate(r, nil, nil, nil, time.Time{}, now)
	rep.AddTracker(nil, TicketIndexState{}, nil, time.Time{}, now)
	if rep.Tracker != nil || rep.Movement[0].TrackerTicketsRaised != nil || rep.Open.ClosedTicketFindingOpen != nil {
		t.Errorf("never read: nothing should be set: %+v", rep)
	}

	rep = Aggregate(r, nil, nil, nil, time.Time{}, now)
	rep.AddTracker([]TrackerTicket{{Key: "T-1", CreatedAt: day(2026, 7, 5)}},
		TicketIndexState{Tickets: 1, FirstCreated: day(2026, 7, 5), LastSynced: now}, nil, time.Time{}, now)
	if rep.Movement[0].TrackerTicketsRaised != nil {
		t.Errorf("June ended before the first ticket: want absent, got %v", *rep.Movement[0].TrackerTicketsRaised)
	}
	if rep.Movement[1].TrackerTicketsRaised == nil || *rep.Movement[1].TrackerTicketsRaised != 1 {
		t.Errorf("July raised = %v, want 1", rep.Movement[1].TrackerTicketsRaised)
	}
	if rep.Movement[2].TrackerTicketsRaised == nil || *rep.Movement[2].TrackerTicketsRaised != 0 {
		t.Errorf("August raised = %v, want a counted zero", rep.Movement[2].TrackerTicketsRaised)
	}
}

func TestOpenSummaryDatesTheTicketClosedOnAnOpenItem(t *testing.T) {
	r := Range{Since: day(2026, 6, 1), Until: day(2026, 9, 21), Bucket: BucketMonth}
	now := day(2026, 9, 21)
	open := []State{
		{OpenedAt: day(2026, 6, 1), Current: Snapshot{Key: "a"}},
		{OpenedAt: day(2026, 6, 1), Current: Snapshot{Key: "b"}},
		// Ticketed again: being worked, whatever happened to the first ticket.
		{OpenedAt: day(2026, 6, 1), Current: Snapshot{Key: "c", Tickets: []string{"T-9"}}},
		// Its ticket closed before this span opened: a previous span's ticket.
		{OpenedAt: day(2026, 9, 1), Current: Snapshot{Key: "d"}},
	}
	tickets := []TrackerTicket{
		// Two closes on a: the latest dates it, 3 days ago.
		{Key: "T-1", ItemKey: "a", CreatedAt: day(2026, 6, 2), ResolvedAt: ptr(day(2026, 7, 1))},
		{Key: "T-2", ItemKey: "a", CreatedAt: day(2026, 7, 2), ResolvedAt: ptr(day(2026, 9, 18))},
		// 50 days ago.
		{Key: "T-3", ItemKey: "b", CreatedAt: day(2026, 6, 2), ResolvedAt: ptr(day(2026, 8, 2))},
		{Key: "T-4", ItemKey: "c", CreatedAt: day(2026, 6, 2), ResolvedAt: ptr(day(2026, 8, 2))},
		{Key: "T-5", ItemKey: "d", CreatedAt: day(2026, 6, 2), ResolvedAt: ptr(day(2026, 8, 2))},
		// Still open: not a close.
		{Key: "T-6", ItemKey: "b", CreatedAt: day(2026, 6, 2)},
		// Its item is no longer open.
		{Key: "T-7", ItemKey: "gone", CreatedAt: day(2026, 6, 2), ResolvedAt: ptr(day(2026, 8, 2))},
	}
	rep := Aggregate(r, nil, nil, open, time.Time{}, now)
	rep.AddTracker(tickets, TicketIndexState{Tickets: len(tickets), LastSynced: now}, open, time.Time{}, now)

	if rep.Open.ClosedTicketFindingOpen == nil || *rep.Open.ClosedTicketFindingOpen != 2 {
		t.Fatalf("closed ticket, finding open = %v, want 2", rep.Open.ClosedTicketFindingOpen)
	}
	if rep.Open.ClosedTicketAgeDays["0-7"] != 1 || rep.Open.ClosedTicketAgeDays["30-90"] != 1 || len(rep.Open.ClosedTicketAgeDays) != 2 {
		t.Errorf("ages = %v, want one 0-7 and one 30-90", rep.Open.ClosedTicketAgeDays)
	}
}

// fakeStore is just enough of a Store for SyncTickets.
type fakeStore struct {
	Store
	idx      TicketIndexState
	open     []State
	upserted []TrackerTicket
}

func (f *fakeStore) TicketsIndexed(context.Context) (TicketIndexState, error) { return f.idx, nil }
func (f *fakeStore) Open(context.Context) ([]State, error)                    { return f.open, nil }
func (f *fakeStore) UpsertTickets(_ context.Context, t []TrackerTicket) error {
	f.upserted = append(f.upserted, t...)
	return nil
}

func TestSyncTicketsWindow(t *testing.T) {
	now := day(2026, 9, 21)
	cases := []struct {
		name       string
		idx        TicketIndexState
		full       bool
		wantFull   bool
		wantWindow time.Duration
	}{
		{name: "empty index backfills", wantFull: true},
		{name: "asked to backfill", idx: TicketIndexState{Tickets: 3, LastSynced: now.Add(-time.Hour)}, full: true, wantFull: true},
		{name: "recent sync reads two days", idx: TicketIndexState{Tickets: 3, LastSynced: now.Add(-time.Hour)}, wantWindow: 48 * time.Hour},
		{name: "old sync reads since then", idx: TicketIndexState{Tickets: 3, LastSynced: now.Add(-5 * 24 * time.Hour)}, wantWindow: 5*24*time.Hour + time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeStore{idx: tc.idx, open: []State{{OpenedAt: day(2026, 9, 1), Current: Snapshot{Key: "k", Repository: "app"}}}}
			var gotWithin time.Duration
			fetch := func(_ context.Context, within time.Duration) ([]TrackerTicket, error) {
				gotWithin = within
				return []TrackerTicket{{Key: "T-1", Images: []string{"app"}}, {Key: "T-2"}}, nil
			}
			res, err := SyncTickets(context.Background(), st, fetch, tc.full, now)
			if err != nil {
				t.Fatal(err)
			}
			if res.Full != tc.wantFull || gotWithin != tc.wantWindow {
				t.Errorf("full %v window %v, want %v %v", res.Full, gotWithin, tc.wantFull, tc.wantWindow)
			}
			if res.Fetched != 2 || res.Matched != 1 || len(st.upserted) != 2 || st.upserted[0].ItemKey != "k" || !st.upserted[1].LastSeenAt.Equal(now) {
				t.Errorf("sync = %+v, upserted %+v", res, st.upserted)
			}
		})
	}
}

// Edge cases the tests above leave open, one behaviour each. Every case reads the
// report the way a consumer would: by period label, with nil meaning "not
// measured" and a pointer to zero meaning "measured, none".
func TestAddTrackerEdgeCases(t *testing.T) {
	utc := func(y int, m time.Month, d, h, min int) time.Time { return time.Date(y, m, d, h, min, 0, 0, time.UTC) }
	first := utc(2026, 6, 1, 9, 0)
	now := utc(2026, 9, 21, 12, 0)
	months := Range{Since: utc(2026, 6, 1, 0, 0), Until: now, Bucket: BucketMonth}

	type period struct {
		raised, closed         int
		toldN, toStartN, workN int
		told, toStart, worked  *float64
	}
	cases := []struct {
		name string
		rng  Range
		// match runs MatchTickets against open first, as SyncTickets does.
		match      bool
		open       []State
		tickets    []TrackerTicket
		want       map[string]period
		wantClosed int
	}{
		{
			// Jira reports no resolution once a ticket leaves done, so the reopened
			// ticket is raised work, not a close, and no interval ends.
			name: "reopened after resolution counts as raised, not closed",
			rng:  months,
			tickets: []TrackerTicket{{Key: "T-1", ItemKey: "a", ItemOpenedAt: ptr(utc(2026, 7, 1, 0, 0)),
				CreatedAt: utc(2026, 7, 2, 0, 0), StartedAt: ptr(utc(2026, 7, 3, 0, 0))}},
			open: []State{{OpenedAt: utc(2026, 7, 1, 0, 0), Current: Snapshot{Key: "a"}}},
			want: map[string]period{"2026-07": {raised: 1}},
		},
		{
			// A previous span's ticket: its close is counted and its own intervals
			// stand, but "told" would be negative, and the item it is matched to was
			// not open when it closed.
			name: "ticket resolved before its item opened has no told interval",
			rng:  months,
			tickets: []TrackerTicket{{Key: "T-1", ItemKey: "a", ItemOpenedAt: ptr(utc(2026, 7, 20, 0, 0)),
				CreatedAt: utc(2026, 7, 2, 0, 0), StartedAt: ptr(utc(2026, 7, 3, 0, 0)), ResolvedAt: ptr(utc(2026, 7, 10, 0, 0))}},
			open: []State{{OpenedAt: utc(2026, 7, 20, 0, 0), Current: Snapshot{Key: "a"}}},
			want: map[string]period{"2026-07": {raised: 1, closed: 1, toStartN: 1, toStart: ptr(1.0), workN: 1, worked: ptr(7.0)}},
		},
		{
			// One ticket, two open items on its image: attributed once, to the item
			// opened first, so the close is one item left open, not two.
			name:  "two items sharing a repository count the close once",
			rng:   months,
			match: true,
			open: []State{
				{OpenedAt: utc(2026, 7, 5, 0, 0), Current: Snapshot{Key: "eng|orders|app|svc", Repository: "app"}},
				{OpenedAt: utc(2026, 7, 1, 0, 0), Current: Snapshot{Key: "eng|billing|app|svc", Repository: "app"}},
			},
			tickets: []TrackerTicket{{Key: "T-1", Images: []string{"app"}, CreatedAt: utc(2026, 7, 6, 0, 0),
				ResolvedAt: ptr(utc(2026, 7, 8, 0, 0))}},
			want:       map[string]period{"2026-07": {raised: 1, closed: 1, toldN: 1, told: ptr(5.0)}},
			wantClosed: 1,
		},
		{
			// Periods are half-open: a timestamp on the boundary belongs to the period
			// it starts, for raised and closed alike.
			name: "a timestamp exactly on a period boundary falls in the later period",
			rng:  months,
			tickets: []TrackerTicket{{Key: "T-1", CreatedAt: utc(2026, 7, 1, 0, 0),
				StartedAt: ptr(utc(2026, 7, 1, 0, 0)), ResolvedAt: ptr(utc(2026, 8, 1, 0, 0))}},
			want: map[string]period{
				"2026-06": {},
				"2026-07": {raised: 1},
				"2026-08": {closed: 1, toStartN: 1, toStart: ptr(0.0), workN: 1, worked: ptr(31.0)},
			},
		},
		{
			// ISO weeks run Monday to Sunday: the last minute of Sunday and midnight on
			// Monday land in different weeks.
			name: "week buckets split at Monday midnight",
			rng:  Range{Since: utc(2026, 9, 7, 0, 0), Until: now, Bucket: BucketWeek},
			tickets: []TrackerTicket{
				{Key: "T-1", CreatedAt: utc(2026, 9, 8, 0, 0), ResolvedAt: ptr(utc(2026, 9, 13, 23, 59))},
				{Key: "T-2", CreatedAt: utc(2026, 9, 8, 0, 0), ResolvedAt: ptr(utc(2026, 9, 14, 0, 0))},
			},
			want: map[string]period{
				"2026-W37": {raised: 2, closed: 1},
				"2026-W38": {closed: 1},
				"2026-W39": {},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tickets := tc.tickets
			if tc.match {
				tickets = MatchTickets(tickets, tc.open)
			}
			rep := Aggregate(tc.rng, nil, nil, tc.open, first, now)
			rep.AddTracker(tickets, TicketIndexState{Tickets: len(tickets), FirstCreated: utc(2026, 1, 1, 0, 0), LastSynced: now}, tc.open, first, now)

			byLabel := map[string]Movement{}
			for _, m := range rep.Movement {
				byLabel[m.Period] = m
			}
			for label, want := range tc.want {
				m, ok := byLabel[label]
				if !ok {
					t.Fatalf("no period %s in %v", label, rep.Movement)
				}
				if m.TrackerTicketsRaised == nil || m.TrackerTicketsClosed == nil {
					t.Fatalf("%s: tracker counts absent, want counted", label)
				}
				if *m.TrackerTicketsRaised != want.raised || *m.TrackerTicketsClosed != want.closed {
					t.Errorf("%s raised/closed = %d/%d, want %d/%d", label, *m.TrackerTicketsRaised, *m.TrackerTicketsClosed, want.raised, want.closed)
				}
				checkMedian(t, label+" told", m.MedianDaysTold, m.MedianDaysToldN, want.told, want.toldN)
				checkMedian(t, label+" to start", m.MedianDaysToStart, m.MedianDaysToStartN, want.toStart, want.toStartN)
				checkMedian(t, label+" worked", m.MedianDaysWorked, m.MedianDaysWorkedN, want.worked, want.workN)
			}
			if rep.Open.ClosedTicketFindingOpen == nil || *rep.Open.ClosedTicketFindingOpen != tc.wantClosed {
				t.Errorf("closed ticket, finding open = %v, want %d", rep.Open.ClosedTicketFindingOpen, tc.wantClosed)
			}
		})
	}
}

func checkMedian(t *testing.T, name string, got *float64, n int, want *float64, wantN int) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("%s = %v over %d, want unmeasured", name, *got, n)
	case want != nil && (got == nil || *got != *want):
		t.Errorf("%s = %v over %d, want %v over %d", name, got, n, *want, wantN)
	case n != wantN:
		t.Errorf("%s rests on %d, want %d", name, n, wantN)
	}
}
