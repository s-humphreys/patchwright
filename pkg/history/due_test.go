package history

import (
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

func TestDaysToDue(t *testing.T) {
	due := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		at   time.Time
		want int
	}{
		{name: "a week early", at: time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC), want: 7},
		{name: "late on the due day is on time", at: time.Date(2026, 7, 17, 23, 59, 0, 0, time.UTC), want: 0},
		{name: "the day after", at: time.Date(2026, 7, 18, 0, 1, 0, 0, time.UTC), want: -1},
		// 01:00 on the 18th in UTC+2 is still the 17th in UTC.
		{name: "measured in UTC", at: time.Date(2026, 7, 18, 1, 0, 0, 0, time.FixedZone("UTC+2", 2*60*60)), want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DaysToDue(due, tc.at); got != tc.want {
				t.Errorf("DaysToDue(%v, %v) = %d, want %d", due, tc.at, got, tc.want)
			}
		})
	}
}

func TestTicketEventsCarryTheDueDateOfACreate(t *testing.T) {
	a := Snapshots([]sink.FindingView{view("acr.io/app:1", "eng", "orders", "high")}, nil)[0]
	b := Snapshots([]sink.FindingView{view("acr.io/other:1", "eng", "orders", "high")}, nil)[0]
	due := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	events := TicketEvents([]State{openState(1, a, t0), openState(2, b, t0)}, []TicketWrite{
		{Key: "DVOP-1", Action: "create", Images: []string{"acr.io/app:1"}, DueDate: &due},
		{Key: "DVOP-2", Action: "extend", Images: []string{"acr.io/other:1"}},
	}, t0)
	if len(events) != 2 {
		t.Fatalf("want two ticket_raised events, got %+v", events)
	}
	for _, e := range events {
		switch e.Payload.Ticket {
		case "DVOP-1":
			if e.Payload.DueDate == nil || !e.Payload.DueDate.Equal(due) {
				t.Errorf("create due_date = %v, want %v", e.Payload.DueDate, due)
			}
		case "DVOP-2":
			if e.Payload.DueDate != nil {
				t.Errorf("extend due_date = %v, want absent: an extend never moves the deadline", e.Payload.DueDate)
			}
		}
	}
}

func TestTicketClosedIsMeasuredAgainstTheDueDate(t *testing.T) {
	v := view("acr.io/app:1", "eng", "orders", "high")
	prev := Snapshots([]sink.FindingView{v}, map[string][]string{"acr.io/app": {"DVOP-1"}})[0]
	// Still in the queue, but the ticket has gone from the open index.
	cur := Snapshots([]sink.FindingView{v}, nil)
	due := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name        string
		ticketDue   map[string]time.Time
		at          time.Time
		wantDays    *int
		wantOverdue *bool
	}{
		{name: "early", ticketDue: map[string]time.Time{"DVOP-1": due}, at: due.AddDate(0, 0, -3).Add(9 * time.Hour),
			wantDays: ptr(3), wantOverdue: ptr(false)},
		{name: "on the day", ticketDue: map[string]time.Time{"DVOP-1": due}, at: due.Add(18 * time.Hour),
			wantDays: ptr(0), wantOverdue: ptr(false)},
		{name: "late", ticketDue: map[string]time.Time{"DVOP-1": due}, at: due.AddDate(0, 0, 2).Add(time.Hour),
			wantDays: ptr(-2), wantOverdue: ptr(true)},
		// A due date for another ticket says nothing about this one.
		{name: "no due date recorded", ticketDue: map[string]time.Time{"DVOP-7": due}, at: due},
		{name: "no due dates at all", at: due},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := openState(3, prev, t0)
			st.TicketDue = tc.ticketDue
			events, _ := Diff(Input{Open: []State{st}, Current: cur, Views: []sink.FindingView{v}, Now: tc.at})
			if len(events) != 1 || events[0].Kind != KindTicketClosed || events[0].Payload.Ticket != "DVOP-1" {
				t.Fatalf("want one ticket_closed for DVOP-1, got %+v", events)
			}
			p := events[0].Payload
			if tc.wantDays == nil {
				if p.DueDate != nil || p.DaysToDue != nil || p.Overdue != nil {
					t.Errorf("no due date recorded: want the fields absent, got due=%v days=%v overdue=%v", p.DueDate, p.DaysToDue, p.Overdue)
				}
				return
			}
			if p.DueDate == nil || !p.DueDate.Equal(due) {
				t.Errorf("due_date = %v, want %v", p.DueDate, due)
			}
			if p.DaysToDue == nil || *p.DaysToDue != *tc.wantDays {
				t.Errorf("days_to_due = %v, want %d", p.DaysToDue, *tc.wantDays)
			}
			if p.Overdue == nil || *p.Overdue != *tc.wantOverdue {
				t.Errorf("overdue = %v, want %v", p.Overdue, *tc.wantOverdue)
			}
		})
	}
}

func TestAggregateMeasuresClosesAgainstTheDueDate(t *testing.T) {
	r := Range{Since: day(2026, 7, 1), Until: day(2026, 9, 21), Bucket: BucketMonth}
	events := []Event{
		// July: one early, one on the day, one late, and one with no due date.
		{Key: "k1", Kind: KindTicketClosed, At: day(2026, 7, 10), Payload: Payload{Ticket: "DVOP-1", DaysToDue: ptr(4), Overdue: ptr(false)}},
		{Key: "k2", Kind: KindTicketClosed, At: day(2026, 7, 11), Payload: Payload{Ticket: "DVOP-2", DaysToDue: ptr(0), Overdue: ptr(false)}},
		{Key: "k3", Kind: KindTicketClosed, At: day(2026, 7, 12), Payload: Payload{Ticket: "DVOP-3", DaysToDue: ptr(-7), Overdue: ptr(true)}},
		{Key: "k4", Kind: KindTicketClosed, At: day(2026, 7, 13), Payload: Payload{Ticket: "DVOP-4"}},
		// August: only closes without a due date, so nothing to measure.
		{Key: "k5", Kind: KindTicketClosed, At: day(2026, 8, 13), Payload: Payload{Ticket: "DVOP-5", EvidenceAtClose: ptr(true)}},
	}
	now := day(2026, 9, 21)
	open := []State{
		// DVOP-10 is past due and covers two items: one overdue ticket, not two.
		{OpenedAt: day(2026, 9, 1), Current: Snapshot{Key: "a", Tickets: []string{"DVOP-10"}},
			TicketDue: map[string]time.Time{"DVOP-10": day(2026, 9, 1)}},
		{OpenedAt: day(2026, 9, 1), Current: Snapshot{Key: "b", Tickets: []string{"DVOP-10", "DVOP-11"}},
			TicketDue: map[string]time.Time{"DVOP-10": day(2026, 9, 1), "DVOP-11": day(2026, 9, 30)}},
		// DVOP-12 is past due but no longer covers the item, so it is not open work.
		{OpenedAt: day(2026, 9, 1), Current: Snapshot{Key: "c"},
			TicketDue: map[string]time.Time{"DVOP-12": day(2026, 9, 1)}},
		// Due today: not overdue yet.
		{OpenedAt: day(2026, 9, 1), Current: Snapshot{Key: "d", Tickets: []string{"DVOP-13"}},
			TicketDue: map[string]time.Time{"DVOP-13": now}},
	}

	rep := Aggregate(r, nil, events, open, time.Time{}, now)

	jul, aug := rep.Movement[0], rep.Movement[1]
	if jul.TicketsClosed != 4 || jul.TicketsClosedOnTime != 2 || jul.TicketsClosedOverdue != 1 {
		t.Errorf("July closed/on time/overdue = %d/%d/%d, want 4/2/1", jul.TicketsClosed, jul.TicketsClosedOnTime, jul.TicketsClosedOverdue)
	}
	if jul.MeanDaysToDueAtClose == nil || *jul.MeanDaysToDueAtClose != -1 {
		t.Errorf("July mean days to due = %v, want -1 over the three with a due date", jul.MeanDaysToDueAtClose)
	}
	if aug.TicketsClosed != 1 || aug.TicketsClosedOnTime != 0 || aug.TicketsClosedOverdue != 0 || aug.MeanDaysToDueAtClose != nil {
		t.Errorf("August has no due dates and must be unaffected: %+v", aug)
	}
	if rep.Open.TicketsOverdueOpen != 1 {
		t.Errorf("open overdue tickets = %d, want 1", rep.Open.TicketsOverdueOpen)
	}
}
