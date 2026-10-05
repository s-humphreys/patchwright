package history

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// eventStore answers Events from a list, as the real store does: [since, until),
// oldest first. It records each window asked for.
type eventStore struct {
	Store
	events  []Event
	windows [][2]time.Time
	failAt  int
}

func (s *eventStore) Events(_ context.Context, since, until time.Time) ([]Event, error) {
	s.windows = append(s.windows, [2]time.Time{since, until})
	if s.failAt > 0 && len(s.windows) == s.failAt {
		return nil, errors.New("timeout")
	}
	var out []Event
	for _, e := range s.events {
		if !e.At.Before(since) && e.At.Before(until) {
			out = append(out, e)
		}
	}
	return out, nil
}

// The range is read a day at a time, every event once and in order, including one
// that falls exactly on the boundary between two reads.
func TestEachEventReadsADayAtATime(t *testing.T) {
	since := time.Date(2026, 9, 21, 16, 9, 0, 0, time.UTC)
	until := since.Add(3*24*time.Hour + 5*time.Hour)
	st := &eventStore{}
	for i, at := range []time.Time{since, since.Add(time.Hour), since.Add(24 * time.Hour), since.Add(50 * time.Hour), until.Add(-time.Second), until} {
		st.events = append(st.events, Event{ID: int64(i + 1), At: at})
	}
	var got []int64
	if err := EachEvent(context.Background(), st, since, until, func(e Event) { got = append(got, e.ID) }); err != nil {
		t.Fatal(err)
	}
	if want := []int64{1, 2, 3, 4, 5}; !reflect.DeepEqual(got, want) {
		t.Errorf("events = %v, want %v", got, want)
	}
	if len(st.windows) != 4 {
		t.Fatalf("reads = %v, want four", st.windows)
	}
	for i, w := range st.windows {
		if w[1].Sub(w[0]) > 24*time.Hour {
			t.Errorf("read %d spans %v", i, w[1].Sub(w[0]))
		}
		if i > 0 && !w[0].Equal(st.windows[i-1][1]) {
			t.Errorf("read %d starts %v, previous ended %v", i, w[0], st.windows[i-1][1])
		}
	}
	if !st.windows[0][0].Equal(since) || !st.windows[3][1].Equal(until) {
		t.Errorf("reads cover %v to %v, want %v to %v", st.windows[0][0], st.windows[3][1], since, until)
	}

	failing := &eventStore{events: st.events, failAt: 2}
	if err := EachEvent(context.Background(), failing, since, until, func(Event) {}); err == nil || len(failing.windows) != 2 {
		t.Errorf("err = %v after %d reads, want the second read's error", err, len(failing.windows))
	}
}

// Folding events one at a time, through the exclusion, gives the report Aggregate
// gives over ExcludeTickets' output.
func TestAggregationMatchesAggregate(t *testing.T) {
	r := Range{Since: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), Until: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Bucket: BucketWeek}
	opened := &Snapshot{Key: "k", Repository: "acr.io/app", Team: "orders", Rule: "urgent", Signals: []string{"kev"},
		CVEs: []CVE{{ID: "CVE-1", KEV: true}, {ID: "CVE-2", EPSS: 0.7}}, Tickets: []string{"EX-1"}}
	changed := *opened
	changed.CVEs = changed.CVEs[:1]
	changed.Signals = nil
	at := func(d int) time.Time { return r.Since.AddDate(0, 0, d) }
	events := []Event{
		{ItemID: 1, Key: "k", Kind: KindOpened, At: at(1), Payload: Payload{Snapshot: opened}},
		{ItemID: 1, Key: "k", Kind: KindTicketRaised, At: at(2), Payload: Payload{Ticket: "EX-1"}},
		{ItemID: 1, Key: "k", Kind: KindTicketRaised, At: at(2), Payload: Payload{Ticket: "IN-1"}},
		{ItemID: 1, Key: "k", Kind: KindChanged, At: at(9), Payload: Payload{Snapshot: &changed, SignalsRemoved: []string{"kev"},
			CVEsRemoved: []string{"CVE-2"}, CVEsCleared: []CVE{{ID: "CVE-2", EPSS: 0.7}}, Ticketed: true, Tickets: []string{"EX-1"}}},
		{ItemID: 1, Key: "k", Kind: KindResolved, At: at(20), Payload: Payload{Opened: opened, Closed: &changed, Ticketed: true}},
		{ItemID: 1, Key: "k", Kind: KindTicketClosed, At: at(21), Payload: Payload{Ticket: "EX-1"}},
	}
	tickets := []TrackerTicket{{Key: "EX-1", Project: "EX", CreatedAt: at(2)}, {Key: "IN-1", Project: "IN", CreatedAt: at(2)}}
	scopes := []TicketScope{{Route: "excluded", Project: "EX"}}
	first, now := at(0), r.Until

	keptEvents, keptTickets, wantExcluded := ExcludeTickets(r, append([]Event(nil), events...), tickets, scopes)
	want := Aggregate(r, nil, keptEvents, nil, first, now)

	x, gotTickets := NewTicketExclusion(r, tickets, scopes)
	agg := NewAggregation(r, nil, nil, first, now)
	for _, e := range events {
		if x.Keep(&e) {
			agg.Add(e)
		}
	}
	if got := agg.Report(); !reflect.DeepEqual(got, want) {
		t.Errorf("folded report %+v, want %+v", got, want)
	}
	if got := x.Excluded(); !reflect.DeepEqual(got, wantExcluded) || !reflect.DeepEqual(gotTickets, keptTickets) {
		t.Errorf("excluded %+v and tickets %+v, want %+v and %+v", got, gotTickets, wantExcluded, keptTickets)
	}
	if wantExcluded.TicketsRaised != 1 || wantExcluded.TicketsClosed != 1 {
		t.Errorf("excluded = %+v, want one raised and one closed", wantExcluded)
	}

	var none *TicketExclusion
	e := events[1]
	if !none.Keep(&e) || none.Excluded() != nil {
		t.Error("a nil exclusion keeps everything and reports nothing")
	}
}
