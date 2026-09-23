package server

import (
	"context"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
)

func TestTrackerCountsCoverTheWholeFirstPeriod(t *testing.T) {
	store := newMemStore()
	d := func(m time.Month, day int) time.Time { return time.Date(2026, m, day, 12, 0, 0, 0, time.UTC) }
	_ = store.UpsertTickets(context.Background(), []history.TrackerTicket{
		{Key: "T-1", CreatedAt: d(6, 5), LastSeenAt: d(9, 21)},
		{Key: "T-2", CreatedAt: d(6, 28), LastSeenAt: d(9, 21)},
	})
	s := New(&stubAssessor{}).WithHistory(store, 400*24*time.Hour)
	// What ?since=90d asks for on 23 September.
	rep, err := s.historyReport(context.Background(), history.Range{Since: d(6, 25), Until: d(9, 23), Bucket: history.BucketMonth}, d(9, 23))
	if err != nil {
		t.Fatal(err)
	}
	jun := rep.Movement[0]
	t.Logf("period %s [%s, %s) raised=%v", jun.Period, jun.Start.Format(time.DateOnly), jun.End.Format(time.DateOnly), *jun.TrackerTicketsRaised)
	if *jun.TrackerTicketsRaised != 2 {
		t.Errorf("%s tracker_tickets_raised = %d, want 2: the period covers all of June but only tickets from the 25th were read", jun.Period, *jun.TrackerTicketsRaised)
	}
}
