package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
)

// A report waits for the one being built, and gives up when its caller does rather
// than queueing behind it for ever.
func TestHistoryReportsBuildOneAtATime(t *testing.T) {
	s := New(nil).WithHistory(newMemStore(), 30*24*time.Hour)
	now := time.Now().UTC()
	rng := history.Range{Since: now.Add(-30 * 24 * time.Hour), Until: now, Bucket: history.BucketMonth}

	s.history.reports <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.historyReport(ctx, rng, now); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v while another report holds the slot, want the caller's deadline", err)
	}
	<-s.history.reports

	if _, err := s.historyReport(context.Background(), rng, now); err != nil {
		t.Fatalf("report after the slot was released: %v", err)
	}
	if len(s.history.reports) != 0 {
		t.Error("a finished report should give the slot back")
	}
}
