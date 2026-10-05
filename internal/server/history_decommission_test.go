package server

import (
	"context"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// An item whose workloads go is lapsed as not running, then credited as
// decommissioned by the first run after the window, unless a run in between could
// not read every source. The repositories credited are what ticket reconciliation
// is handed.
func TestHistoryCreditsDecommissions(t *testing.T) {
	gone := func() model.Finding {
		f := upgradable("acr.io/app:1", "orders")
		f.Actionable, f.Live = false, false
		return f
	}
	for _, tc := range []struct {
		name     string
		failures []model.SourceFailure
		want     int
	}{
		{name: "every run complete", want: 1},
		{name: "a run in the window left a cluster out", failures: []model.SourceFailure{{Stage: model.StageLive, Cluster: "remote", Error: "Unauthorized"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			a := &partialAssessor{findings: []model.Finding{upgradable("acr.io/app:1", "orders")}}
			s := New(a).WithHistory(store, 30*24*time.Hour).WithLapseAfter(1).WithDecommissionAfter(20 * time.Millisecond)
			s.Refresh(context.Background())
			a.findings = []model.Finding{gone()}
			s.Refresh(context.Background())
			if k := store.kinds(); k[history.KindLapsed] != 1 {
				t.Fatalf("want a lapse, got %v", k)
			}
			a.failures = tc.failures
			s.Refresh(context.Background())
			a.failures = nil
			time.Sleep(30 * time.Millisecond)
			s.Refresh(context.Background())
			s.Refresh(context.Background())

			if got := store.kinds()[history.KindDecommissioned]; got != tc.want {
				t.Fatalf("decommissioned = %d, want %d (%v)", got, tc.want, store.kinds())
			}
			if got := s.decommissionedRepos()["app"]; got != (tc.want == 1) {
				t.Errorf("decommissioned repositories = %v", s.decommissionedRepos())
			}
		})
	}
}
