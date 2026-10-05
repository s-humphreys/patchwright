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
	both := model.Sources{LiveSource: "kube", LiveClusters: []string{"a", "b"}}
	for _, tc := range []struct {
		name     string
		failures []model.SourceFailure
		narrowed bool
		want     int
	}{
		{name: "every run complete", want: 1},
		{name: "a run in the window left a cluster out", failures: []model.SourceFailure{{Stage: model.StageLive, Cluster: "remote", Error: "Unauthorized"}}},
		{name: "a cluster taken out of the live source in the window", narrowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			a := &scopedAssessor{partialAssessor: partialAssessor{findings: []model.Finding{upgradable("acr.io/app:1", "orders")}}, sources: both}
			s := New(a).WithHistory(store, 30*24*time.Hour).WithLapseAfter(1).WithDecommissionAfter(20 * time.Millisecond)
			s.Refresh(context.Background())
			a.findings = []model.Finding{gone()}
			s.Refresh(context.Background())
			if k := store.kinds(); k[history.KindLapsed] != 1 {
				t.Fatalf("want a lapse, got %v", k)
			}
			a.failures = tc.failures
			if tc.narrowed {
				a.sources = model.Sources{LiveSource: "kube", LiveClusters: []string{"a"}}
			}
			s.Refresh(context.Background())
			a.failures, a.sources = nil, both
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

// scopedAssessor reports the live source's clusters, which a test moves between runs.
type scopedAssessor struct {
	partialAssessor
	sources model.Sources
}

func (s *scopedAssessor) Sources() model.Sources { return s.sources }
