package cli

import (
	"context"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/pipeline"
)

type oneImageProvider struct{}

func (oneImageProvider) Name() string { return "stub" }

func (oneImageProvider) Fetch(context.Context) ([]model.Occurrence, error) {
	return []model.Occurrence{{Image: model.ParseImageRef("acr.io/app:1")}}, nil
}

// fleetSource leaves out the clusters it is told to on its next read.
type fleetSource struct {
	drop    []string
	pending []model.SourceFailure
}

func (*fleetSource) Name() string { return "fleet" }

func (f *fleetSource) RunningImagesPartial(context.Context) (map[string]int, bool, error) {
	for _, c := range f.drop {
		f.pending = append(f.pending, model.SourceFailure{Stage: model.StageLive, Cluster: c, Error: "Unauthorized"})
	}
	return map[string]int{"acr.io/app:1": 1}, len(f.drop) > 0, nil
}

func (f *fleetSource) RunningImages(ctx context.Context) (map[string]int, error) {
	running, _, err := f.RunningImagesPartial(ctx)
	return running, err
}

func (f *fleetSource) TakeClusterFailures() []model.SourceFailure {
	out := f.pending
	f.pending = nil
	return out
}

func TestTheClustersLeftOutAreReportedWithTheRunTheyBelongTo(t *testing.T) {
	pl, err := pipeline.New(&config.Config{
		Owners: []config.OwnerRule{{Name: "all", Match: "true", Class: "engineering", Team: "a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	src := &fleetSource{
		drop: []string{"remote"},
		// Left over from a run that failed, which was reported as failed then.
		pending: []model.SourceFailure{{Stage: model.StageLive, Cluster: "stale"}},
	}
	a := &assessor{provider: oneImageProvider{}, pipeline: pl, liveEnrichers: []enrich.Enricher{enrich.NewLiveness(src)}, clusters: src}

	if _, err := a.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := a.Failures()
	if len(got) != 1 || got[0].Cluster != "remote" || got[0].Stage != model.StageLive {
		t.Fatalf("failures = %+v, want only this run's cluster", got)
	}

	src.drop = nil
	if _, err := a.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := a.Failures(); len(got) != 0 {
		t.Errorf("a cluster read in full this run is not a gap: %+v", got)
	}
}
