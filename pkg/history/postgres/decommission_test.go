package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

func TestAssessmentPartialRoundTripsAndIsBackfilled(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for i, a := range []history.Assessment{
		{StartedAt: t0, FinishedAt: t0, Partial: true},
		{StartedAt: t0.Add(time.Hour), FinishedAt: t0.Add(time.Hour)},
	} {
		if _, err := s.Record(ctx, a, nil, nil); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	// A run recorded before the column, whose summary lists a source failure.
	if _, err := s.pool.Exec(ctx, `INSERT INTO assessments (started_at, finished_at, findings, actionable, items, risk, summary)
		VALUES ($1, $1, 0, 0, 0, '{}', '{"source_failures":[{"stage":"exploit","error":"timeout"}]}')`, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	body, err := migrations.ReadFile("migrations/010_assessment_partial.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, string(body)); err != nil {
		t.Fatalf("re-apply backfill: %v", err)
	}
	got, err := s.Assessments(ctx, t0, t0.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !got[0].Partial || got[1].Partial || !got[2].Partial {
		t.Errorf("partial = %v %v %v, want true false true", got[0].Partial, got[1].Partial, got[2].Partial)
	}
}

// The whole path against the store: an item stops running, lapses, and is credited
// as decommissioned by the first run after the window, once.
func TestDecommissionIsRecordedOnce(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	gone := sink.FindingView{
		Image: "acr.io/app:1", Repository: "acr.io/app", Owner: sink.OwnerView{Class: "eng", Team: "orders"},
		Liveness: &sink.LivenessView{Live: false}, RemediationChecked: true,
		Upgrade: &sink.UpgradeView{Name: "svc", Resolved: true},
	}
	item := snap("eng|orders|acr.io/app|svc", "acr.io/app", "orders")
	item.CVEs = []history.CVE{{ID: "CVE-1", KEV: true}}
	if _, err := s.Record(ctx, history.Assessment{StartedAt: t0, FinishedAt: t0},
		[]history.Event{{Key: item.Key, Kind: history.KindOpened, At: t0, Payload: history.Payload{Snapshot: &item}}}, nil); err != nil {
		t.Fatal(err)
	}
	after := 7 * 24 * time.Hour
	run := func(at time.Time) []history.Event {
		t.Helper()
		open, err := s.Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		events, marks := history.Diff(history.Input{Open: open, Views: []sink.FindingView{gone}, LapseAfter: 2, Now: at})
		from := at.Add(-history.DecommissionLookback(after))
		recent, err := s.Events(ctx, from, at)
		if err != nil {
			t.Fatal(err)
		}
		runs, err := s.Assessments(ctx, from, at)
		if err != nil {
			t.Fatal(err)
		}
		decom := history.Decommissions(history.DecommissionInput{
			After: after, Events: recent, Assessments: runs, Views: []sink.FindingView{gone}, Now: at,
		})
		events = append(events, decom...)
		if _, err := s.Record(ctx, history.Assessment{StartedAt: at, FinishedAt: at}, events, marks); err != nil {
			t.Fatal(err)
		}
		return decom
	}
	gonesince := t0.Add(time.Hour)
	for h := 0; h < 3; h++ {
		if d := run(gonesince.Add(time.Duration(h) * time.Hour)); len(d) != 0 {
			t.Fatalf("decommissioned at hour %d, inside the window: %+v", h, d)
		}
	}
	if d := run(gonesince.Add(after)); len(d) != 1 {
		t.Fatalf("want a decommission at the deadline, got %+v", d)
	}
	if d := run(gonesince.Add(after + time.Hour)); len(d) != 0 {
		t.Fatalf("decommissioned twice: %+v", d)
	}
	events, err := s.Events(ctx, t0, t0.Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var found []history.Event
	for _, e := range events {
		if e.Kind == history.KindDecommissioned {
			found = append(found, e)
		}
	}
	if len(found) != 1 || !found[0].At.Equal(gonesince) || found[0].Key != item.Key || found[0].Payload.Closed == nil {
		t.Errorf("decommissioned events = %+v, want one dated %v", found, gonesince)
	}
}
