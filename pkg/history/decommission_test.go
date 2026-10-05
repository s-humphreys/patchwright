package history

import (
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// lapsedNotRunning is item 7 lapsing through Diff the way production does: absent
// from the queue for lapseAfter runs because nothing runs its image, starting at
// since.
func lapsedNotRunning(t *testing.T, since time.Time) Event {
	t.Helper()
	v := view("acr.io/app:1", "eng", "orders", "high")
	prev := Snapshots([]sink.FindingView{v}, map[string][]string{"acr.io/app": {"PROJ-1"}})[0]
	gone := fixed(v)
	gone.Liveness = &sink.LivenessView{Live: false}
	st := openState(7, prev, since.AddDate(0, 0, -20))
	st.Missing, st.MissingSince = 2, &since
	events, _ := Diff(Input{Open: []State{st}, Views: []sink.FindingView{gone}, LapseAfter: 3, Now: since.Add(2 * time.Hour)})
	for _, e := range events {
		if e.Kind == KindLapsed {
			e.Key = prev.Key
			return e
		}
	}
	t.Fatalf("no lapse from %+v", events)
	return Event{}
}

func TestDecommissions(t *testing.T) {
	since := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	after := 7 * 24 * time.Hour
	now := since.Add(after + time.Hour)
	key := Key("eng", "orders", "acr.io/app", "nginx")
	elsewhere := func(live *sink.LivenessView) []sink.FindingView {
		v := fixed(view("acr.io/app:2", "eng", "payments", "high"))
		v.Liveness = live
		return []sink.FindingView{v}
	}
	runs := []Assessment{{FinishedAt: since.Add(time.Hour)}, {FinishedAt: since.Add(72 * time.Hour)}}

	cases := []struct {
		name        string
		lapse       func(Event) Event
		extra       []Event
		assessments []Assessment
		current     []Snapshot
		views       []sink.FindingView
		partial     bool
		now         time.Time
		want        bool
	}{
		{name: "gone for the window, every run complete", want: true},
		{name: "still reported, not running", views: elsewhere(&sink.LivenessView{Live: false}), want: true},
		{name: "lapsed on its first absent run", lapse: func(e Event) Event { e.Payload.MissingSince = nil; e.At = since; return e }, want: true},
		{name: "inside the window", now: since.Add(after - time.Hour)},
		{name: "a run in the window was partial", assessments: []Assessment{{FinishedAt: since.Add(48 * time.Hour), Partial: true}}},
		{name: "this run is partial", partial: true},
		{name: "the image runs elsewhere", views: elsewhere(&sink.LivenessView{Live: true})},
		{name: "liveness unknown elsewhere", views: elsewhere(nil)},
		{name: "came back under its key", extra: []Event{{ItemID: 9, Key: key, Kind: KindOpened, At: since.Add(48 * time.Hour),
			Payload: Payload{Snapshot: &Snapshot{Key: key, Repository: "acr.io/app"}}}}},
		{name: "moved to another owner", extra: []Event{{ItemID: 9, Key: "other", Kind: KindOpened, At: since.Add(48 * time.Hour),
			Payload: Payload{Snapshot: &Snapshot{Key: "other", Repository: "acr.io/app"}}}}},
		{name: "in the queue now under another key", current: []Snapshot{{Key: "other", Repository: "acr.io/app"}}},
		{name: "in the queue now under its key", current: []Snapshot{{Key: key, Repository: "acr.io/app"}}},
		{name: "no longer reported is not a removal", lapse: func(e Event) Event { e.Payload.Reason = "acr.io/app is no longer reported"; return e }},
		{name: "an earlier run judged it", assessments: []Assessment{{FinishedAt: since.Add(after + 10*time.Minute)}}},
		{name: "already decommissioned", extra: []Event{{ItemID: 7, Key: key, Kind: KindDecommissioned, At: since}}},
		{name: "older than the lookback", now: since.Add(DecommissionLookback(after) + time.Hour)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lapse := lapsedNotRunning(t, since)
			if c.lapse != nil {
				lapse = c.lapse(lapse)
			}
			at := now
			if !c.now.IsZero() {
				at = c.now
			}
			got := Decommissions(DecommissionInput{
				After: after, Events: append([]Event{lapse}, c.extra...), Assessments: append(append([]Assessment{}, runs...), c.assessments...),
				Current: c.current, Views: c.views, Partial: c.partial, Now: at,
			})
			if !c.want {
				if len(got) != 0 {
					t.Fatalf("want no decommission, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want one decommission, got %+v", got)
			}
			e := got[0]
			if e.Kind != KindDecommissioned || e.ItemID != 7 || e.Key != key || !e.At.Equal(since) {
				t.Errorf("event = %+v, want item 7 dated %v", e, since)
			}
			p := e.Payload
			if p.Closed == nil || len(p.Closed.CVEs) != 2 || p.Opened == nil || p.OpenedAt == nil || !p.Ticketed ||
				len(p.Tickets) != 1 || p.MissingSince == nil || !p.MissingSince.Equal(since) {
				t.Errorf("payload = %+v", p)
			}
			if p.DaysOpen == nil || *p.DaysOpen != 20 {
				t.Errorf("days open = %v, want 20 to the disappearance", p.DaysOpen)
			}
			if !strings.Contains(p.Evidence, "7 days") || !strings.Contains(p.Evidence, "acr.io/app") {
				t.Errorf("evidence = %q", p.Evidence)
			}
		})
	}
}

func TestDecommissionedRepositories(t *testing.T) {
	got := DecommissionedRepositories([]Event{
		{Kind: KindDecommissioned, Payload: Payload{Closed: &Snapshot{Repository: "acr.io/a"}}},
		{Kind: KindLapsed, Payload: Payload{Closed: &Snapshot{Repository: "acr.io/b"}}},
		{Kind: KindDecommissioned},
	})
	if len(got) != 1 || !got["acr.io/a"] {
		t.Errorf("got %v, want only acr.io/a", got)
	}
}

func TestAggregateCreditsDecommissionsToThePeriodOfDisappearance(t *testing.T) {
	r := Range{Since: day(2026, 8, 1), Until: day(2026, 10, 5), Bucket: BucketMonth}
	cve := func(id string, kev bool, epss float64) CVE { return CVE{ID: id, KEV: kev, EPSS: epss} }
	before := &Snapshot{Key: "k1", CVEs: []CVE{cve("CVE-A", true, 0.9), cve("CVE-B", false, 0.7), cve("CVE-C", false, 0)}}
	events := []Event{
		// August: item 1 clears CVE-A while open, then its workloads go on 30 August.
		{ItemID: 1, Key: "k1", Kind: KindOpened, At: day(2026, 8, 2), Payload: Payload{Snapshot: before}},
		{ItemID: 1, Key: "k1", Kind: KindChanged, At: day(2026, 8, 10), Payload: Payload{
			CVEsRemoved: []string{"CVE-A"}, CVEsCleared: []CVE{cve("CVE-A", true, 0.9)}, Ticketed: true}},
		{ItemID: 1, Key: "k1", Kind: KindDecommissioned, At: day(2026, 8, 30), Payload: Payload{Ticketed: true,
			Closed: &Snapshot{Key: "k1", CVEs: []CVE{cve("CVE-A", true, 0.9), cve("CVE-B", false, 0.7), cve("CVE-C", false, 0)}}}},
		{ItemID: 1, Key: "k1", Kind: KindLapsed, At: day(2026, 8, 30).Add(2 * time.Hour), Payload: Payload{Reason: "acr.io/a is no longer running"}},
		// September: an unticketed item, sharing CVE-C, decommissioned; one fixed.
		{ItemID: 2, Key: "k2", Kind: KindDecommissioned, At: day(2026, 9, 4), Payload: Payload{
			Closed: &Snapshot{Key: "k2", CVEs: []CVE{cve("CVE-C", false, 0), cve("CVE-D", true, 0.1)}}}},
		{ItemID: 3, Key: "k3", Kind: KindResolved, At: day(2026, 9, 6), Payload: Payload{
			Closed: &Snapshot{Key: "k3", CVEs: []CVE{cve("CVE-D", true, 0.1)}}}},
	}
	rep := Aggregate(r, nil, events, nil, time.Time{}, day(2026, 10, 5))
	aug, sep := rep.Movement[0], rep.Movement[1]

	wantAug := Decommissioned{Items: 1, ItemsTicketed: 1, CVETally: CVETally{CVEs: 2, EPSSHigh: 1}, Ticketed: CVETally{CVEs: 2, EPSSHigh: 1}}
	if aug.Decommissioned != wantAug {
		t.Errorf("August = %+v, want %+v (CVE-A was already cleared)", aug.Decommissioned, wantAug)
	}
	if aug.Lapsed != 1 || aug.Resolved != 0 || aug.Remediated != 1 || aug.CVEsCleared != 1 {
		t.Errorf("August lapsed/resolved/remediated/cleared = %d/%d/%d/%d, want 1/0/1/1 (lapsed keeps its meaning)",
			aug.Lapsed, aug.Resolved, aug.Remediated, aug.CVEsCleared)
	}
	wantSep := Decommissioned{Items: 1, CVETally: CVETally{CVEs: 2, KEV: 1}, Unticketed: CVETally{CVEs: 2, KEV: 1}}
	if sep.Decommissioned != wantSep || sep.Remediated != 2 {
		t.Errorf("September = %+v remediated %d, want %+v and 2", sep.Decommissioned, sep.Remediated, wantSep)
	}

	tot := rep.Totals
	wantTot := Decommissioned{Items: 2, ItemsTicketed: 1, CVETally: CVETally{CVEs: 3, KEV: 1, EPSSHigh: 1},
		Ticketed: CVETally{CVEs: 2, EPSSHigh: 1}, Unticketed: CVETally{CVEs: 1, KEV: 1}}
	if tot.Decommissioned != wantTot {
		t.Errorf("range decommissioned = %+v, want %+v (CVE-C once, ticketed)", tot.Decommissioned, wantTot)
	}
	// Cleared: CVE-A (partly) and CVE-D (resolved). Decommissioned: B, C, D. Union A-D.
	if tot.RemediatedItems != 3 || tot.RemediatedCVEs != (CVETally{CVEs: 4, KEV: 2, EPSSHigh: 2}) {
		t.Errorf("remediated = %d items, %+v", tot.RemediatedItems, tot.RemediatedCVEs)
	}
	if tot.CVEsCleared != 2 || tot.CVEsResolved != 1 {
		t.Errorf("cleared/resolved = %d/%d, want 2/1: decommissions must not move them", tot.CVEsCleared, tot.CVEsResolved)
	}
}
