package history

import (
	"reflect"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// scanned is a deployment of acr.io/app the provider assessed and liveness found
// running, carrying two KEVs, one EPSS-high CVE and one that stays.
func scanned(tag, digest string) sink.FindingView {
	v := view("acr.io/app:"+tag, "eng", "orders", "urgent")
	v.Digest = digest
	v.ProviderAssessed = true
	v.Vulns = []sink.VulnView{
		{ID: "CVE-KEV-1", Severity: "critical", KEV: true, EPSS: 0.9},
		{ID: "CVE-KEV-2", Severity: "high", KEV: true, EPSS: 0.2},
		{ID: "CVE-EPSS", Severity: "high", EPSS: 0.6},
		{ID: "CVE-STAYS", Severity: "medium"},
	}
	return v
}

// only keeps the named CVEs on a deployment.
func only(v sink.FindingView, ids ...string) sink.FindingView {
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = true
	}
	var out []sink.VulnView
	for _, c := range v.Vulns {
		if keep[c.ID] {
			out = append(out, c)
		}
	}
	v.Vulns = out
	return v
}

func itemOf(t *testing.T, views []sink.FindingView, tickets ...string) Snapshot {
	t.Helper()
	got := Snapshots(views, map[string][]string{"acr.io/app": tickets})
	if len(got) != 1 {
		t.Fatalf("want one item, got %+v", got)
	}
	return got[0]
}

func TestSnapshotsRecordScanState(t *testing.T) {
	a, b := scanned("1", "sha256:aaa"), scanned("2", "")
	got := itemOf(t, []sink.FindingView{a, b})
	want := &Scan{Source: "provider", Live: true, Builds: []string{"acr.io/app:2", "sha256:aaa"}}
	if !reflect.DeepEqual(got.Scan, want) {
		t.Errorf("scan = %+v, want %+v (digest when known, reference otherwise)", got.Scan, want)
	}

	fallback := scanned("2", "sha256:bbb")
	fallback.ProviderAssessed, fallback.FallbackScanned, fallback.FallbackSource = false, true, "trivy"
	if s := itemOf(t, []sink.FindingView{a, fallback}).Scan; s.Source != "" {
		t.Errorf("images scanned by different feeds cannot vouch for an absence: %+v", s)
	}
	if s := itemOf(t, []sink.FindingView{fallback}).Scan; s.Source != "fallback:trivy" {
		t.Errorf("fallback source = %q", s.Source)
	}
	failed := scanned("1", "sha256:aaa")
	failed.Scanned, failed.ScanError = false, "unauthorized"
	if s := itemOf(t, []sink.FindingView{failed}).Scan; s.Source != "" {
		t.Errorf("a failed scan is no source: %+v", s)
	}
	withSource := scanned("1", "sha256:aaa")
	withSource.Scanned = true
	if s := itemOf(t, []sink.FindingView{withSource}).Scan; s.Source != "provider+scan" {
		t.Errorf("a vuln source alongside the provider is a different source: %q", s.Source)
	}
	unreconciled := scanned("1", "sha256:aaa")
	unreconciled.Liveness = nil
	if s := itemOf(t, []sink.FindingView{a, unreconciled}).Scan; s.Live {
		t.Errorf("one unreconciled image makes the item not live: %+v", s)
	}
}

func TestDiffCreditsOnlyRemediatedCVEs(t *testing.T) {
	v1 := scanned("1", "sha256:aaa")
	v2 := scanned("2", "sha256:bbb")
	cases := []struct {
		name    string
		prev    []sink.FindingView
		now     []sink.FindingView
		tickets []string // covering the item at the previous assessment
		missing int
		partial bool
		strip   bool // drop the previous snapshot's scan state, as a pre-release row
		cleared []string
		reason  string
	}{
		{
			name: "image replaced, KEVs gone, item still open: credited",
			prev: []sink.FindingView{v1}, now: []sink.FindingView{only(v2, "CVE-STAYS")},
			cleared: []string{"CVE-EPSS", "CVE-KEV-1", "CVE-KEV-2"},
		},
		{
			name: "same tag rebuilt to a new digest: credited",
			prev: []sink.FindingView{v1}, now: []sink.FindingView{only(scanned("1", "sha256:ccc"), "CVE-STAYS", "CVE-EPSS")},
			cleared: []string{"CVE-KEV-1", "CVE-KEV-2"},
		},
		{
			name: "image unchanged, CVE gone: the scanner's answer moved, not credited",
			prev: []sink.FindingView{v1}, now: []sink.FindingView{only(v1, "CVE-STAYS", "CVE-EPSS")},
			reason: "the running image did not change",
		},
		{
			name: "provider did not assess the new image: coverage gap, not credited",
			prev: []sink.FindingView{v1}, now: []sink.FindingView{func() sink.FindingView {
				v := only(v2, "CVE-STAYS")
				v.ProviderAssessed = false
				return v
			}()},
			reason: "not every image was fully scanned",
		},
		{
			name: "the provider before, the fallback now: a different feed, not credited",
			prev: []sink.FindingView{v1}, now: []sink.FindingView{func() sink.FindingView {
				v := only(v2, "CVE-STAYS")
				v.ProviderAssessed, v.FallbackScanned, v.FallbackSource = false, true, "trivy"
				return v
			}()},
			reason: "scanned by provider, then by fallback:trivy",
		},
		{
			name: "a source failed this run: partial, not credited",
			prev: []sink.FindingView{v1}, now: []sink.FindingView{only(v2, "CVE-STAYS")}, partial: true,
			reason: "could not read every source",
		},
		{
			name: "absent from the previous assessment: not credited",
			prev: []sink.FindingView{v1}, now: []sink.FindingView{only(v2, "CVE-STAYS")}, missing: 1,
			reason: "absent from the previous assessment",
		},
		{
			name: "previous snapshot recorded before scan state existed: not credited",
			prev: []sink.FindingView{v1}, now: []sink.FindingView{only(v2, "CVE-STAYS")}, strip: true,
			reason: "recorded no scan state",
		},
		{
			name: "liveness not reconciled now: not credited",
			prev: []sink.FindingView{v1}, now: []sink.FindingView{func() sink.FindingView {
				v := only(v2, "CVE-STAYS")
				v.Liveness = nil
				return v
			}()},
			reason: "liveness was not reconciled",
		},
		{
			name: "a deployment went away, and with it its CVEs: not credited",
			prev: []sink.FindingView{only(v1, "CVE-STAYS"), func() sink.FindingView {
				v := scanned("0", "sha256:000")
				v.Dimensions = map[string][]string{"account": {"Production UK"}, "namespace": {"payments"}}
				return v
			}()},
			now:    []sink.FindingView{only(v2, "CVE-STAYS")},
			reason: "no longer running in payments",
		},
		{
			name: "ticketed at the previous assessment: attributed to the ticket",
			prev: []sink.FindingView{v1}, now: []sink.FindingView{only(v2, "CVE-STAYS", "CVE-EPSS")}, tickets: []string{"PROJ-7"},
			cleared: []string{"CVE-KEV-1", "CVE-KEV-2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := itemOf(t, tc.prev, tc.tickets...)
			if tc.strip {
				prev.Scan = nil
			}
			// The ticket closed in the same run the upgrade landed, as often happens.
			now := itemOf(t, tc.now)
			st := State{ID: 7, OpenedAt: t0, Opened: prev, Current: prev, Missing: tc.missing}
			events, _ := Diff(Input{Open: []State{st}, Current: []Snapshot{now}, Partial: tc.partial, Now: t0.Add(1)})
			var ev *Event
			for i := range events {
				if events[i].Kind == KindChanged {
					ev = &events[i]
				}
			}
			if ev == nil {
				t.Fatalf("CVEs left the item, so a changed event is due: %+v", events)
			}
			var ids []string
			for _, c := range ev.Payload.CVEsCleared {
				ids = append(ids, c.ID)
			}
			if !reflect.DeepEqual(ids, tc.cleared) {
				t.Errorf("cleared = %v, want %v (reason %q)", ids, tc.cleared, ev.Payload.Reason)
			}
			if tc.reason != "" && !strings.Contains(ev.Payload.Reason, tc.reason) {
				t.Errorf("reason = %q, want it to say %q", ev.Payload.Reason, tc.reason)
			}
			if len(tc.cleared) == 0 {
				if ev.Payload.Evidence != "" || ev.Payload.Ticketed || ev.Payload.Tickets != nil {
					t.Errorf("nothing credited, so no evidence or attribution: %+v", ev.Payload)
				}
				return
			}
			if ev.Payload.Reason != "" || ev.Payload.Evidence == "" {
				t.Errorf("credited CVEs carry evidence and no reason: %+v", ev.Payload)
			}
			if !reflect.DeepEqual(ev.Payload.Tickets, tc.tickets) || ev.Payload.Ticketed != (len(tc.tickets) > 0) {
				t.Errorf("attribution = %v ticketed %v, want %v", ev.Payload.Tickets, ev.Payload.Ticketed, tc.tickets)
			}
			for _, c := range ev.Payload.CVEsCleared {
				if c.ID == "CVE-KEV-1" && (!c.KEV || c.EPSS != 0.9) {
					t.Errorf("a cleared CVE keeps the replaced image's readings: %+v", c)
				}
			}
		})
	}
}

// Neither a CVE leaving KEV nor its EPSS decaying is the CVE leaving the item, so
// neither is ever credited, even when the image moved in the same run.
func TestFeedMovementIsNotAClearance(t *testing.T) {
	prev := itemOf(t, []sink.FindingView{scanned("1", "sha256:aaa")})
	now := scanned("2", "sha256:bbb")
	now.Vulns[0].KEV = false // dropped off the catalogue
	now.Vulns[2].EPSS = 0.1  // decayed below the threshold
	now.Vulns[1].KEV, now.TopEPSS = false, 0
	cur := itemOf(t, []sink.FindingView{now})
	st := State{ID: 1, OpenedAt: t0, Opened: prev, Current: prev}
	events, _ := Diff(Input{Open: []State{st}, Current: []Snapshot{cur}, Now: t0.Add(1)})
	for _, e := range events {
		if len(e.Payload.CVEsCleared) > 0 || len(e.Payload.CVEsRemoved) > 0 {
			t.Errorf("feed movement credited as a clearance: %+v", e.Payload)
		}
	}
	if cleared, _, _ := Clearance(prev, cur, 0, false); cleared != nil {
		t.Errorf("Clearance = %+v", cleared)
	}
}

// The comparison is between consecutive assessments: an image that moved in an
// earlier run without a changed event is refreshed on the stored snapshot, so a CVE
// vanishing later from that same image is not credited to the earlier move.
func TestDiffRefreshesTheSnapshotWhenTheImageMovesQuietly(t *testing.T) {
	v1, v2 := scanned("1", "sha256:aaa"), scanned("2", "sha256:bbb")
	prev := itemOf(t, []sink.FindingView{v1})
	st := State{ID: 3, OpenedAt: t0, Opened: prev, Current: prev}

	moved := itemOf(t, []sink.FindingView{v2})
	events, marks := Diff(Input{Open: []State{st}, Current: []Snapshot{moved}, Now: t0.Add(1)})
	if len(events) != 0 {
		t.Fatalf("the same CVEs on a new image is not movement: %+v", events)
	}
	if len(marks) != 1 || marks[0].Snapshot == nil || !reflect.DeepEqual(marks[0].Snapshot.Scan, moved.Scan) {
		t.Fatalf("the stored snapshot should be refreshed: %+v", marks)
	}
	st.Current = *marks[0].Snapshot

	_, marks = Diff(Input{Open: []State{st}, Current: []Snapshot{moved}, Now: t0.Add(2)})
	if len(marks) != 0 {
		t.Errorf("nothing moved, nothing to write: %+v", marks)
	}

	noise := itemOf(t, []sink.FindingView{only(v2, "CVE-STAYS")})
	events, _ = Diff(Input{Open: []State{st}, Current: []Snapshot{noise}, Now: t0.Add(3)})
	if len(events) != 1 || len(events[0].Payload.CVEsCleared) != 0 || !strings.Contains(events[0].Payload.Reason, "did not change") {
		t.Errorf("a CVE vanishing from an unchanged image is not credited: %+v", events)
	}
}

func cve(id string, kev bool, epss float64) CVE { return CVE{ID: id, KEV: kev, EPSS: epss} }

func TestAggregateCountsClearedCVEsOnce(t *testing.T) {
	r := Range{Since: day(2026, 7, 1), Until: day(2026, 9, 21), Bucket: BucketMonth}
	kev1, kev2, epss, plain := cve("CVE-KEV-1", true, 0.9), cve("CVE-KEV-2", true, 0.1), cve("CVE-EPSS", false, 0.6), cve("CVE-PLAIN", false, 0)
	closed := Snapshot{Key: "a", CVEs: []CVE{plain, kev1}}
	events := []Event{
		// July: item a, ticketed, clears both KEVs while staying open. The same event
		// replayed counts nothing more.
		{ItemID: 1, Key: "a", Kind: KindChanged, At: day(2026, 7, 10), Payload: Payload{CVEsRemoved: []string{"CVE-KEV-1", "CVE-KEV-2"}, CVEsCleared: []CVE{kev1, kev2}, Ticketed: true, Tickets: []string{"PROJ-1"}}},
		{ItemID: 1, Key: "a", Kind: KindChanged, At: day(2026, 7, 11), Payload: Payload{CVEsCleared: []CVE{kev1}, Ticketed: true}},
		// July: item b, unticketed, clears KEV-1 too and an EPSS-high CVE. KEV-1 is
		// ticketed for the period because item a's clearing was.
		{ItemID: 2, Key: "b", Kind: KindChanged, At: day(2026, 7, 12), Payload: Payload{CVEsCleared: []CVE{kev1, epss}}},
		// August: KEV-1 comes back on a and clears again; that counts again.
		{ItemID: 1, Key: "a", Kind: KindChanged, At: day(2026, 8, 2), Payload: Payload{CVEsAdded: []string{"CVE-KEV-1"}}},
		{ItemID: 1, Key: "a", Kind: KindChanged, At: day(2026, 8, 9), Payload: Payload{CVEsCleared: []CVE{kev1}, Ticketed: true}},
		// September: a resolves. Its last snapshot still lists KEV-1, which was
		// credited in August and has not come back since: only CVE-PLAIN is new.
		{ItemID: 1, Key: "a", Kind: KindResolved, At: day(2026, 9, 3), Payload: Payload{Closed: &closed, Opened: &closed, Ticketed: true}},
		// September: an EPSS decay is not a clearance.
		{ItemID: 2, Key: "b", Kind: KindChanged, At: day(2026, 9, 4), Payload: Payload{SignalsRemoved: []string{SignalEPSSHigh}}},
	}
	rep := Aggregate(r, nil, events, nil, day(2026, 6, 1), day(2026, 9, 21))
	jul, aug, sep := rep.Movement[0], rep.Movement[1], rep.Movement[2]

	wantJul := Cleared{
		CVEsCleared: 3, KEVCVEsCleared: 2, EPSSHighCVEsCleared: 2,
		ClearedTicketed:    CVETally{CVEs: 2, KEV: 2, EPSSHigh: 1},
		ClearedUnticketed:  CVETally{CVEs: 1, EPSSHigh: 1},
		ItemsPartlyCleared: 2,
	}
	if jul.Cleared != wantJul {
		t.Errorf("July = %+v, want %+v", jul.Cleared, wantJul)
	}
	if aug.CVEsCleared != 1 || aug.KEVCVEsCleared != 1 || aug.ClearedTicketed.KEV != 1 || aug.ItemsPartlyCleared != 1 {
		t.Errorf("a CVE that came back and cleared again counts again: %+v", aug.Cleared)
	}
	if sep.CVEsCleared != 1 || sep.KEVCVEsCleared != 0 || sep.ClearedTicketed.CVEs != 1 || sep.ItemsPartlyCleared != 0 {
		t.Errorf("a resolution after partial clears counts only what was not already credited: %+v", sep.Cleared)
	}
	if sep.CVEsResolved != 2 || sep.KEVCVEsResolved != 1 || jul.CVEsResolved != 0 {
		t.Errorf("cves_resolved keeps its meaning, the resolved items' CVEs: jul %d, sep %d/%d", jul.CVEsResolved, sep.CVEsResolved, sep.KEVCVEsResolved)
	}
	if sep.EPSSDecayed != 1 {
		t.Errorf("decay is still reported as decay: %d", sep.EPSSDecayed)
	}

	// Across the range each CVE counts once, though KEV-1 cleared in all three months.
	want := RangeTotals{
		CVEsResolved: 2, KEVCVEsResolved: 1,
		Cleared: Cleared{
			CVEsCleared: 4, KEVCVEsCleared: 2, EPSSHighCVEsCleared: 2,
			ClearedTicketed:    CVETally{CVEs: 3, KEV: 2, EPSSHigh: 1},
			ClearedUnticketed:  CVETally{CVEs: 1, EPSSHigh: 1},
			ItemsPartlyCleared: 2,
		},
	}
	if rep.Totals != want {
		t.Errorf("totals = %+v, want %+v", rep.Totals, want)
	}
}

// A reassignment carries the new owner's snapshot without CVEsAdded, so a CVE on
// it is treated as back: it may clear again under the new owner.
func TestAggregateTreatsAReassignedSnapshotAsBack(t *testing.T) {
	r := Range{Since: day(2026, 7, 1), Until: day(2026, 9, 1), Bucket: BucketMonth}
	kev := cve("CVE-KEV-1", true, 0)
	to := Snapshot{Key: "a2", CVEs: []CVE{kev}}
	clear := Event{ItemID: 1, Key: "a", Kind: KindChanged, Payload: Payload{CVEsCleared: []CVE{kev}}}
	july, august := clear, clear
	july.At, august.At = day(2026, 7, 2), day(2026, 8, 4)
	without := Aggregate(r, nil, []Event{july, august}, nil, day(2026, 6, 1), day(2026, 9, 1))
	if without.Movement[1].KEVCVEsCleared != 0 {
		t.Fatalf("without coming back it cannot clear again: %+v", without.Movement[1].Cleared)
	}
	reassigned := Event{ItemID: 1, Key: "a", Kind: KindReassigned, At: day(2026, 8, 3), Payload: Payload{Snapshot: &to}}
	with := Aggregate(r, nil, []Event{july, reassigned, august}, nil, day(2026, 6, 1), day(2026, 9, 1))
	if with.Movement[1].KEVCVEsCleared != 1 || with.Totals.KEVCVEsCleared != 1 {
		t.Errorf("back on the reassigned snapshot, so August counts it; the range still counts it once: %+v / %+v",
			with.Movement[1].Cleared, with.Totals.Cleared)
	}
}
