package history

import (
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// The figure that read 177 against 78 KEV items opened: the vuln source answered for
// every image straight after a restart and for fewer on each run after, so an item's
// CVEs, and the KEV flags and EPSS scores on them, left with the coverage and came
// back with the next restart. Each return counted as the item becoming
// known-exploited.
func TestFeedTransitionsFollowScanCoverage(t *testing.T) {
	exploited := sink.VulnView{ID: "CVE-KEV", Severity: "critical", KEV: true, EPSS: 0.9}
	notYet := exploited
	notYet.KEV = false
	plain := sink.VulnView{ID: "CVE-PLAIN", Severity: "high", EPSS: 0.1}
	newKEV := sink.VulnView{ID: "CVE-NEW", Severity: "critical", KEV: true, EPSS: 0.2}
	high := sink.VulnView{ID: "CVE-EPSS", Severity: "high", EPSS: 0.6}
	fell := high
	fell.EPSS = 0.3

	cases := []struct {
		name string
		runs [][]sink.FindingView
		// rawKEV and rawDecay are what counting every changed event gives.
		rawKEV, rawDecay int
		kev, decay       int
	}{
		{name: "coverage lost and regained on an unchanged image is one entry, not three",
			runs: [][]sink.FindingView{
				{scannedAs("sha256:a", notYet)}, {scannedAs("sha256:a", exploited)},
				{unscannedAs("sha256:a")}, {scannedAs("sha256:a", exploited)},
				{unscannedAs("sha256:a")}, {scannedAs("sha256:a", exploited)},
			},
			rawKEV: 3, rawDecay: 2, kev: 1},
		{name: "an image replaced in a run the vuln source missed is no evidence the KEV left",
			runs: [][]sink.FindingView{
				{scannedAs("sha256:a", exploited)}, {unscannedAs("sha256:b")}, {scannedAs("sha256:b", exploited)},
			},
			rawKEV: 1, rawDecay: 1},
		{name: "a genuine leave, then a new KEV on the new image, is a second entry",
			runs: [][]sink.FindingView{
				{scannedAs("sha256:a", exploited, plain)}, {scannedAs("sha256:b", plain)},
				{unscannedAs("sha256:b")}, {scannedAs("sha256:b", plain, newKEV)},
			},
			rawKEV: 1, rawDecay: 1, kev: 1},
		{name: "a KEV flag removed while the CVE stays and the source is unchanged is a leave",
			runs: [][]sink.FindingView{
				{scannedAs("sha256:a", exploited)}, {scannedAs("sha256:a", notYet)}, {scannedAs("sha256:a", exploited)},
			},
			rawKEV: 1, kev: 1},
		{name: "coverage lost and regained keeps the EPSS standing",
			runs: [][]sink.FindingView{
				{scannedAs("sha256:a", high)}, {unscannedAs("sha256:a")}, {scannedAs("sha256:a", high)},
				{unscannedAs("sha256:a")}, {scannedAs("sha256:a", high)},
			},
			rawDecay: 2},
		{name: "a score that fell while the vuln source missed the image is still a decay",
			runs: [][]sink.FindingView{
				{scannedAs("sha256:a", high)}, {unscannedAs("sha256:a")}, {scannedAs("sha256:a", fell)},
			},
			rawDecay: 1, decay: 1},
		{name: "the EPSS CVE fixed by a new image is not a decay",
			runs: [][]sink.FindingView{
				{scannedAs("sha256:a", high, plain)}, {scannedAs("sha256:b", plain)},
				{unscannedAs("sha256:b")}, {scannedAs("sha256:b", plain)},
			},
			rawDecay: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			events := replay(t, c.runs)
			rawKEV, rawDecay := 0, 0
			for _, e := range events {
				rawKEV += countOf(e.Payload.SignalsAdded, SignalKnownExploit)
				rawDecay += countOf(e.Payload.SignalsRemoved, SignalEPSSHigh)
			}
			if rawKEV != c.rawKEV || rawDecay != c.rawDecay {
				t.Fatalf("raw signal moves = %d kev, %d epss; the scenario expects %d, %d", rawKEV, rawDecay, c.rawKEV, c.rawDecay)
			}
			r := Range{Since: t0.AddDate(0, 0, -1), Until: t0.AddDate(0, 0, 1), Bucket: BucketMonth}
			m := Aggregate(r, nil, events, nil, time.Time{}, r.Until).Movement[0]
			if m.BecameKnownExploited != c.kev || m.EPSSDecayed != c.decay {
				t.Errorf("became KEV %d, EPSS decayed %d; want %d, %d", m.BecameKnownExploited, m.EPSSDecayed, c.kev, c.decay)
			}
		})
	}
}

// Records made before snapshots carried their scan state cannot show a CVE was
// remediated, so a CVE leaving them never ends an item's standing: the stored
// production record is corrected from its own events, with no backfill.
func TestFeedTransitionsOnRecordsWithoutScanState(t *testing.T) {
	kev := CVE{ID: "A", KEV: true, EPSS: 0.9}
	with := &Snapshot{Key: "k", CVEs: []CVE{kev}, Images: []string{"acr.io/app:1"},
		Signals: []string{SignalKnownExploit, SignalEPSSHigh}}
	without := &Snapshot{Key: "k", Images: []string{"acr.io/app:2"}}
	var events []Event
	events = append(events, Event{ItemID: 1, Key: "k", Kind: KindOpened, At: day(2026, 9, 2), Payload: Payload{Snapshot: with}})
	for i := 0; i < 3; i++ {
		events = append(events,
			Event{ItemID: 1, Key: "k", Kind: KindChanged, At: day(2026, 9, 3+2*i), Payload: Payload{Snapshot: without,
				SignalsRemoved: []string{SignalKnownExploit, SignalEPSSHigh}, CVEsRemoved: []string{"A"}}},
			Event{ItemID: 1, Key: "k", Kind: KindChanged, At: day(2026, 9, 4+2*i), Payload: Payload{Snapshot: with,
				SignalsAdded: []string{SignalKnownExploit, SignalEPSSHigh}, CVEsAdded: []string{"A"}}})
	}
	r := Range{Since: day(2026, 9, 1), Until: day(2026, 9, 30), Bucket: BucketMonth}
	m := Aggregate(r, nil, events, nil, time.Time{}, r.Until).Movement[0]
	if m.BecameKnownExploited != 0 || m.EPSSDecayed != 0 {
		t.Errorf("became KEV %d, EPSS decayed %d; want 0, 0", m.BecameKnownExploited, m.EPSSDecayed)
	}
}
