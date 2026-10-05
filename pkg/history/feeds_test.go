package history

import (
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// deployed is acr.io/app carrying vulns, with the kev signal and top EPSS the
// assessment derives from them.
func deployed(vulns ...sink.VulnView) sink.FindingView {
	v := view("acr.io/app:1", "eng", "orders", "high")
	v.Vulns, v.Signals, v.TopEPSS = vulns, nil, 0
	for _, c := range vulns {
		if c.KEV && len(v.Signals) == 0 {
			v.Signals = []string{SignalKnownExploit}
		}
		if c.EPSS > v.TopEPSS {
			v.TopEPSS = c.EPSS
		}
	}
	return v
}

// outage is the same deployment after a run whose exploit lookup failed: every CVE
// still there, no KEV flag and no EPSS score on any of them.
func outage(v sink.FindingView) sink.FindingView {
	out := v
	out.Vulns = nil
	for _, c := range v.Vulns {
		c.KEV, c.EPSS = false, 0
		out.Vulns = append(out.Vulns, c)
	}
	return deployed(out.Vulns...)
}

// replay runs each assessment through Diff against the item as a store would hold
// it, and returns the events, so a test reads the report production would.
func replay(t *testing.T, runs [][]sink.FindingView) []Event {
	t.Helper()
	first := Snapshots(runs[0], nil)[0]
	st := openState(1, first, t0)
	events := []Event{{ItemID: 1, Key: first.Key, Kind: KindOpened, At: t0, Payload: Payload{Snapshot: &first}}}
	for i, views := range runs[1:] {
		at := t0.Add(time.Duration(i+1) * time.Hour)
		evs, marks := Diff(Input{Open: []State{st}, Current: Snapshots(views, nil), Views: views, Now: at})
		for _, e := range evs {
			if e.Kind == KindChanged {
				st.Current = *e.Payload.Snapshot
			}
			events = append(events, e)
		}
		for _, m := range marks {
			if m.Snapshot != nil {
				st.Current = *m.Snapshot
			}
		}
	}
	return events
}

// The figure that read 151 against 43 KEV items: every run whose exploit lookup
// failed dropped kev and epss-high from every item and the next run added them back,
// and each return counted as the item becoming known-exploited.
func TestFeedTransitionsCountOncePerTransition(t *testing.T) {
	kev := sink.VulnView{ID: "CVE-KEV", Severity: "critical", KEV: true, EPSS: 0.9}
	plain := sink.VulnView{ID: "CVE-PLAIN", Severity: "high", EPSS: 0.7}
	joins := plain
	joins.KEV = true
	decays := plain
	decays.EPSS = 0.3
	newKEV := sink.VulnView{ID: "CVE-NEW", Severity: "critical", KEV: true, EPSS: 0.2}
	ok := deployed(kev, plain)

	cases := []struct {
		name string
		runs [][]sink.FindingView
		// rawKEV and rawDecay are what counting every changed event gives, the
		// pattern the report used to repeat.
		rawKEV, rawDecay int
		kev, decay       int
	}{
		{name: "three exploit-feed outages on an item exploited from the start",
			runs:   [][]sink.FindingView{{ok}, {outage(ok)}, {ok}, {outage(ok)}, {ok}, {outage(ok)}, {ok}},
			rawKEV: 3, rawDecay: 3},
		{name: "a CVE joins KEV, through an outage, then decays and recovers",
			runs: [][]sink.FindingView{
				{deployed(plain)}, {deployed(joins)}, {outage(deployed(joins))}, {deployed(joins)},
				{deployed(decays)}, {deployed(plain)},
			},
			rawKEV: 2, rawDecay: 2, kev: 1, decay: 1},
		{name: "a fixed CVE takes its signals with it, and a new KEV is a new entry",
			runs: [][]sink.FindingView{
				{deployed(joins)}, {deployed()}, {deployed(newKEV)},
			},
			rawKEV: 1, rawDecay: 1, kev: 1},
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

func countOf(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}

// An item first seen in the range by a changed event has no snapshot before it, so
// the event's own signal moves are all there is to go on.
func TestFeedTransitionsForAnItemOpenedBeforeTheRange(t *testing.T) {
	snap := func(cves ...CVE) *Snapshot {
		s := &Snapshot{Key: "k", CVEs: cves}
		for _, c := range cves {
			if c.KEV && !s.Has(SignalKnownExploit) {
				s.Signals = append(s.Signals, SignalKnownExploit)
			}
			if c.EPSS > EPSSHigh && !s.Has(SignalEPSSHigh) {
				s.Signals = append(s.Signals, SignalEPSSHigh)
			}
		}
		return s
	}
	cases := []struct {
		name      string
		events    []Payload
		kev, epss int
	}{
		{name: "joins KEV", events: []Payload{{SignalsAdded: []string{SignalKnownExploit}, Snapshot: snap(CVE{ID: "A", KEV: true})}}, kev: 1},
		{name: "an outage first, then the return", events: []Payload{
			{SignalsRemoved: []string{SignalKnownExploit, SignalEPSSHigh}, Snapshot: snap(CVE{ID: "A"})},
			{SignalsAdded: []string{SignalKnownExploit, SignalEPSSHigh}, Snapshot: snap(CVE{ID: "A", KEV: true, EPSS: 0.9})},
		}},
		{name: "a genuine decay", events: []Payload{{SignalsRemoved: []string{SignalEPSSHigh}, Snapshot: snap(CVE{ID: "A", EPSS: 0.2})}}, epss: 1},
		{name: "the high CVE fixed is not a decay", events: []Payload{{SignalsRemoved: []string{SignalEPSSHigh}, CVEsRemoved: []string{"A"},
			Snapshot: snap(CVE{ID: "B", EPSS: 0.1})}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var events []Event
			for i, p := range c.events {
				events = append(events, Event{ItemID: 1, Key: "k", Kind: KindChanged, At: day(2026, 9, 2+i), Payload: p})
			}
			r := Range{Since: day(2026, 9, 1), Until: day(2026, 9, 30), Bucket: BucketMonth}
			m := Aggregate(r, nil, events, nil, time.Time{}, r.Until).Movement[0]
			if m.BecameKnownExploited != c.kev || m.EPSSDecayed != c.epss {
				t.Errorf("became KEV %d, EPSS decayed %d; want %d, %d", m.BecameKnownExploited, m.EPSSDecayed, c.kev, c.epss)
			}
		})
	}
}

// An image leaving the item in a run that missed a source takes its CVEs out of the
// snapshot, but that run vouched for nothing, so its return is no new entry.
func TestFeedTransitionsHoldThroughAPartialRun(t *testing.T) {
	a := CVE{ID: "A", KEV: true, EPSS: 0.9}
	with := &Snapshot{Key: "k", CVEs: []CVE{a}, Signals: []string{SignalKnownExploit, SignalEPSSHigh}}
	without := &Snapshot{Key: "k"}
	events := []Event{
		{ItemID: 1, Key: "k", Kind: KindOpened, At: day(2026, 9, 2), Payload: Payload{Snapshot: with}},
		{ItemID: 1, Key: "k", Kind: KindChanged, At: day(2026, 9, 3), Payload: Payload{Snapshot: without,
			SignalsRemoved: []string{SignalKnownExploit, SignalEPSSHigh}, CVEsRemoved: []string{"A"}, Reason: reasonPartial}},
		{ItemID: 1, Key: "k", Kind: KindChanged, At: day(2026, 9, 4), Payload: Payload{Snapshot: with,
			SignalsAdded: []string{SignalKnownExploit, SignalEPSSHigh}, CVEsAdded: []string{"A"}}},
	}
	r := Range{Since: day(2026, 9, 1), Until: day(2026, 9, 30), Bucket: BucketMonth}
	m := Aggregate(r, nil, events, nil, time.Time{}, r.Until).Movement[0]
	if m.BecameKnownExploited != 0 || m.EPSSDecayed != 0 {
		t.Errorf("became KEV %d, EPSS decayed %d; want 0, 0", m.BecameKnownExploited, m.EPSSDecayed)
	}
}
