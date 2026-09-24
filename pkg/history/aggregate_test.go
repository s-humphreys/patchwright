package history

import (
	"maps"
	"slices"
	"testing"
	"time"
)

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 12, 0, 0, 0, time.UTC) }

func TestPeriodsAlignToCalendar(t *testing.T) {
	months := Periods(Range{Since: day(2026, 6, 15), Until: day(2026, 9, 21), Bucket: BucketMonth})
	if len(months) != 4 || months[0].Period != "2026-06" || months[3].Period != "2026-09" {
		t.Fatalf("months = %+v", months)
	}
	if !months[0].Start.Equal(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("first month should start on the first: %v", months[0].Start)
	}
	weeks := Periods(Range{Since: day(2026, 9, 16), Until: day(2026, 9, 21), Bucket: BucketWeek})
	// 16 Sept 2026 is a Wednesday; its ISO week starts Monday the 14th.
	if len(weeks) != 2 || weeks[0].Period != "2026-W38" || weeks[0].Start.Weekday() != time.Monday {
		t.Errorf("weeks = %+v", weeks)
	}
}

func ptr[T any](v T) *T { return &v }

func TestAggregateClassifiesByOpeningState(t *testing.T) {
	r := Range{Since: day(2026, 7, 1), Until: day(2026, 9, 21), Bucket: BucketMonth}
	openedKEV := Snapshot{Key: "k1", Team: "orders", Rule: "exploited-fixable", Priority: "urgent", Signals: []string{"epss-high", "kev"}}
	openedPlain := Snapshot{Key: "k2", Team: "billing", Rule: "any-critical", Priority: "low"}
	events := []Event{
		// July: two items open. One has its EPSS decay in July.
		{Key: "k1", Kind: KindOpened, At: day(2026, 7, 3), Payload: Payload{Snapshot: &openedKEV}},
		{Key: "k2", Kind: KindOpened, At: day(2026, 7, 4), Payload: Payload{Snapshot: &openedPlain}},
		{Key: "k1", Kind: KindChanged, At: day(2026, 7, 20), Payload: Payload{SignalsRemoved: []string{"epss-high"}}},
		{Key: "k1", Kind: KindTicketRaised, At: day(2026, 7, 5), Payload: Payload{Ticket: "DVOP-1", Action: "create"}},
		// August: the KEV item resolves, ticketed, after 40 days. The plain one lapses.
		{Key: "k1", Kind: KindResolved, At: day(2026, 8, 12), Payload: Payload{Opened: &openedKEV, Ticketed: true, DaysOpen: ptr(40), Evidence: "x"}},
		{Key: "k1", Kind: KindTicketClosed, At: day(2026, 8, 12), Payload: Payload{Ticket: "DVOP-1", EvidenceAtClose: ptr(true)}},
		{Key: "k2", Kind: KindLapsed, At: day(2026, 8, 20), Payload: Payload{Opened: &openedPlain, DaysOpen: ptr(47), Reason: "acr.io/x is no longer reported"}},
		// September: a ticket closed by hand with the finding still open, and one
		// patchwright closed because nothing was running the image.
		{Key: "k3", Kind: KindTicketClosed, At: day(2026, 9, 2), Payload: Payload{Ticket: "DVOP-2", EvidenceAtClose: ptr(false)}},
		{Key: "k4", Kind: KindTicketClosed, At: day(2026, 9, 3), Payload: Payload{Ticket: "DVOP-4", EvidenceAtClose: ptr(false), Reason: "not-running"}},
		// Outside the range: ignored.
		{Key: "k9", Kind: KindOpened, At: day(2026, 6, 2), Payload: Payload{Snapshot: &openedPlain}},
	}
	assessments := []Assessment{
		{FinishedAt: day(2026, 7, 3), Findings: 100, Actionable: 40, ItemCount: 2, Risk: RiskStats{Items: 2, Sum: 900}},
		{FinishedAt: day(2026, 7, 30), Findings: 100, Actionable: 40, ItemCount: 2, Risk: RiskStats{Items: 2, Sum: 950}},
		{FinishedAt: day(2026, 8, 30), Findings: 90, Actionable: 30, ItemCount: 1, Risk: RiskStats{Items: 1, Sum: 400}},
	}
	open := []State{
		{OpenedAt: day(2026, 9, 1), Current: Snapshot{Key: "k3", Signals: []string{"kev"}, Tickets: []string{"DVOP-3"}}},
		{OpenedAt: day(2026, 9, 1), Current: Snapshot{Key: "k5"}, Missing: 1},
	}

	rep := Aggregate(r, assessments, events, open, time.Time{}, day(2026, 9, 21))

	if len(rep.Movement) != 3 {
		t.Fatalf("want 3 periods, got %d", len(rep.Movement))
	}
	jul, aug, sep := rep.Movement[0], rep.Movement[1], rep.Movement[2]

	if jul.Opened != 2 || jul.EPSSDecayed != 1 || jul.TicketsRaised != 1 {
		t.Errorf("july = %+v", jul)
	}
	if jul.BySignal["kev"].Opened != 1 || jul.BySignal["epss-high"].Opened != 1 || jul.ByTeam["billing"].Opened != 1 {
		t.Errorf("july splits = %+v %+v", jul.BySignal, jul.ByTeam)
	}

	if aug.Resolved != 1 || aug.ResolvedTicketed != 1 || aug.ResolvedUnticketed != 0 || aug.Lapsed != 1 {
		t.Errorf("august = %+v", aug)
	}
	// The EPSS signal had decayed before resolution; classification is by the
	// OPENING state, so it still counts as an EPSS resolution.
	if aug.BySignal["epss-high"].Resolved != 1 || aug.BySignal["kev"].ResolvedTicketed != 1 {
		t.Errorf("august by signal = %+v", aug.BySignal)
	}
	if aug.ByRule["exploited-fixable"].Resolved != 1 || aug.ByRule["any-critical"].Lapsed != 1 || aug.ByPriority["urgent"].Resolved != 1 {
		t.Errorf("august by rule/priority = %+v %+v", aug.ByRule, aug.ByPriority)
	}
	if aug.MedianDaysToResolve == nil || *aug.MedianDaysToResolve != 40 {
		t.Errorf("median days = %v (lapses must not count)", aug.MedianDaysToResolve)
	}
	if aug.LapseReasons["no longer reported"] != 1 {
		t.Errorf("lapse reasons = %v", aug.LapseReasons)
	}
	if aug.TicketsClosed != 1 || aug.TicketsClosedFindingOpen != 0 {
		t.Errorf("august tickets = %+v", aug)
	}

	if sep.TicketsClosed != 2 || sep.TicketsClosedFindingOpen != 2 || sep.Opened != 0 || sep.TicketsClosedByTool["not-running"] != 1 {
		t.Errorf("september = %+v", sep)
	}

	if len(rep.Risk) != 2 {
		t.Fatalf("risk points = %+v (september had no assessment)", rep.Risk)
	}
	if rep.Risk[0].Period != "2026-07" || rep.Risk[0].Risk.Sum != 950 || rep.Risk[0].Assessments != 2 {
		t.Errorf("july risk should be the LAST assessment of the month: %+v", rep.Risk[0])
	}
	if rep.Risk[1].Risk.Sum != 400 {
		t.Errorf("august risk = %+v", rep.Risk[1])
	}

	if rep.Open.Items != 2 || rep.Open.Ticketed != 1 || rep.Open.Missing != 1 || rep.Open.BySignal["kev"] != 1 || rep.Open.AgeDays["7-30"] != 2 {
		t.Errorf("open = %+v", rep.Open)
	}
	if rep.Assessments != 3 || rep.SchemaVersion != SchemaVersion || !rep.Enabled {
		t.Errorf("header = %+v", rep)
	}
}

func TestAgeBucket(t *testing.T) {
	for days, want := range map[int]string{0: "0-7", 6: "0-7", 7: "7-30", 45: "30-90", 200: "180+"} {
		if got := ageBucket(days); got != want {
			t.Errorf("ageBucket(%d) = %q, want %q", days, got, want)
		}
	}
}

func TestParseBucket(t *testing.T) {
	if b, err := ParseBucket(""); err != nil || b != BucketMonth {
		t.Errorf("default should be month")
	}
	if _, err := ParseBucket("fortnight"); err == nil {
		t.Errorf("unknown bucket must be rejected")
	}
}

// The first assessment opens everything it sees. Those items were not opened that
// month; they were already there, and a chart that shows them as a flood of new
// work misreads the record's start as an event in the estate.
func TestAggregateSeparatesTheBaselineFromOpenings(t *testing.T) {
	first := day(2026, 8, 15)
	snap := Snapshot{Key: "k", Team: "t", Signals: []string{"kev"}, CVEs: []CVE{{ID: "CVE-1", KEV: true}, {ID: "CVE-2"}}}
	events := []Event{
		{Key: "a", Kind: KindOpened, At: first, Payload: Payload{Snapshot: &snap}},
		{Key: "b", Kind: KindOpened, At: first.Add(20 * time.Second), Payload: Payload{Snapshot: &snap}},
		{Key: "c", Kind: KindOpened, At: first.Add(time.Hour), Payload: Payload{Snapshot: &snap}},
		{Key: "a", Kind: KindResolved, At: first.AddDate(0, 0, 3), Payload: Payload{Opened: &snap, Closed: &snap, DaysOpen: ptr(3)}},
		{Key: "b", Kind: KindResolved, At: first.AddDate(0, 0, 4), Payload: Payload{Opened: &snap, Closed: &Snapshot{CVEs: []CVE{{ID: "CVE-2"}, {ID: "CVE-3"}}}, DaysOpen: ptr(4)}},
	}
	rep := Aggregate(Range{Since: day(2026, 8, 1), Until: day(2026, 9, 1), Bucket: BucketMonth}, nil, events, nil, first, day(2026, 9, 1))
	m := rep.Movement[0]
	if m.Baseline != 2 || rep.Baseline != 2 || m.Opened != 1 {
		t.Errorf("baseline/opened = %d/%d, want 2/1", m.Baseline, m.Opened)
	}
	if m.BySignal["kev"].Opened != 1 {
		t.Errorf("the baseline must not count as opened in the splits: %+v", m.BySignal)
	}
	if m.Resolved != 2 || m.CVEsResolved != 3 || m.KEVCVEsResolved != 1 {
		t.Errorf("resolved %d, cves %d (want 3 distinct), kev cves %d (want 1)", m.Resolved, m.CVEsResolved, m.KEVCVEsResolved)
	}
	if rep.FirstRecorded == nil || !rep.FirstRecorded.Equal(first) {
		t.Errorf("first recorded should be carried: %v", rep.FirstRecorded)
	}
}

// A work item carrying several signals is one item. Stacked by signal, it has to sit
// in exactly one band or the bar overstates the queue.
func TestAggregateCountsOpenItemsOnceUnderTheirMostSevereSignal(t *testing.T) {
	r := Range{Since: day(2026, 7, 1), Until: day(2026, 9, 21), Bucket: BucketMonth}
	items := []Snapshot{
		{Key: "a", Signals: []string{"end-of-life", "fixable-critical", "kev", "epss-high"}},
		{Key: "b", Signals: []string{"fixable-critical", "epss-high"}},
		{Key: "c", Signals: []string{"end-of-life", "fixable-critical"}},
		{Key: "d", Signals: []string{"end-of-life", "in-flight"}},
		// Retired and unrelated signals put an item in no band.
		{Key: "e", Signals: []string{"exposed", "in-flight"}},
		{Key: "f"},
	}
	assessments := []Assessment{
		{ID: 1, FinishedAt: day(2026, 7, 10), Items: []Snapshot{{Key: "early", Signals: []string{"kev"}}}},
		{ID: 2, FinishedAt: day(2026, 7, 30), Items: items},
		// Never read: the report says nothing rather than zero.
		{ID: 3, FinishedAt: day(2026, 8, 30), ItemCount: 4},
		// Read, and empty.
		{ID: 4, FinishedAt: day(2026, 9, 20), Items: []Snapshot{}},
	}
	if got := LastOfPeriods(r, assessments); !slices.Equal(got, []int{1, 2, 3}) {
		t.Fatalf("last of periods = %v, want [1 2 3]", got)
	}
	rep := Aggregate(r, assessments, nil, nil, time.Time{}, day(2026, 9, 21))
	if len(rep.Risk) != 3 {
		t.Fatalf("risk points = %+v", rep.Risk)
	}
	want := map[string]int{"kev": 1, "epss-high": 1, "fixable-critical": 1, "end-of-life": 1}
	if got := rep.Risk[0].OpenBySignal; !maps.Equal(got, want) {
		t.Errorf("july open by signal = %v, want %v", got, want)
	}
	if got := rep.Risk[1].OpenBySignal; got != nil {
		t.Errorf("august's list was never read, so nothing should be claimed: %v", got)
	}
	zero := map[string]int{"kev": 0, "epss-high": 0, "fixable-critical": 0, "end-of-life": 0}
	if got := rep.Risk[2].OpenBySignal; !maps.Equal(got, zero) {
		t.Errorf("an empty queue is zeros: %v", got)
	}
}
