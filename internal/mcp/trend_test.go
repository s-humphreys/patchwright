package mcp

import (
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
)

func trendFixture() history.Report {
	first := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	med := 12.0
	return history.Report{
		SchemaVersion: history.SchemaVersion, Enabled: true, Bucket: history.BucketMonth,
		Since: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), Until: time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC),
		FirstRecorded: &first,
		Caveats:       []string{"the record begins 2026-08-15; periods before it are empty because nothing was watching, not because nothing happened"},
		Risk: []history.RiskPoint{
			{Period: "2026-08", Risk: history.RiskStats{Items: 300, Sum: 250000, KnownExploited: 30}},
			{Period: "2026-09", Risk: history.RiskStats{Items: 280, Sum: 200000, KnownExploited: 28}},
		},
		Movement: []history.Movement{
			{Period: "2026-07"},
			{Period: "2026-08", Opened: 300, Resolved: 2, ResolvedTicketed: 1, ResolvedUnticketed: 1, Lapsed: 1,
				BySignal: map[string]history.Counts{"kev": {Opened: 30, Resolved: 1, ResolvedTicketed: 1}}},
			{Period: "2026-09", Opened: 20, Resolved: 5, ResolvedTicketed: 2, ResolvedUnticketed: 3, Lapsed: 8,
				TicketsClosedFindingOpen: 1, EPSSDecayed: 10, MedianDaysToResolve: &med,
				LapseReasons: map[string]int{"no longer reported": 6, "no longer running": 2},
				BySignal:     map[string]history.Counts{"kev": {Opened: 2, Resolved: 3, ResolvedTicketed: 2, Lapsed: 1}, history.SignalEPSSHigh: {Opened: 5, Resolved: 1}}},
		},
		Open: history.OpenSummary{Items: 280, Ticketed: 50, Missing: 4},
	}
}

func TestTrendReportLeadsWithTheRecordStart(t *testing.T) {
	r := NewTrendReport(trendFixture())
	if len(r.Summary) == 0 || !strings.Contains(r.Summary[0], "The record begins 15 August 2026") {
		t.Fatalf("first sentence must be when the record begins: %v", r.Summary)
	}
	if len(r.Caveats) == 0 || !strings.Contains(r.Caveats[0], "record begins") {
		t.Errorf("caveats should be carried through first: %v", r.Caveats)
	}
}

func TestTrendReportVerdictAndTotals(t *testing.T) {
	r := NewTrendReport(trendFixture())
	if r.Direction.Verdict != "improving" || r.Direction.ChangePct != -20 {
		t.Errorf("250000 -> 200000 is improving by 20%%: %+v", r.Direction)
	}
	m := r.Movement
	if m.Opened != 320 || m.Resolved != 7 || m.ResolvedTicketed != 3 || m.ResolvedUnticketed != 4 || m.Lapsed != 9 {
		t.Errorf("totals = %+v", m)
	}
	if m.ResolvedTicketed+m.ResolvedUnticketed != m.Resolved {
		t.Errorf("ticketed and unticketed must partition resolved: %+v", m)
	}
	if m.MedianDaysToResolve == nil || *m.MedianDaysToResolve != 12 {
		t.Errorf("median = %v", m.MedianDaysToResolve)
	}
	if r.BySignal["kev"] != (history.Counts{Opened: 32, Resolved: 4, Lapsed: 1, ResolvedTicketed: 3}) {
		t.Errorf("kev split = %+v", r.BySignal["kev"])
	}
	joined := strings.Join(r.Summary, " ")
	for _, want := range []string{"fell from 250000", "-20.0%", "320 work items opened and 7 resolved with evidence", "3 were ticketed work", "cleared 0 distinct CVEs", "9 items lapsed", "no longer reported 6 and no longer running 2", "Known-exploited: 32 opened, 4 resolved", "10 items left that bucket by score decay", "1 tickets were closed while the image still ran", "Median time from first seen to resolved", "Open now: 280 items, 50 ticketed, 4 absent"} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary should say %q:\n%s", want, joined)
		}
	}
	// The one number the summary must never produce: resolved plus lapsed.
	if strings.Contains(joined, "16 ") {
		t.Errorf("summary appears to sum resolved and lapsed: %s", joined)
	}
}

func TestTrendReportWithOnePeriodIsAPointNotADirection(t *testing.T) {
	rep := trendFixture()
	rep.Risk = rep.Risk[1:]
	r := NewTrendReport(rep)
	if r.Direction.Verdict != "insufficient-data" {
		t.Errorf("verdict = %q", r.Direction.Verdict)
	}
	if !strings.Contains(strings.Join(r.Summary, " "), "a point, not a direction") {
		t.Errorf("summary should say so: %v", r.Summary)
	}
}

func TestTrendReportFlatBand(t *testing.T) {
	rep := trendFixture()
	rep.Risk[1].Risk.Sum = 245000 // -2%
	if v := NewTrendReport(rep).Direction.Verdict; v != "flat" {
		t.Errorf("a 2%% move is flat, got %q", v)
	}
	rep.Risk[1].Risk.Sum = 300000 // +20%
	if v := NewTrendReport(rep).Direction.Verdict; v != "worsening" {
		t.Errorf("a 20%% rise is worsening, got %q", v)
	}
}

func TestTrendReportEmptyRange(t *testing.T) {
	r := NewTrendReport(history.Report{Enabled: true, Bucket: history.BucketMonth})
	if r.Direction.Verdict != "insufficient-data" || !strings.Contains(strings.Join(r.Summary, " "), "No assessment has been recorded") {
		t.Errorf("empty = %+v", r)
	}
}

func TestTrendReportCycleTime(t *testing.T) {
	rep := trendFixture()
	f := func(v float64) *float64 { return &v }
	i := func(v int) *int { return &v }
	rep.Movement[1].TrackerTicketsRaised, rep.Movement[1].TrackerTicketsClosed = i(4), i(1)
	rep.Movement[1].MedianDaysTold, rep.Movement[1].MedianDaysToldN = f(2), 1
	rep.Movement[1].MedianDaysWorked, rep.Movement[1].MedianDaysWorkedN = f(10), 1
	rep.Movement[2].TrackerTicketsRaised, rep.Movement[2].TrackerTicketsClosed = i(6), i(5)
	rep.Movement[2].MedianDaysTold, rep.Movement[2].MedianDaysToldN = f(4), 3
	rep.Movement[2].MedianDaysToStart, rep.Movement[2].MedianDaysToStartN = f(1.5), 4
	n := 2
	rep.Open.ClosedTicketFindingOpen, rep.Open.ClosedTicketAgeDays = &n, map[string]int{"0-7": 1, "30-90": 1}

	r := NewTrendReport(rep)
	m := r.Movement
	if m.TrackerTicketsRaised == nil || *m.TrackerTicketsRaised != 10 || *m.TrackerTicketsClosed != 6 {
		t.Errorf("tracker totals = %v/%v, want 10/6", m.TrackerTicketsRaised, m.TrackerTicketsClosed)
	}
	// Weighted by the tickets each rests on: one at 2 days, three at 4.
	if m.MedianDaysTold == nil || *m.MedianDaysTold != 4 || m.MedianDaysToldN != 4 {
		t.Errorf("told = %v over %d, want 4 over 4", m.MedianDaysTold, m.MedianDaysToldN)
	}
	if m.MedianDaysToStart == nil || *m.MedianDaysToStart != 1.5 || m.MedianDaysWorkedN != 1 {
		t.Errorf("to start / worked = %+v", m)
	}
	joined := strings.Join(r.Summary, " ")
	for _, want := range []string{
		"finding to ticket 4.0 days (over 4 tickets)", "ticket to first In Progress 1.5 days (over 4 tickets)",
		"In Progress to resolved 10.0 days (over 1 tickets)", "10 tickets were raised and 6 closed",
		"tickets, not resolutions", "2 open items had their ticket closed while the finding stayed open",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary should say %q:\n%s", want, joined)
		}
	}
}

func TestTrendReportWithoutTheTrackerSaysNothingOfIt(t *testing.T) {
	r := NewTrendReport(trendFixture())
	if r.Movement.TrackerTicketsRaised != nil || r.Movement.MedianDaysTold != nil {
		t.Errorf("no tracker data: %+v", r.Movement)
	}
	joined := strings.Join(r.Summary, " ")
	if strings.Contains(joined, "cycle time") || strings.Contains(joined, "tracker") {
		t.Errorf("summary mentions the tracker without data: %s", joined)
	}
}
