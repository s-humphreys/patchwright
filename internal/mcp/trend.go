package mcp

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
)

// HistorySource reads the record of movement for a range. Nil when history is not
// enabled, which the tool reports as such rather than as an empty record.
type HistorySource func(ctx context.Context, since, until time.Time, bucket history.Bucket) (history.Report, error)

// TrendReport answers "is this getting better" in words, with the caveats first,
// from the same report the history page draws. It adds a verdict and a handful of
// sentences and nothing else: every number in it is one the page shows.
type TrendReport struct {
	// Caveats come first, before any number, because the most misleading thing a
	// trend can do is show a period before the record began as a quiet one.
	Caveats []string  `json:"caveats"`
	Since   time.Time `json:"since"`
	Until   time.Time `json:"until"`
	Bucket  string    `json:"bucket"`
	// FirstRecorded is when the record begins; nil when it is empty.
	FirstRecorded *time.Time `json:"first_recorded,omitempty"`

	// Summary is the answer in sentences, in the order a reader needs them.
	Summary []string `json:"summary"`

	Direction Direction   `json:"direction"`
	Movement  TrendTotals `json:"movement"`
	// BySignal sums the per-period splits over the range, classified by each item's
	// opening state. KEV is the headline; EPSS is a forecast and sits beside it.
	BySignal map[string]history.Counts `json:"by_signal,omitempty"`
	ByRule   map[string]history.Counts `json:"by_rule,omitempty"`
	ByTeam   map[string]history.Counts `json:"by_team,omitempty"`

	Periods []history.Movement  `json:"periods"`
	Open    history.OpenSummary `json:"open"`
}

// Direction is the risk score at the two ends of the range.
type Direction struct {
	// Verdict is one of improving, worsening, flat, or insufficient-data.
	Verdict     string  `json:"verdict"`
	FirstPeriod string  `json:"first_period,omitempty"`
	LastPeriod  string  `json:"last_period,omitempty"`
	RiskStart   float64 `json:"risk_sum_start"`
	RiskEnd     float64 `json:"risk_sum_end"`
	ChangePct   float64 `json:"change_pct"`
	ItemsStart  int     `json:"items_start"`
	ItemsEnd    int     `json:"items_end"`
	KEVStart    int     `json:"kev_items_start"`
	KEVEnd      int     `json:"kev_items_end"`
}

// TrendTotals are the movement counts summed over the range. ResolvedTicketed is a
// subset of Resolved; Lapsed is never remediation.
type TrendTotals struct {
	Opened                   int `json:"opened"`
	Resolved                 int `json:"resolved"`
	ResolvedTicketed         int `json:"resolved_ticketed"`
	ResolvedUnticketed       int `json:"resolved_unticketed"`
	Lapsed                   int `json:"lapsed"`
	Reassigned               int `json:"reassigned"`
	TicketsRaised            int `json:"tickets_raised"`
	TicketsClosed            int `json:"tickets_closed"`
	TicketsClosedFindingOpen int `json:"tickets_closed_finding_open"`
	EPSSDecayed              int `json:"epss_decayed"`
	BecameKnownExploited     int `json:"became_known_exploited"`
	// MedianDaysToResolve is the median of the per-period medians, weighted by how
	// many resolved in each; nil when nothing resolved.
	MedianDaysToResolve *float64       `json:"median_days_to_resolve,omitempty"`
	LapseReasons        map[string]int `json:"lapse_reasons,omitempty"`
	TicketsClosedByTool map[string]int `json:"tickets_closed_by_tool,omitempty"`
}

// flatBand is how far the risk sum can move and still be called flat.
const flatBand = 5.0

// NewTrendReport builds the report from a history report.
func NewTrendReport(rep history.Report) TrendReport {
	out := TrendReport{
		Caveats: append([]string{}, rep.Caveats...), Since: rep.Since, Until: rep.Until, Bucket: string(rep.Bucket),
		FirstRecorded: rep.FirstRecorded, Periods: rep.Movement, Open: rep.Open,
		BySignal: map[string]history.Counts{}, ByRule: map[string]history.Counts{}, ByTeam: map[string]history.Counts{},
		Movement: TrendTotals{LapseReasons: map[string]int{}, TicketsClosedByTool: map[string]int{}},
	}
	out.Direction = direction(rep.Risk)

	var medians []weighted
	for _, m := range rep.Movement {
		t := &out.Movement
		t.Opened += m.Opened
		t.Resolved += m.Resolved
		t.ResolvedTicketed += m.ResolvedTicketed
		t.ResolvedUnticketed += m.ResolvedUnticketed
		t.Lapsed += m.Lapsed
		t.Reassigned += m.Reassigned
		t.TicketsRaised += m.TicketsRaised
		t.TicketsClosed += m.TicketsClosed
		t.TicketsClosedFindingOpen += m.TicketsClosedFindingOpen
		t.EPSSDecayed += m.EPSSDecayed
		t.BecameKnownExploited += m.BecameKnownExploited
		for k, v := range m.LapseReasons {
			t.LapseReasons[k] += v
		}
		for k, v := range m.TicketsClosedByTool {
			t.TicketsClosedByTool[k] += v
		}
		if m.MedianDaysToResolve != nil && m.Resolved > 0 {
			medians = append(medians, weighted{*m.MedianDaysToResolve, m.Resolved})
		}
		sumCounts(out.BySignal, m.BySignal)
		sumCounts(out.ByRule, m.ByRule)
		sumCounts(out.ByTeam, m.ByTeam)
	}
	if med, ok := weightedMedian(medians); ok {
		out.Movement.MedianDaysToResolve = &med
	}
	if len(out.Movement.LapseReasons) == 0 {
		out.Movement.LapseReasons = nil
	}
	if len(out.Movement.TicketsClosedByTool) == 0 {
		out.Movement.TicketsClosedByTool = nil
	}
	out.Summary = trendSummary(out)
	return out
}

func sumCounts(into map[string]history.Counts, from map[string]history.Counts) {
	for k, v := range from {
		c := into[k]
		c.Opened += v.Opened
		c.Resolved += v.Resolved
		c.Lapsed += v.Lapsed
		c.ResolvedTicketed += v.ResolvedTicketed
		into[k] = c
	}
}

type weighted struct {
	value  float64
	weight int
}

func weightedMedian(ws []weighted) (float64, bool) {
	total := 0
	for _, w := range ws {
		total += w.weight
	}
	if total == 0 {
		return 0, false
	}
	sort.Slice(ws, func(i, j int) bool { return ws[i].value < ws[j].value })
	seen := 0
	for _, w := range ws {
		seen += w.weight
		if seen*2 >= total {
			return w.value, true
		}
	}
	return ws[len(ws)-1].value, true
}

func direction(points []history.RiskPoint) Direction {
	d := Direction{Verdict: "insufficient-data"}
	if len(points) == 0 {
		return d
	}
	first, last := points[0], points[len(points)-1]
	d.FirstPeriod, d.LastPeriod = first.Period, last.Period
	d.RiskStart, d.RiskEnd = first.Risk.Sum, last.Risk.Sum
	d.ItemsStart, d.ItemsEnd = first.Risk.Items, last.Risk.Items
	d.KEVStart, d.KEVEnd = first.Risk.KnownExploited, last.Risk.KnownExploited
	if len(points) < 2 || first.Risk.Sum == 0 {
		return d
	}
	d.ChangePct = math.Round((last.Risk.Sum-first.Risk.Sum)/first.Risk.Sum*1000) / 10
	switch {
	case d.ChangePct <= -flatBand:
		d.Verdict = "improving"
	case d.ChangePct >= flatBand:
		d.Verdict = "worsening"
	default:
		d.Verdict = "flat"
	}
	return d
}

// trendSummary writes the answer. Each sentence states one thing and names the
// distinction it depends on, because the reader is an agent that will repeat the
// sentence without the table behind it.
func trendSummary(r TrendReport) []string {
	var out []string
	if r.FirstRecorded != nil {
		out = append(out, fmt.Sprintf("The record begins %s; anything before that is not a quiet period, it is an unwatched one.",
			r.FirstRecorded.Format("2 January 2006")))
	}
	d := r.Direction
	switch d.Verdict {
	case "insufficient-data":
		if d.LastPeriod == "" {
			out = append(out, "No assessment has been recorded in this range, so there is no direction to report.")
		} else {
			out = append(out, fmt.Sprintf("Only one period (%s) has data: %d open items with a risk sum of %.0f. That is a point, not a direction.",
				d.LastPeriod, d.ItemsEnd, d.RiskEnd))
		}
	default:
		word := map[string]string{"improving": "fell", "worsening": "rose", "flat": "was flat"}[d.Verdict]
		out = append(out, fmt.Sprintf("The estate's risk score sum %s from %.0f in %s to %.0f in %s (%+.1f%%), across %d then %d open items; known-exploited items went from %d to %d.",
			word, d.RiskStart, d.FirstPeriod, d.RiskEnd, d.LastPeriod, d.ChangePct, d.ItemsStart, d.ItemsEnd, d.KEVStart, d.KEVEnd))
	}
	m := r.Movement
	out = append(out, fmt.Sprintf("%d work items opened and %d resolved with evidence, of which %d were ticketed work and %d landed by another route (an update bot, a Flux automation, a rebuild done in passing).",
		m.Opened, m.Resolved, m.ResolvedTicketed, m.ResolvedUnticketed))
	if m.Lapsed > 0 {
		out = append(out, fmt.Sprintf("%d items lapsed: they left the queue without evidence the work was done, and are not counted as remediation. Reasons: %s.",
			m.Lapsed, describeCounts(m.LapseReasons)))
	}
	if kev, ok := r.BySignal["kev"]; ok && (kev.Opened > 0 || kev.Resolved > 0) {
		out = append(out, fmt.Sprintf("Known-exploited: %d opened, %d resolved (%d ticketed), %d lapsed, classified by the item's state when first seen.",
			kev.Opened, kev.Resolved, kev.ResolvedTicketed, kev.Lapsed))
	}
	if epss, ok := r.BySignal[history.SignalEPSSHigh]; ok && (epss.Opened > 0 || epss.Resolved > 0 || m.EPSSDecayed > 0) {
		out = append(out, fmt.Sprintf("EPSS above 0.5: %d opened, %d resolved; %d items left that bucket by score decay rather than by a patch.",
			epss.Opened, epss.Resolved, m.EPSSDecayed))
	}
	if m.TicketsClosedFindingOpen > 0 {
		out = append(out, fmt.Sprintf("%d tickets were closed while the image still ran; those are neither resolved nor lapsed.", m.TicketsClosedFindingOpen))
	}
	if m.MedianDaysToResolve != nil {
		out = append(out, fmt.Sprintf("Median time from first seen to resolved, over resolved items only: %.0f days.", *m.MedianDaysToResolve))
	}
	out = append(out, fmt.Sprintf("Open now: %d items, %d ticketed%s.", r.Open.Items, r.Open.Ticketed,
		map[bool]string{true: fmt.Sprintf(", %d absent from the latest run and inside the grace period", r.Open.Missing), false: ""}[r.Open.Missing > 0]))
	return out
}

func describeCounts(m map[string]int) string {
	if len(m) == 0 {
		return "none recorded"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return m[keys[i]] > m[keys[j]] || (m[keys[i]] == m[keys[j]] && keys[i] < keys[j]) })
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return joinAnd(parts)
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	out := ""
	for i, p := range parts {
		switch {
		case i == 0:
			out = p
		case i == len(parts)-1:
			out += " and " + p
		default:
			out += ", " + p
		}
	}
	return out
}
