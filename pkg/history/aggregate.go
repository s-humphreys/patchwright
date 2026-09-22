package history

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Bucket is the period a report is grouped by.
type Bucket string

const (
	BucketMonth Bucket = "month"
	BucketWeek  Bucket = "week"
)

// ParseBucket accepts the bucket names the API takes. Empty means month.
func ParseBucket(s string) (Bucket, error) {
	switch Bucket(s) {
	case "", BucketMonth:
		return BucketMonth, nil
	case BucketWeek:
		return BucketWeek, nil
	}
	return "", fmt.Errorf("bucket must be %q or %q", BucketMonth, BucketWeek)
}

// Report is the history of a range, by period. Every figure is in work items.
type Report struct {
	SchemaVersion int `json:"schema_version"`
	// Enabled is false when no store is configured, in which case nothing else here
	// is populated and the caveat says so.
	Enabled bool      `json:"enabled"`
	Since   time.Time `json:"since"`
	Until   time.Time `json:"until"`
	Bucket  Bucket    `json:"bucket"`
	// FirstRecorded is when the record begins. A range that starts before it is
	// reporting on a period the tool was not watching, and the caveat says so.
	FirstRecorded *time.Time `json:"first_recorded,omitempty"`
	// Baseline is the items already open when the record began, when that moment
	// falls inside the range.
	Baseline      int `json:"baseline"`
	Assessments   int `json:"assessments"`
	RetentionDays int `json:"retention_days,omitempty"`

	// Risk is the estate's direction: the last assessment of each period.
	Risk []RiskPoint `json:"risk"`
	// Movement is what opened, resolved and lapsed in each period.
	Movement []Movement `json:"movement"`
	// Open is the queue as the record holds it now.
	Open OpenSummary `json:"open"`

	Caveats []string `json:"caveats,omitempty"`
}

// RiskPoint is the estate at the end of one period.
type RiskPoint struct {
	Period string    `json:"period"`
	At     time.Time `json:"at"`
	// Assessments is how many runs fell in the period; a period with one has a
	// point, not a trend.
	Assessments int                  `json:"assessments"`
	Findings    int                  `json:"findings"`
	Actionable  int                  `json:"actionable"`
	Risk        RiskStats            `json:"risk"`
	ByClass     map[string]RiskStats `json:"by_class,omitempty"`
	ByTeam      map[string]RiskStats `json:"by_team,omitempty"`
}

// Movement is the transitions in one period.
type Movement struct {
	Period string    `json:"period"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`

	// Baseline is the items that were already open when the record began, counted
	// in the period it began. They are not "opened": nothing happened to them that
	// period except that something started watching. Kept apart so the first month
	// does not read as a flood of new work.
	Baseline   int `json:"baseline"`
	Opened     int `json:"opened"`
	Resolved   int `json:"resolved"`
	Lapsed     int `json:"lapsed"`
	Reassigned int `json:"reassigned"`

	// CVEsResolved is the distinct CVEs carried by the items resolved this period,
	// and KEVCVEsResolved the known-exploited among them. The item is the unit of
	// work; the CVE is what security asked about, and one item can clear hundreds.
	CVEsResolved    int `json:"cves_resolved"`
	KEVCVEsResolved int `json:"kev_cves_resolved"`

	// The delineation. ResolvedTicketed is a subset of Resolved, never a separate
	// total; Resolved less ResolvedTicketed is work that landed by another route.
	ResolvedTicketed   int `json:"resolved_ticketed"`
	ResolvedUnticketed int `json:"resolved_unticketed"`
	TicketsRaised      int `json:"tickets_raised"`
	TicketsClosed      int `json:"tickets_closed"`
	// TicketsClosedFindingOpen is a ticket closed while patchwright had no evidence
	// the work was done: a human closing a ticket on an image that still runs.
	TicketsClosedFindingOpen int `json:"tickets_closed_finding_open"`
	// TicketsClosedByTool splits the tickets patchwright itself closed by reason
	// (upgrade-landed, not-running, no-longer-actionable). The remainder of
	// TicketsClosed were closed by people.
	TicketsClosedByTool map[string]int `json:"tickets_closed_by_tool,omitempty"`

	// EPSSDecayed is items that left the EPSS bucket because the score fell while
	// they were open. Not remediation, and not hidden.
	EPSSDecayed int `json:"epss_decayed"`
	// BecameKnownExploited is items whose CVEs joined KEV while open.
	BecameKnownExploited int `json:"became_known_exploited"`

	// MedianDaysToResolve is over resolved items only, dated from when the record
	// first saw them. Nil when nothing resolved.
	MedianDaysToResolve *float64 `json:"median_days_to_resolve,omitempty"`
	// LapseReasons says why lapses could not be called resolutions.
	LapseReasons map[string]int `json:"lapse_reasons,omitempty"`

	// The splits, each classified by the item's OPENING state.
	BySignal   map[string]Counts `json:"by_signal,omitempty"`
	ByRule     map[string]Counts `json:"by_rule,omitempty"`
	ByPriority map[string]Counts `json:"by_priority,omitempty"`
	ByTeam     map[string]Counts `json:"by_team,omitempty"`
}

// Counts is opened, resolved and lapsed for one split.
type Counts struct {
	Opened   int `json:"opened"`
	Resolved int `json:"resolved"`
	Lapsed   int `json:"lapsed"`
	// ResolvedTicketed is the ticketed subset of Resolved.
	ResolvedTicketed int `json:"resolved_ticketed"`
}

// OpenSummary is the open queue as the record holds it.
type OpenSummary struct {
	Items    int `json:"items"`
	Ticketed int `json:"ticketed"`
	// Missing is how many open items were absent from the latest assessment and are
	// inside the grace period: not yet lapsed, not confirmed present.
	Missing  int            `json:"missing"`
	BySignal map[string]int `json:"by_signal,omitempty"`
	// AgeDays buckets open items by how long the record has held them.
	AgeDays map[string]int `json:"age_days,omitempty"`
}

// Range is what a report covers.
type Range struct {
	Since, Until time.Time
	Bucket       Bucket
}

// Periods splits a range into buckets, aligned to calendar months or ISO weeks in
// UTC, so "this month" on the page is the month somebody means.
func Periods(r Range) []Movement {
	var out []Movement
	start := periodStart(r.Since, r.Bucket)
	for start.Before(r.Until) {
		end := nextPeriod(start, r.Bucket)
		out = append(out, Movement{Period: periodLabel(start, r.Bucket), Start: start, End: end})
		start = end
	}
	return out
}

func periodStart(t time.Time, b Bucket) time.Time {
	t = t.UTC()
	switch b {
	case BucketWeek:
		d := t.Truncate(24 * time.Hour)
		// ISO weeks start on Monday.
		offset := (int(d.Weekday()) + 6) % 7
		return d.AddDate(0, 0, -offset)
	default:
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
}

func nextPeriod(start time.Time, b Bucket) time.Time {
	if b == BucketWeek {
		return start.AddDate(0, 0, 7)
	}
	return start.AddDate(0, 1, 0)
}

func periodLabel(start time.Time, b Bucket) string {
	if b == BucketWeek {
		y, w := start.ISOWeek()
		return fmt.Sprintf("%d-W%02d", y, w)
	}
	return start.Format("2006-01")
}

// Aggregate builds a report from the assessments and events in a range and the
// items currently open. first is when the record began (zero when unknown): the
// opened events of that first assessment are the baseline, not new work.
func Aggregate(r Range, assessments []Assessment, events []Event, open []State, first, now time.Time) Report {
	rep := Report{
		SchemaVersion: SchemaVersion, Enabled: true,
		Since: r.Since, Until: r.Until, Bucket: r.Bucket,
		Assessments: len(assessments),
		Risk:        []RiskPoint{},
		Movement:    Periods(r),
		Open:        openSummary(open, now),
	}
	if !first.IsZero() {
		f := first
		rep.FirstRecorded = &f
	}
	// The first assessment's opened events all carry its timestamp; a minute of
	// slack covers the record's own clock against the assessment's.
	isBaseline := func(at time.Time) bool {
		return !first.IsZero() && !at.After(first.Add(time.Minute))
	}
	periodOf := func(t time.Time) int {
		for i, m := range rep.Movement {
			if !t.Before(m.Start) && t.Before(m.End) {
				return i
			}
		}
		return -1
	}

	// Risk: the last assessment of each period, with how many the period had.
	type acc struct {
		last  Assessment
		count int
	}
	perPeriod := map[int]*acc{}
	for _, a := range assessments {
		i := periodOf(a.FinishedAt)
		if i < 0 {
			continue
		}
		if perPeriod[i] == nil {
			perPeriod[i] = &acc{}
		}
		perPeriod[i].count++
		if !a.FinishedAt.Before(perPeriod[i].last.FinishedAt) {
			perPeriod[i].last = a
		}
	}
	for i, m := range rep.Movement {
		a, ok := perPeriod[i]
		if !ok {
			continue
		}
		rep.Risk = append(rep.Risk, RiskPoint{
			Period: m.Period, At: a.last.FinishedAt, Assessments: a.count,
			Findings: a.last.Findings, Actionable: a.last.Actionable,
			Risk: a.last.Risk, ByClass: a.last.ByClass, ByTeam: a.last.ByTeam,
		})
	}

	days := map[int][]float64{}
	cves := map[int]map[string]bool{}
	kevs := map[int]map[string]bool{}
	for _, e := range events {
		i := periodOf(e.At)
		if i < 0 {
			continue
		}
		m := &rep.Movement[i]
		switch e.Kind {
		case KindOpened:
			if isBaseline(e.At) {
				m.Baseline++
				rep.Baseline++
				continue
			}
			m.Opened++
			if e.Payload.Snapshot != nil {
				m.split(*e.Payload.Snapshot, func(c *Counts) { c.Opened++ })
			}
		case KindResolved:
			m.Resolved++
			if snap := e.Payload.Closed; snap == nil {
				snap = e.Payload.Opened
			} else {
				if cves[i] == nil {
					cves[i], kevs[i] = map[string]bool{}, map[string]bool{}
				}
				for _, c := range snap.CVEs {
					cves[i][c.ID] = true
					if c.KEV {
						kevs[i][c.ID] = true
					}
				}
			}
			if e.Payload.Ticketed {
				m.ResolvedTicketed++
			} else {
				m.ResolvedUnticketed++
			}
			if e.Payload.DaysOpen != nil {
				days[i] = append(days[i], float64(*e.Payload.DaysOpen))
			}
			if e.Payload.Opened != nil {
				ticketed := e.Payload.Ticketed
				m.split(*e.Payload.Opened, func(c *Counts) {
					c.Resolved++
					if ticketed {
						c.ResolvedTicketed++
					}
				})
			}
		case KindLapsed:
			m.Lapsed++
			if m.LapseReasons == nil {
				m.LapseReasons = map[string]int{}
			}
			m.LapseReasons[lapseClass(e.Payload.Reason)]++
			if e.Payload.Opened != nil {
				m.split(*e.Payload.Opened, func(c *Counts) { c.Lapsed++ })
			}
		case KindReassigned:
			m.Reassigned++
		case KindChanged:
			for _, s := range e.Payload.SignalsRemoved {
				if s == SignalEPSSHigh {
					m.EPSSDecayed++
				}
			}
			for _, s := range e.Payload.SignalsAdded {
				if s == "kev" {
					m.BecameKnownExploited++
				}
			}
		case KindTicketRaised:
			m.TicketsRaised++
		case KindTicketClosed:
			m.TicketsClosed++
			if e.Payload.EvidenceAtClose != nil && !*e.Payload.EvidenceAtClose {
				m.TicketsClosedFindingOpen++
			}
			if e.Payload.Reason != "" {
				if m.TicketsClosedByTool == nil {
					m.TicketsClosedByTool = map[string]int{}
				}
				m.TicketsClosedByTool[e.Payload.Reason]++
			}
		}
	}
	for i := range rep.Movement {
		if d := days[i]; len(d) > 0 {
			sort.Float64s(d)
			med := median(d)
			rep.Movement[i].MedianDaysToResolve = &med
		}
		rep.Movement[i].CVEsResolved = len(cves[i])
		rep.Movement[i].KEVCVEsResolved = len(kevs[i])
	}
	return rep
}

// split applies fn to each classification bucket the opening snapshot falls in.
func (m *Movement) split(s Snapshot, fn func(*Counts)) {
	bump := func(mp *map[string]Counts, k string) {
		if k == "" {
			k = "none"
		}
		if *mp == nil {
			*mp = map[string]Counts{}
		}
		c := (*mp)[k]
		fn(&c)
		(*mp)[k] = c
	}
	for _, sig := range s.Signals {
		bump(&m.BySignal, sig)
	}
	bump(&m.ByRule, s.Rule)
	bump(&m.ByPriority, s.Priority)
	bump(&m.ByTeam, s.Team)
}

// lapseClass folds a lapse reason to its kind, so a report has a handful of rows
// rather than one per repository.
func lapseClass(reason string) string {
	switch {
	case reason == "":
		return "unknown"
	case contains(reason, "no longer reported"):
		return "no longer reported"
	case contains(reason, "no longer running"):
		return "no longer running"
	case contains(reason, "not checked for a newer version"):
		return "remediation not checked"
	case contains(reason, "could not be resolved"):
		return "versions unresolved"
	case contains(reason, "still has"):
		return "upgrade still available"
	case contains(reason, "liveness"):
		return "liveness not reconciled"
	}
	return "other"
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func median(sorted []float64) float64 {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

var ageBuckets = []int{7, 30, 90, 180}

func openSummary(open []State, now time.Time) OpenSummary {
	out := OpenSummary{Items: len(open), BySignal: map[string]int{}, AgeDays: map[string]int{}}
	for _, st := range open {
		if st.Current.Ticketed() {
			out.Ticketed++
		}
		if st.Missing > 0 {
			out.Missing++
		}
		for _, s := range st.Current.Signals {
			out.BySignal[s]++
		}
		out.AgeDays[ageBucket(int(now.Sub(st.OpenedAt).Hours()/24))]++
	}
	if len(out.BySignal) == 0 {
		out.BySignal = nil
	}
	if len(out.AgeDays) == 0 {
		out.AgeDays = nil
	}
	return out
}

func ageBucket(days int) string {
	prev := 0
	for _, b := range ageBuckets {
		if days < b {
			return fmt.Sprintf("%d-%d", prev, b)
		}
		prev = b
	}
	return fmt.Sprintf("%d+", prev)
}
