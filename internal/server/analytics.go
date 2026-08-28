package server

import (
	"math"
	"sort"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// Analytics for a security engineer asking "who is not moving, and on what".
//
// The queue answers "what is wrong right now". It cannot answer "is this team
// working through it or sitting on it", which is the question behind most of the
// asks that reach a security team - and the one people currently answer by
// eyeballing a table and forming an impression.
//
// Everything here is computed from data the assessment already has. Where a
// question needs data we do not collect, the field says so rather than being
// approximated: an invented responsiveness number would be acted on by someone
// deciding which team to chase.

// ageBuckets are the age bands findings are counted into, in days. Open-ended at
// the top: the tail is the interesting part, and a bucket that closes hides it.
var ageBuckets = []int{7, 30, 90, 180}

// staleFixDays is when an available fix that nobody has started becomes a
// finding about the team rather than about the software.
//
// Thirty days is a month of releases: long enough that a team shipping normally
// would have picked up a base image rebuild in passing, short enough to catch a
// queue nobody is reading.
const staleFixDays = 30

// TeamAnalytics is one team's responsiveness.
type TeamAnalytics struct {
	Class string `json:"class"`
	Team  string `json:"team"`

	Findings   int `json:"findings"`
	Actionable int `json:"actionable"`

	// MedianAgeDays and P90AgeDays are over ACTIONABLE findings, dated from the
	// oldest CVE each carries: an image carrying something since June has been
	// exposed since June, whatever arrived later. Null when nothing here is dated,
	// which happens without an age source and is not the same as "new".
	MedianAgeDays *int `json:"median_age_days"`
	P90AgeDays    *int `json:"p90_age_days"`

	// AgeBuckets counts actionable findings by how long they have been carrying
	// their oldest CVE.
	AgeBuckets map[string]int `json:"age_buckets"`

	// Fixable is actionable findings with an upgrade available. Unstarted is the
	// subset with no open pull request and no open ticket - nobody has begun.
	// StaleUnstarted is Unstarted older than the threshold, which is the sharpest
	// single signal here: a fix has existed for a month and nothing has moved.
	Fixable        int `json:"fixable"`
	Unstarted      int `json:"unstarted"`
	StaleUnstarted int `json:"stale_unstarted"`

	// InFlight counts findings with an open pull request that would apply the
	// upgrade. InFlightStale counts those open past the configured threshold, and
	// InFlightMedianDays how long they have been open. A high in-flight count with
	// a high median is a review bottleneck, not an engagement problem, and the two
	// need different conversations.
	InFlight           int  `json:"in_flight"`
	InFlightStale      int  `json:"in_flight_stale"`
	InFlightMedianDays *int `json:"in_flight_median_days"`

	// TicketsOpen counts findings with an open ticket. TicketsUntouched counts
	// those still in Jira's "new" category: raised and not picked up. Resolution
	// time is deliberately absent - see AnalyticsNotes.
	TicketsOpen      int `json:"tickets_open"`
	TicketsUntouched int `json:"tickets_untouched"`

	// KEV is findings carrying a known-exploited CVE, and KEVFixable those with an
	// upgrade available. The gap between them is what a security team escalates on.
	KEV        int `json:"kev"`
	KEVFixable int `json:"kev_fixable"`

	// BaseClears and BaseTotal are the CVEs a base rebuild would remove across this
	// team's images, and the CVEs those images carry. The ratio says how much of a
	// team's queue is not really theirs to fix line by line.
	BaseClears int `json:"base_clears"`
	BaseTotal  int `json:"base_total"`

	// Unassessed counts findings the provider never looked at. A team can look
	// responsive purely because nothing scanned its images.
	Unassessed int `json:"unassessed"`
}

// AnalyticsView is the whole page's data.
type AnalyticsView struct {
	Teams []TeamAnalytics `json:"teams"`
	// Estate is the same shape summed over every team, so a row can be read
	// against the whole rather than in isolation.
	Estate TeamAnalytics `json:"estate"`
	// AgeBucketOrder names the buckets in order, so a consumer does not have to
	// sort map keys that are not sortable as strings.
	AgeBucketOrder []string `json:"age_bucket_order"`
	// Notes are the questions this page is asked that the data cannot answer.
	// Present in the payload rather than only in the UI: an API consumer building
	// its own dashboard needs to know what is missing as much as the page does.
	Notes []string `json:"notes"`
	// StaleFixDays is the threshold behind StaleUnstarted, reported so a reader
	// knows what "stale" meant rather than inferring it.
	StaleFixDays int `json:"stale_fix_days"`
}

// analyticsNotes records what this page cannot say, and why.
//
// Stated rather than omitted. A dashboard with no mention of ticket resolution
// time reads as a dashboard whose author did not think of it; one that says the
// data is not collected tells a reader where to look next.
var analyticsNotes = []string{
	"Ticket resolution time is not shown: the tracker index holds only open tickets, " +
		"and carries no created or resolved date. Measuring it needs those fields fetched " +
		"and closed tickets indexed.",
	"Ages are dated from each finding's oldest CVE, which needs an age source. Without " +
		"one every age is absent rather than zero.",
	"A team with unassessed images can look responsive because nothing scanned them. " +
		"The unassessed column is there to be read alongside the rest.",
}

// buildAnalytics computes per-team responsiveness from the cached assessment.
func buildAnalytics(findings []model.Finding, tickets map[string][]ticketRef, now time.Time) AnalyticsView {
	byTeam := map[string]*teamAccumulator{}
	estate := newAccumulator("", "")

	for i := range findings {
		f := &findings[i]
		if f.Suppressed {
			continue
		}
		key := f.Owner.Class + "\x00" + f.Owner.Team
		acc, ok := byTeam[key]
		if !ok {
			acc = newAccumulator(f.Owner.Class, f.Owner.Team)
			byTeam[key] = acc
		}
		acc.add(f, tickets, now)
		estate.add(f, tickets, now)
	}

	out := AnalyticsView{
		AgeBucketOrder: bucketNames(),
		Notes:          analyticsNotes,
		StaleFixDays:   staleFixDays,
		Estate:         estate.result(),
	}
	for _, acc := range byTeam {
		out.Teams = append(out.Teams, acc.result())
	}
	// Worst first, by the thing the page exists to surface: fixes nobody has
	// started, then sheer age, then size. A team sorted to the top should be the
	// one worth a conversation.
	sort.Slice(out.Teams, func(i, j int) bool {
		a, b := out.Teams[i], out.Teams[j]
		if a.StaleUnstarted != b.StaleUnstarted {
			return a.StaleUnstarted > b.StaleUnstarted
		}
		ai, bi := deref(a.MedianAgeDays), deref(b.MedianAgeDays)
		if ai != bi {
			return ai > bi
		}
		return a.Actionable > b.Actionable
	})
	return out
}

func deref(v *int) int {
	if v == nil {
		return -1
	}
	return *v
}

type teamAccumulator struct {
	t        TeamAnalytics
	ages     []int
	prAgeDay []int
}

func newAccumulator(class, team string) *teamAccumulator {
	return &teamAccumulator{t: TeamAnalytics{
		Class: class, Team: team, AgeBuckets: map[string]int{},
	}}
}

func (a *teamAccumulator) add(f *model.Finding, tickets map[string][]ticketRef, now time.Time) {
	a.t.Findings++
	if !f.ProviderAssessed() {
		a.t.Unassessed++
	}
	if d := f.BaseDiff; d != nil {
		a.t.BaseClears += d.Clears
		a.t.BaseTotal += d.Total
	}
	kev := false
	for _, v := range f.Vulns {
		if v.KEV {
			kev = true
			break
		}
	}
	upgradable := f.Upgrade != nil && f.Upgrade.Available && f.Upgrade.Actionable
	if kev {
		a.t.KEV++
		if upgradable {
			a.t.KEVFixable++
		}
	}
	if !f.Actionable {
		return
	}
	a.t.Actionable++

	age := -1
	if t, ok := f.OldestVuln(); ok {
		age = int(now.Sub(t).Hours() / 24)
		a.ages = append(a.ages, age)
		a.t.AgeBuckets[bucketFor(age)]++
	}

	open := tickets[f.Image.Repository]
	hasTicket := len(open) > 0
	if hasTicket {
		a.t.TicketsOpen++
		untouched := true
		for _, tk := range open {
			if tk.Category != "" && tk.Category != "new" {
				untouched = false
				break
			}
		}
		if untouched {
			a.t.TicketsUntouched++
		}
	}

	if f.InFlight != nil {
		a.t.InFlight++
		if f.InFlight.Stale {
			a.t.InFlightStale++
		}
		a.prAgeDay = append(a.prAgeDay, int(now.Sub(f.InFlight.Opened).Hours()/24))
	}

	if !upgradable {
		return
	}
	a.t.Fixable++
	if f.InFlight == nil && !hasTicket {
		a.t.Unstarted++
		// Only counted as stale when the age is KNOWN. Without an age source an
		// unstarted fix is not evidence of anything, and counting it as stale
		// would manufacture a signal out of missing data.
		if age >= staleFixDays {
			a.t.StaleUnstarted++
		}
	}
}

func (a *teamAccumulator) result() TeamAnalytics {
	out := a.t
	out.MedianAgeDays = percentile(a.ages, 50)
	out.P90AgeDays = percentile(a.ages, 90)
	out.InFlightMedianDays = percentile(a.prAgeDay, 50)
	return out
}

// percentile returns the p-th percentile, or nil when there is nothing to
// measure. Nil rather than zero: "no dated findings" and "everything found
// today" are different, and zero reads as the second.
func percentile(vals []int, p int) *int {
	if len(vals) == 0 {
		return nil
	}
	s := append([]int(nil), vals...)
	sort.Ints(s)
	// Nearest-rank: with a handful of findings an interpolated percentile invents
	// a value between two real ones, and these are counts of days on real images.
	rank := int(math.Ceil(float64(p) / 100 * float64(len(s))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(s) {
		rank = len(s)
	}
	v := s[rank-1]
	return &v
}

func bucketNames() []string {
	out := make([]string, 0, len(ageBuckets)+1)
	prev := 0
	for _, b := range ageBuckets {
		out = append(out, bucketLabel(prev, b))
		prev = b
	}
	return append(out, bucketLabel(prev, -1))
}

func bucketLabel(from, to int) string {
	if to < 0 {
		return itoa(from) + "d+"
	}
	if from == 0 {
		return "0-" + itoa(to) + "d"
	}
	return itoa(from) + "-" + itoa(to) + "d"
}

func bucketFor(age int) string {
	prev := 0
	for _, b := range ageBuckets {
		if age < b {
			return bucketLabel(prev, b)
		}
		prev = b
	}
	return bucketLabel(prev, -1)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}
