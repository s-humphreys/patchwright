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

// epssUrgent is the exploitation probability at which a finding is treated as
// pressing regardless of anything else. Agreed with security rather than derived:
// it is the threshold their urgency definition already uses, and having it in two
// places with two values would be worse than having it here.
const epssUrgent = 0.5

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

	// EPSSHigh counts findings carrying a CVE at or above the urgency threshold.
	// TopEPSS and TopPercentile are the worst single CVE this team holds.
	//
	// Both numbers, because either alone misleads. A score of 0.08 sounds
	// negligible and can be the 94th percentile, since almost every CVE scores
	// near zero; a high percentile with a low score is a crowded field rather than
	// a real threat. Asked for by name for vulnerability-management reporting.
	EPSSHigh      int     `json:"epss_high"`
	TopEPSS       float64 `json:"top_epss"`
	TopPercentile float64 `json:"top_epss_percentile"`

	// BaseClears and BaseTotal are the CVEs a base rebuild would remove across this
	// team's images, and the CVEs those images carry. The ratio says how much of a
	// team's queue is not really theirs to fix line by line.
	BaseClears int `json:"base_clears"`
	BaseTotal  int `json:"base_total"`

	// Unassessed counts findings the provider never looked at. A team can look
	// responsive purely because nothing scanned its images.
	Unassessed int `json:"unassessed"`
}

// Win is one base image upgrade and everything it would fix at once.
//
// The leverage in this estate is not spread evenly across teams: a handful of
// base images account for most of the CVE mass, and one rebuild clears them for
// every image built on that base. Ranking those is a to-do list; ranking teams by
// how slow they are is a league table, which tells a security engineer who to
// blame rather than what to do next.
type Win struct {
	FromRef string `json:"from_ref"`
	ToRef   string `json:"to_ref"`
	// Images is how many images sit on this base, and Teams how many owners they
	// span. A rebuild crossing eight teams is coordination; one inside a single
	// team is a morning's work.
	Images int `json:"images"`
	Teams  int `json:"teams"`
	// ImageRefs names them, so the rebuild can be scoped rather than guessed at.
	ImageRefs []string `json:"image_refs,omitempty"`
	// Clears is the CVEs the move removes across all of those images, Introduces
	// what it brings with it. Both, always: an upgrade reported only by what it
	// fixes stops being trusted the first time somebody checks.
	Clears     int `json:"clears"`
	Total      int `json:"total"`
	Introduces int `json:"introduces"`
	// KEVCleared is known-exploited CVEs among the cleared. The number that moves
	// a rebuild up a sprint.
	KEVCleared int `json:"kev_cleared"`
}

// Issue is a class of problem nobody is acting on, counted across the estate.
//
// Grouped by the NATURE of the problem rather than by owner. Each kind needs a
// different response - an escalation, a nudge, a build-pipeline change, a
// scanner fix - and a per-team split buries that under names.
type Issue struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	Count int    `json:"count"`
	// Why says what the reader should do about it, in a sentence. A count with no
	// reading is a number somebody has to interpret, and different people
	// interpret it differently.
	Why string `json:"why"`
	// Images names every affected image. All of them, not a sample: a security
	// engineer reading "15 images built on a dead line" wants the fifteen, and a
	// count they cannot expand is a number they have to take on trust.
	Images []string `json:"images,omitempty"`
	// Teams is how many owners the issue spans, for whether it is one team's
	// problem or the estate's.
	Teams int `json:"teams"`
}

// AnalyticsView is the whole page's data.
type AnalyticsView struct {
	// Wins are the base upgrades that clear the most, biggest first.
	Wins []Win `json:"wins"`
	// Issues are the things nobody is acting on, worst first.
	Issues []Issue         `json:"issues"`
	Teams  []TeamAnalytics `json:"teams"`
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
		Wins:           buildWins(findings),
		Issues:         buildIssues(findings, tickets, now),
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
	epssHigh bool
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
		}
		if v.EPSS > a.t.TopEPSS {
			a.t.TopEPSS = v.EPSS
		}
		if v.EPSSPercentile > a.t.TopPercentile {
			a.t.TopPercentile = v.EPSSPercentile
		}
		if v.EPSS >= epssUrgent {
			a.epssHigh = true
		}
	}
	if a.epssHigh {
		a.t.EPSSHigh++
		a.epssHigh = false
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

// maxWins and maxIssueExamples bound what the page shows. A ranked list stops
// being a ranking somewhere, and past a handful nobody reads it.
const (
	maxWins           = 8
	minWinCVEsCleared = 1
)

// buildWins ranks base upgrades by how much they clear across every image on them.
func buildWins(findings []model.Finding) []Win {
	type acc struct {
		w      Win
		teams  map[string]bool
		images map[string]bool
		refs   []string
	}
	byBase := map[string]*acc{}

	for i := range findings {
		f := &findings[i]
		if f.Suppressed {
			continue
		}
		d := f.BaseDiff
		if d == nil || !d.Determined || d.Clears < minWinCVEsCleared {
			continue
		}
		key := d.FromRef + " -> " + d.ToRef
		a, ok := byBase[key]
		if !ok {
			a = &acc{
				w:      Win{FromRef: d.FromRef, ToRef: d.ToRef},
				teams:  map[string]bool{},
				images: map[string]bool{},
			}
			byBase[key] = a
		}
		// Per IMAGE, not per finding: one image owned by three teams is one
		// rebuild, and counting it three times would treble the headline.
		if a.images[f.Image.Key()] {
			a.teams[f.Owner.Class+"/"+f.Owner.Team] = true
			continue
		}
		a.images[f.Image.Key()] = true
		a.refs = append(a.refs, f.Image.Ref)
		a.teams[f.Owner.Class+"/"+f.Owner.Team] = true
		a.w.Clears += d.Clears
		a.w.Total += d.Total
		a.w.Introduces += d.Introduces
		for _, v := range f.Vulns {
			if v.KEV && v.FixedByUpgrade {
				a.w.KEVCleared++
			}
		}
	}

	out := make([]Win, 0, len(byBase))
	for _, a := range byBase {
		refs := make([]string, 0, len(a.refs))
		refs = append(refs, a.refs...)
		a.w.ImageRefs = sortedCopy(refs)
		a.w.Images = len(a.images)
		a.w.Teams = len(a.teams)
		out = append(out, a.w)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Clears != out[j].Clears {
			return out[i].Clears > out[j].Clears
		}
		return out[i].Images > out[j].Images
	})
	if len(out) > maxWins {
		out = out[:maxWins]
	}
	return out
}

// issueAccumulator collects one class of problem.
type issueAccumulator struct {
	count  int
	teams  map[string]bool
	seen   map[string]bool
	images []string
}

func (a *issueAccumulator) add(f *model.Finding) {
	a.count++
	if a.teams == nil {
		a.teams = map[string]bool{}
	}
	if a.seen == nil {
		a.seen = map[string]bool{}
	}
	a.teams[f.Owner.Class+"/"+f.Owner.Team] = true
	if !a.seen[f.Image.Ref] {
		if a.seen == nil {
			a.seen = map[string]bool{}
		}
		a.seen[f.Image.Ref] = true
		a.images = append(a.images, f.Image.Ref)
	}
}

func (a *issueAccumulator) issue(key, title, why string) Issue {
	return Issue{
		Key: key, Title: title, Why: why,
		Count: a.count, Teams: len(a.teams), Images: sortedCopy(a.images),
	}
}

// buildIssues counts what is not being acted on, by the nature of the problem.
func buildIssues(findings []model.Finding, tickets map[string][]ticketRef, now time.Time) []Issue {
	var (
		kevNoFix   issueAccumulator
		kevWaiting issueAccumulator
		stale      issueAccumulator
		eol        issueAccumulator
		blind      issueAccumulator
		prStale    issueAccumulator
	)

	for i := range findings {
		f := &findings[i]
		if f.Suppressed {
			continue
		}
		upgradable := f.Upgrade != nil && f.Upgrade.Available && f.Upgrade.Actionable
		kev := false
		for _, v := range f.Vulns {
			if v.KEV {
				kev = true
				break
			}
		}
		if kev && !upgradable {
			kevNoFix.add(f)
		}
		if !f.ProviderAssessed() {
			blind.add(f)
		}
		if f.Upgrade != nil && f.Upgrade.Support != nil {
			st := f.Upgrade.Support
			if st.Known && !st.Supported {
				eol.add(f)
			}
		}
		if f.InFlight != nil && f.InFlight.Stale {
			prStale.add(f)
		}
		if !f.Actionable || !upgradable {
			continue
		}
		started := f.InFlight != nil || len(tickets[f.Image.Repository]) > 0
		if kev && !started {
			kevWaiting.add(f)
		}
		if started {
			continue
		}
		if t, ok := f.OldestVuln(); ok && int(now.Sub(t).Hours()/24) >= staleFixDays {
			stale.add(f)
		}
	}

	out := []Issue{
		kevWaiting.issue("kev-unstarted", "Known-exploited, fix available, nobody started",
			"Top of the list."),
		kevNoFix.issue("kev-no-fix", "Known-exploited, no upgrade available",
			"Needs a decision: mitigate, isolate or accept."),
		stale.issue("stale-fix", "Fix available over "+itoa(staleFixDays)+" days, untouched",
			"The software is not the blocker."),
		eol.issue("eol-base", "Built on an unmaintained line",
			"Needs a migration, not a patch. No further fix is coming."),
		prStale.issue("pr-stale", "Pull requests open past the stale threshold",
			"Work done, not landed. A review bottleneck."),
		blind.issue("unassessed", "Never assessed by the provider",
			"Zero findings here is missing data, not a clean result."),
	}
	// Empty categories are dropped: a page of zeroes trains people to skim past
	// the ones that are not zero.
	kept := out[:0]
	for _, i := range out {
		if i.Count > 0 {
			kept = append(kept, i)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Count > kept[j].Count })
	return kept
}

// sortedCopy returns the names in a stable order, so the same assessment renders
// the same list twice running.
func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
