package mcp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/analytics"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Freshness is on every answer. See the package comment for why.
type Freshness struct {
	AssessedAt string `json:"assessed_at"`
	// ProviderDataAgeDays is how old the scan provider's own newest data is, which
	// ages independently of when the assessment ran.
	ProviderDataAgeDays *int   `json:"provider_data_age_days,omitempty"`
	Version             string `json:"patchwright_version,omitempty"`
	// Ran is what this assessment was configured to do. Read it before reading any
	// zero in the answer: a stage that was never asked to run explains a zero that
	// would otherwise look like a measurement.
	Ran Configuration `json:"ran"`
}

// EstateSummary is the headline: the size of the problem, how much of it a rebuild
// would remove, and what is not being addressed.
type EstateSummary struct {
	Freshness Freshness `json:"freshness"`

	Services    int `json:"services"`
	Deployments int `json:"deployments"`
	WorkItems   int `json:"work_items"`
	// Suppressed is deployments policy has ruled out of the queue, excluded from
	// every count above. Reported rather than dropped: a suppression rule that has
	// quietly grown to cover a tenth of the estate is a finding of its own.
	Suppressed int `json:"suppressed_deployments"`

	// Coverage says how much of the estate these numbers actually describe, which
	// bounds every other figure here.
	Coverage Coverage `json:"coverage"`

	Vulnerabilities int `json:"vulnerabilities"`
	KnownExploited  int `json:"known_exploited"`

	// ClearedByRebuilds is how many of the CVEs a base rebuild would remove across
	// the estate, measured rather than estimated. Absent when no differential ran.
	ClearedByRebuilds *int `json:"cleared_by_rebuilds,omitempty"`

	// UnassessedReasons is why the coverage gap exists, in the provider's own words,
	// so it can be worked on rather than only counted.
	UnassessedReasons []UnassessedReason `json:"unassessed_reasons,omitempty"`

	// BiggestWins are the base upgrades worth doing first, and Issues the things
	// nobody is acting on. Both come from the same analytics the page shows, so a
	// tool answer and the page cannot disagree.
	BiggestWins []Win   `json:"biggest_wins,omitempty"`
	Issues      []Issue `json:"issues,omitempty"`

	Caveats []string `json:"caveats,omitempty"`
}

// Coverage is how much of the estate was actually looked at. Reported everywhere a
// total is, because a small number can mean a healthy estate or an unexamined one.
type Coverage struct {
	Assessed int `json:"assessed_deployments"`
	Scanned  int `json:"scanned_deployments"`
	Total    int `json:"total_deployments"`
	// Exposure counts deployments with ANY exposure value, which is not the same as
	// measured: where exposure_measured is false these come from the scan provider,
	// whose field can be constant. Named "reported" for that reason.
	Exposure  int `json:"deployments_with_reported_exposure"`
	BaseDiffs int `json:"deployments_with_base_differential"`
}

// Win is one base upgrade and what it buys.
type Win struct {
	Upgrade string `json:"upgrade"`
	Clears  int    `json:"clears"`
	// Introduces is reported beside Clears, always. An upgrade described only by
	// what it fixes stops being trusted the first time somebody checks.
	Introduces int `json:"introduces"`
	// KEVCleared is the number that moves a rebuild up a sprint.
	KEVCleared int      `json:"kev_cleared"`
	Services   int      `json:"services"`
	Teams      []string `json:"teams,omitempty"`
}

// Issue is a class of problem nobody is acting on.
type Issue struct {
	What     string   `json:"what"`
	Key      string   `json:"key"`
	Count    int      `json:"count"`
	Why      string   `json:"why,omitempty"`
	Services []string `json:"services,omitempty"`
}

// maxNamed bounds the lists inside a summary. A summary that names two hundred
// services is not a summary, and the per-service tools exist for the detail.
const maxNamed = 10

func freshness(a Assessment) Freshness {
	f := Freshness{Version: a.Version, Ran: configuration(a)}
	if !a.GeneratedAt.IsZero() {
		f.AssessedAt = a.GeneratedAt.UTC().Format("2006-01-02 15:04 MST")
	}
	if !a.ProviderDataNewest.IsZero() {
		d := int(a.GeneratedAt.Sub(a.ProviderDataNewest).Hours() / 24)
		if d < 0 {
			d = 0
		}
		f.ProviderDataAgeDays = &d
	}
	return f
}

func estateSummary(a Assessment) EstateSummary {
	items := a.items()
	out := EstateSummary{Freshness: freshness(a), WorkItems: len(items)}

	services := map[string]bool{}
	cves := map[string]bool{}
	kev := map[string]bool{}
	var cleared int
	var measured bool
	for _, f := range a.Findings {
		if f.Suppressed {
			out.Suppressed++
			continue
		}
		services[f.Repository] = true
		out.Deployments++
		out.Coverage.Total++
		if f.ProviderAssessed {
			out.Coverage.Assessed++
		}
		if f.Scanned {
			out.Coverage.Scanned++
		}
		if f.Exposure == "public" || f.Exposure == "internal" {
			out.Coverage.Exposure++
		}
		if f.BaseDiff != nil && f.BaseDiff.Determined {
			out.Coverage.BaseDiffs++
			measured = true
			cleared += f.BaseDiff.Clears
		}
		for _, v := range f.Vulns {
			cves[v.ID] = true
			if v.KEV {
				kev[v.ID] = true
			}
		}
	}
	out.Services = len(services)
	out.Vulnerabilities = len(cves)
	out.KnownExploited = len(kev)
	if measured {
		out.ClearedByRebuilds = &cleared
	}

	for _, w := range a.Analytics.Wins {
		if len(out.BiggestWins) == maxNamed {
			break
		}
		out.BiggestWins = append(out.BiggestWins, Win{
			Upgrade: w.FromRef + " -> " + w.ToRef, Clears: w.Clears,
			Introduces: w.Introduces, KEVCleared: w.KEVCleared,
			Services: len(w.Services), Teams: teamsOf(w.Services),
		})
	}
	for _, i := range a.Analytics.Issues {
		out.Issues = append(out.Issues, Issue{
			What: i.Title, Key: i.Key, Count: i.Count, Why: i.Why,
			Services: namesOf(i.Services, maxNamed),
		})
	}
	out.UnassessedReasons = unassessedReasons(a.active())
	out.Caveats = estateCaveats(a, out)
	return out
}

// estateCaveats states what the summary cannot support. Configuration first: an
// absent signal is explained by what was not asked for before it is described as a
// gap, because the two send a reader to different places.
func estateCaveats(a Assessment, s EstateSummary) []string {
	out := configCaveats(a, s.Coverage)
	if s.Coverage.Assessed < s.Coverage.Total {
		gap := fmt.Sprintf(
			"The scan provider never assessed %d of %d deployments; their counts are unknown, not zero.",
			s.Coverage.Total-s.Coverage.Assessed, s.Coverage.Total)
		if len(s.UnassessedReasons) > 0 {
			gap += " See unassessed_reasons for the provider's own explanation."
		}
		out = append(out, gap)
	}
	if s.Suppressed > 0 {
		out = append(out, fmt.Sprintf(
			"%d deployments are suppressed by policy and are excluded from every count here. "+
				"Suppressed means somebody decided it is not work, not that it is not vulnerable.",
			s.Suppressed))
	}
	if s.ClearedByRebuilds != nil && s.Coverage.BaseDiffs < s.Coverage.Total {
		out = append(out, fmt.Sprintf(
			"The rebuild figure covers the %d of %d deployments a base differential ran for.",
			s.Coverage.BaseDiffs, s.Coverage.Total))
	}
	return out
}

// WorstFirst is the ordered queue: what to do next, and why each row is there.
type WorstFirst struct {
	Freshness Freshness  `json:"freshness"`
	Filtered  string     `json:"filtered_by,omitempty"`
	Total     int        `json:"total_matching"`
	Items     []WorkItem `json:"items"`
	Caveats   []string   `json:"caveats,omitempty"`
}

// WorkItem is one row of that queue - a service and the change it needs.
type WorkItem struct {
	Service       string   `json:"service"`
	Team          string   `json:"team,omitempty"`
	Priority      string   `json:"priority,omitempty"`
	PriorityWhere string   `json:"priority_where,omitempty"`
	Rule          string   `json:"rule,omitempty"`
	Exposure      string   `json:"exposure"`
	Signals       []string `json:"signals,omitempty"`
	Critical      int      `json:"critical"`
	High          int      `json:"high"`
	Deployments   int      `json:"deployments"`
	Upgrade       string   `json:"upgrade,omitempty"`
	// Clears is what the upgrade would remove, when a differential measured it.
	Clears *int `json:"clears,omitempty"`
	// InFlight is a pull request already open for this change.
	InFlight string `json:"in_flight,omitempty"`
}

// worstFirst returns the queue, optionally narrowed. Every filter is exact and
// stated back in the answer, so a narrowed list is never mistaken for the estate.
func worstFirst(a Assessment, team, priority, exposure string, limit int) WorstFirst {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	out := WorstFirst{Freshness: freshness(a)}
	if team != "" {
		if resolved, candidates := matchTeam(a.items(), team); resolved != "" {
			team = resolved
		} else {
			// The filter stands and returns nothing, with the real names attached. The
			// alternative - dropping the filter and returning the estate - would hand
			// back rows the caller would report as this team's, which is worse than an
			// empty answer they can correct.
			out.Caveats = append(out.Caveats, "No team matches \""+team+
				"\", so this list is empty for that reason rather than because the team has no work. "+
				"Teams in this assessment: "+strings.Join(candidates, ", ")+".")
		}
	}
	out.Filtered = describeFilters(team, priority, exposure)

	clears := clearsByItem(a)
	for _, it := range a.items() {
		if team != "" && !strings.EqualFold(it.Team, team) {
			continue
		}
		if priority != "" && !strings.EqualFold(it.Priority, priority) {
			continue
		}
		if exposure != "" && !strings.EqualFold(it.Exposure, exposure) {
			continue
		}
		out.Total++
		if len(out.Items) >= limit {
			continue
		}
		w := WorkItem{
			Service: it.Repository, Team: it.Team, Priority: it.Priority,
			PriorityWhere: it.PriorityWhere, Rule: it.Rule, Exposure: it.Exposure,
			Signals: it.Signals, Critical: it.Critical, High: it.High,
			Deployments: it.Deployments,
		}
		if it.Upgrade != nil && it.Upgrade.Latest != "" {
			w.Upgrade = it.Upgrade.Current + " -> " + it.Upgrade.Latest
		}
		if c, ok := clears[it.Key]; ok {
			w.Clears = &c
		}
		if it.InFlight != nil {
			w.InFlight = it.InFlight.URL
		}
		out.Items = append(out.Items, w)
	}
	out.Caveats = append(out.Caveats, configCaveats(a, coverageOf(a))...)
	if out.Total > len(out.Items) {
		out.Caveats = append(out.Caveats, fmt.Sprintf(
			"%d items match; %d are shown, worst first.", out.Total, len(out.Items)))
	}
	return out
}

// coverageOf is the estate's coverage, computed once for the caveats that need it.
func coverageOf(a Assessment) Coverage {
	var c Coverage
	for _, f := range a.active() {
		c.Total++
		if f.ProviderAssessed {
			c.Assessed++
		}
		if f.Scanned {
			c.Scanned++
		}
		if f.Exposure == "public" || f.Exposure == "internal" {
			c.Exposure++
		}
		if f.BaseDiff != nil && f.BaseDiff.Determined {
			c.BaseDiffs++
		}
	}
	return c
}

func describeFilters(team, priority, exposure string) string {
	var parts []string
	for _, p := range [][2]string{{"team", team}, {"priority", priority}, {"exposure", exposure}} {
		if p[1] != "" {
			parts = append(parts, p[0]+"="+p[1])
		}
	}
	return strings.Join(parts, ", ")
}

// clearsByItem sums each work item's measured rebuild benefit, keyed the same way
// group.Items keys them so the two cannot drift apart.
func clearsByItem(a Assessment) map[string]int {
	byKey := map[string][]sink.FindingView{}
	for _, f := range a.active() {
		byKey[itemKeyOf(f)] = append(byKey[itemKeyOf(f)], f)
	}
	out := map[string]int{}
	for _, it := range a.items() {
		var total int
		var any bool
		for _, f := range byKey[it.Key] {
			if f.BaseDiff != nil && f.BaseDiff.Determined {
				any = true
				total += f.BaseDiff.Clears
			}
		}
		if any {
			out[it.Key] = total
		}
	}
	return out
}

// itemKeyOf reproduces group's item key for a finding. group does not export it,
// and duplicating the join here is preferable to widening that package's surface
// for one caller.
func itemKeyOf(f sink.FindingView) string {
	var name, latest string
	if f.Upgrade != nil {
		name, latest = f.Upgrade.Name, f.Upgrade.Latest
	}
	return strings.Join([]string{f.Owner.Team, f.Owner.Class, f.Repository, name, latest}, "|")
}

// TeamReport is one team's whole position, so a conversation with them starts from
// what they own rather than from a filtered list somebody assembled by hand.
type TeamReport struct {
	Freshness Freshness `json:"freshness"`
	Team      string    `json:"team"`

	Services      int `json:"services"`
	WorkItems     int `json:"work_items"`
	Urgent        int `json:"urgent"`
	High          int `json:"high"`
	Exposed       int `json:"exposed_services"`
	InProgress    int `json:"items_with_open_pull_request"`
	StaleInFlight int `json:"items_with_stale_pull_request"`

	// ClearedByRebuilds is what this team's rebuilds would remove, and Remaining
	// what would survive them - the two halves of the conversation.
	ClearedByRebuilds *int `json:"cleared_by_rebuilds,omitempty"`

	Top     []WorkItem `json:"top_items"`
	Caveats []string   `json:"caveats,omitempty"`
}

// teamReport resolves the team name first, so a near-miss becomes an answer rather
// than a dead end. It returns the candidates it could not choose between when it
// cannot resolve one.
func teamReport(a Assessment, team string) (TeamReport, []string, bool) {
	resolved, candidates := matchTeam(a.items(), team)
	if resolved == "" {
		return TeamReport{}, candidates, false
	}
	team = resolved
	q := worstFirst(a, team, "", "", 100)
	if q.Total == 0 {
		return TeamReport{}, candidates, false
	}
	out := TeamReport{Freshness: q.Freshness, Team: team, WorkItems: q.Total}

	services := map[string]bool{}
	var cleared int
	var measured bool
	for _, it := range a.items() {
		if !strings.EqualFold(it.Team, team) {
			continue
		}
		services[it.Repository] = true
		switch it.Priority {
		case "urgent":
			out.Urgent++
		case "high":
			out.High++
		}
		if it.Exposure == "public" {
			out.Exposed++
		}
		if it.InFlight != nil {
			out.InProgress++
			if it.InFlight.Stale {
				out.StaleInFlight++
			}
		}
	}
	for _, f := range a.active() {
		if !strings.EqualFold(f.Owner.Team, team) {
			continue
		}
		if f.BaseDiff != nil && f.BaseDiff.Determined {
			measured = true
			cleared += f.BaseDiff.Clears
		}
	}
	out.Services = len(services)
	if measured {
		out.ClearedByRebuilds = &cleared
	}
	if len(q.Items) > maxNamed {
		out.Top = q.Items[:maxNamed]
	} else {
		out.Top = q.Items
	}
	out.Caveats = append(out.Caveats, configCaveats(a, Coverage{
		Scanned: coveredBy(a, team), Total: q.Total, BaseDiffs: measuredFor(a, team),
	})...)
	if out.StaleInFlight > 0 {
		out.Caveats = append(out.Caveats, fmt.Sprintf(
			"%d open pull requests are stale: opened long ago and never merged, so they are not progress.",
			out.StaleInFlight))
	}
	return out, nil, true
}

// coveredBy and measuredFor are this team's share of the two coverage questions, so
// its caveats describe its own queue rather than the estate's.
func coveredBy(a Assessment, team string) int {
	var n int
	for _, f := range a.active() {
		if strings.EqualFold(f.Owner.Team, team) && f.Scanned {
			n++
		}
	}
	return n
}

func measuredFor(a Assessment, team string) int {
	var n int
	for _, f := range a.active() {
		if strings.EqualFold(f.Owner.Team, team) && f.BaseDiff != nil && f.BaseDiff.Determined {
			n++
		}
	}
	return n
}

// CVEReport is one CVE across the estate: who has it, whether it is fixable, and
// whether rebuilding removes it.
type CVEReport struct {
	Freshness Freshness `json:"freshness"`
	ID        string    `json:"id"`

	Severity       string  `json:"severity,omitempty"`
	CVSS           float64 `json:"cvss,omitempty"`
	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	KnownExploited bool    `json:"known_exploited"`
	Reference      string  `json:"reference"`

	Deployments int      `json:"deployments"`
	Services    []string `json:"services"`
	Teams       []string `json:"teams,omitempty"`
	// ExposedServices are the affected services reachable from the internet.
	ExposedServices []string `json:"exposed_services,omitempty"`

	FixAvailable bool     `json:"fix_available"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	Packages     []string `json:"packages,omitempty"`
	// ClearedByRebuild counts deployments where the recommended base upgrade
	// removes this CVE; StaysAfterRebuild counts those where it does not.
	ClearedByRebuild  int `json:"cleared_by_rebuild"`
	StaysAfterRebuild int `json:"stays_after_rebuild"`

	Caveats []string `json:"caveats,omitempty"`
}

func cveReport(a Assessment, id string) (CVEReport, bool) {
	id = strings.ToUpper(strings.TrimSpace(id))
	out := CVEReport{Freshness: freshness(a), ID: id,
		Reference: "https://www.cve.org/CVERecord?id=" + id}

	services := map[string]bool{}
	teams := map[string]bool{}
	exposed := map[string]bool{}
	pkgs := map[string]bool{}
	var found bool
	for _, f := range a.Findings {
		for _, v := range f.Vulns {
			if strings.ToUpper(v.ID) != id {
				continue
			}
			found = true
			out.Deployments++
			services[f.Repository] = true
			if f.Owner.Team != "" {
				teams[f.Owner.Team] = true
			}
			if f.Exposure == "public" {
				exposed[f.Repository] = true
			}
			out.Severity, out.CVSS = v.Severity, v.CVSS
			if v.EPSS > out.EPSS {
				out.EPSS, out.EPSSPercentile = v.EPSS, v.EPSSPercentile
			}
			out.KnownExploited = out.KnownExploited || v.KEV
			if v.FixAvailable {
				out.FixAvailable = true
				out.FixedVersion = v.FixedVersion
			}
			for _, p := range v.Packages {
				pkgs[p.Name] = true
			}
			if v.OriginDetermined {
				if v.FixedByUpgrade {
					out.ClearedByRebuild++
				} else {
					out.StaysAfterRebuild++
				}
			}
		}
	}
	if !found {
		return CVEReport{}, false
	}
	out.Services = keys(services, maxNamed)
	out.Teams = keys(teams, maxNamed)
	out.ExposedServices = keys(exposed, maxNamed)
	out.Packages = keys(pkgs, maxNamed)

	out.Caveats = append(out.Caveats, configCaveats(a, Coverage{
		Scanned: out.Deployments, Total: out.Deployments,
		BaseDiffs: out.ClearedByRebuild + out.StaysAfterRebuild,
	})...)
	if out.ClearedByRebuild+out.StaysAfterRebuild < out.Deployments {
		out.Caveats = append(out.Caveats, fmt.Sprintf(
			"A base differential covered %d of %d affected deployments; for the rest, whether a rebuild removes this is unknown.",
			out.ClearedByRebuild+out.StaysAfterRebuild, out.Deployments))
	}
	if !out.FixAvailable {
		out.Caveats = append(out.Caveats, "No fixed version is published for this CVE in the scanned packages, so an upgrade may not resolve it.")
	}
	return out, true
}

func teamsOf(services []analytics.ServiceCount) []string {
	seen := map[string]bool{}
	for _, s := range services {
		if s.Team != "" {
			seen[s.Team] = true
		}
	}
	return keys(seen, maxNamed)
}

func namesOf(services []analytics.ServiceCount, limit int) []string {
	out := make([]string, 0, len(services))
	for _, s := range services {
		if len(out) == limit {
			break
		}
		out = append(out, s.Service)
	}
	return out
}

func keys(m map[string]bool, limit int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
