package mcp

import (
	"fmt"
	"sort"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// PolicyRules are the rules this assessment was evaluated against, as configured.
//
// Carried alongside the findings because a report needs the rules that matched
// NOTHING as much as the ones that matched. "We have a rule for exploited criticals
// and it caught none this month" and "we have no such rule" are the same empty space
// in a report built only from findings, and they are opposite conclusions.
type PolicyRules struct {
	Actionable []PolicyRuleDef
	Suppress   []PolicyRuleDef
}

// PolicyRuleDef is one configured rule. When is included because a reviewer asked to
// approve a suppression needs to see what it actually covers, not only its name -
// and a name is chosen by whoever wrote the rule, so it can flatter it.
type PolicyRuleDef struct {
	Name     string
	When     string
	Priority string
	Until    string
}

// PolicyReport is the estate measured against the organisation's OWN policy, by the
// names its own rules carry.
//
// Distinct from estate_summary's issues, which are patchwright's judgement of what
// is worth acting on - known-exploited, stale fixes, end-of-life bases. Those are a
// good default and a bad basis for a periodic report, because the thing a security
// team signs off is its own policy: if the rules say a critical in pre-production is
// medium, the report has to say that too, or it is reporting somebody else's
// standard back at them.
//
// Everything here is a count of what the configured rules decided. Nothing in it is
// patchwright's opinion about whether those rules are the right ones.
type PolicyReport struct {
	Freshness Freshness `json:"freshness"`

	// Scope is what the counts are over, so no figure below is read against a
	// denominator somebody guessed at.
	Scope Scope `json:"scope"`
	// Coverage bounds every count here. A rule matching nothing on an image nobody
	// assessed has not cleared it.
	//
	// Over UNSUPPRESSED deployments, matching estate_summary so the two cannot
	// disagree in front of the same reader. Its total is therefore
	// verdicts.actionable + verdicts.no_rule_matched, not scope.deployments.
	Coverage Coverage `json:"coverage"`

	// Verdicts is the three-way split of every deployment by what policy decided.
	Verdicts Verdicts `json:"verdicts"`

	// ActionableRules is what the rules found, in the order the rules are evaluated
	// rather than by size. That order is the policy's own statement of severity, and
	// re-sorting by count would put the biggest bucket at the top of a report whose
	// point is the sharpest one.
	ActionableRules []RuleStat `json:"actionable_rules"`
	// SuppressRules is what policy decided is not work, and when each decision
	// lapses. A suppression is an accepted risk, so this is the part of the report
	// somebody has to actively agree with.
	SuppressRules []SuppressStat `json:"suppress_rules"`

	// ByPriority aggregates the same findings by the priority labels the config
	// defines, whatever those are.
	ByPriority []PriorityStat `json:"by_priority"`
	// ByTeam is the same split per owning team, for the accountability half of a
	// review.
	ByTeam []TeamPolicyStat `json:"by_team"`

	// Unmatched is the findings no rule had an opinion about. See Verdicts.
	Unmatched Unmatched `json:"unmatched"`

	Caveats []string `json:"caveats,omitempty"`
}

// Scope is the denominator for everything in the report.
type Scope struct {
	Deployments int `json:"deployments"`
	Services    int `json:"services"`
	// WorkItems is the unit a ticket covers - one service and one upgrade - which is
	// what a queue length means to a team. Deployments is what a coverage percentage
	// means. They are different numbers on purpose.
	WorkItems int `json:"work_items"`
	Teams     int `json:"teams"`
}

// Verdicts partitions every deployment by what policy decided about it. The three
// add up to Scope.Deployments, so a reader can check the arithmetic.
type Verdicts struct {
	Actionable int `json:"actionable"`
	Suppressed int `json:"suppressed"`
	// NoRuleMatched is neither queued nor accepted: policy has no opinion. It is
	// reported as a first-class number because it is invisible everywhere else - it
	// is not in the queue and it is not in the suppression list - and a rule set
	// with a large one is not covering the estate it is supposed to govern.
	NoRuleMatched int `json:"no_rule_matched"`
}

// RuleStat is one configured actionable rule and what it caught.
type RuleStat struct {
	Name     string `json:"name"`
	Priority string `json:"priority"`
	// When is the rule's condition, so the report can be read without the config
	// file open beside it.
	When string `json:"when,omitempty"`

	Deployments int `json:"deployments"`
	Services    int `json:"services"`
	Teams       int `json:"teams"`
	// TopServices names the worst affected, bounded. Not the full list: a report
	// that names two hundred services gets pasted somewhere as though it were a work
	// list, and worst_first is the tool for that.
	TopServices []string `json:"top_services,omitempty"`

	// Matched is false when the rule caught nothing. Reported explicitly rather than
	// left as a zero, because a rule that fires on nothing is either good news or a
	// rule that no longer matches anything it was written for, and the two are worth
	// telling apart deliberately.
	Matched bool `json:"matched"`
}

// SuppressStat is one suppression and the risk it is currently holding.
type SuppressStat struct {
	Name        string   `json:"name"`
	When        string   `json:"when,omitempty"`
	Deployments int      `json:"deployments"`
	Services    int      `json:"services"`
	TopServices []string `json:"top_services,omitempty"`

	// Until is the date the decision lapses, Expired whether it already has, and
	// ExpiresInDays how long is left.
	//
	// A suppression with no expiry is an accepted risk nobody will ever revisit,
	// which is why it is called out rather than only left blank: on a monthly review
	// that is the single most useful thing this report can point at.
	Until         string `json:"until,omitempty"`
	Expired       bool   `json:"expired,omitempty"`
	ExpiresInDays *int   `json:"expires_in_days,omitempty"`
	NoExpiry      bool   `json:"no_expiry,omitempty"`
}

// PriorityStat is one priority label and how much sits at it.
type PriorityStat struct {
	Priority    string `json:"priority"`
	Deployments int    `json:"deployments"`
	Services    int    `json:"services"`
	WorkItems   int    `json:"work_items"`
}

// TeamPolicyStat is one team's position against the policy.
type TeamPolicyStat struct {
	Team  string `json:"team"`
	Class string `json:"class"`

	Actionable    int `json:"actionable"`
	Suppressed    int `json:"suppressed"`
	NoRuleMatched int `json:"no_rule_matched"`
	// ByPriority is this team's actionable split, keyed by the config's own labels.
	ByPriority map[string]int `json:"by_priority,omitempty"`
}

// Unmatched is what no rule spoke to.
type Unmatched struct {
	Deployments int      `json:"deployments"`
	Services    int      `json:"services"`
	TopServices []string `json:"top_services,omitempty"`
	// WithCriticals is how many of them carry a critical the provider reported.
	// Without it the number reads as harmless leftovers; with it, it is the count of
	// known criticals the policy declined to have an opinion about.
	WithCriticals int `json:"with_criticals"`
}

// expiringSoon is the window a monthly review should see coming. Anything shorter
// means a suppression can be raised, lapse and return to the queue entirely between
// two reports, which is the one thing a periodic report exists to prevent.
const expiringSoon = 45 * 24 * time.Hour

// NewPolicyReport builds the report. Exported because the HTTP API serves the same
// thing at /api/v1/policy: a report a security team signs off is not something to
// have two implementations of, and the caveats are the half that would drift.
func NewPolicyReport(a Assessment, now time.Time) PolicyReport {
	out := PolicyReport{Freshness: freshness(a), Coverage: coverageOf(a)}

	services := map[string]bool{}
	teams := map[string]bool{}
	byRule := map[string]*ruleAcc{}
	bySuppress := map[string]*ruleAcc{}
	byPriority := map[string]*ruleAcc{}
	byTeam := map[string]*TeamPolicyStat{}
	var teamOrder []string
	var unmatched ruleAcc

	for i := range a.Findings {
		f := &a.Findings[i]
		services[f.Repository] = true
		if f.Owner.Team != "" {
			teams[f.Owner.Team] = true
		}

		key := f.Owner.Class + "\x00" + f.Owner.Team
		t := byTeam[key]
		if t == nil {
			t = &TeamPolicyStat{Team: f.Owner.Team, Class: f.Owner.Class, ByPriority: map[string]int{}}
			byTeam[key] = t
			teamOrder = append(teamOrder, key)
		}

		switch {
		case f.Suppressed:
			out.Verdicts.Suppressed++
			t.Suppressed++
			acc(bySuppress, f.Rule).add(f)
		case f.Actionable:
			out.Verdicts.Actionable++
			t.Actionable++
			t.ByPriority[f.Priority]++
			acc(byRule, f.Rule).add(f)
			acc(byPriority, f.Priority).add(f)
		default:
			// Not suppressed and not actionable: no rule matched. The finding exists,
			// it may carry criticals, and nothing in the policy speaks to it.
			out.Verdicts.NoRuleMatched++
			t.NoRuleMatched++
			unmatched.add(f)
			if f.Counts["critical"] > 0 {
				out.Unmatched.WithCriticals++
			}
		}
	}

	items := a.items()
	itemsByPriority := map[string]int{}
	for _, it := range items {
		itemsByPriority[it.Priority]++
	}

	out.Scope = Scope{
		Deployments: len(a.Findings), Services: len(services),
		WorkItems: len(items), Teams: len(teams),
	}

	// Configured order, not size. See PolicyReport.ActionableRules.
	for _, r := range a.Policy.Actionable {
		st := RuleStat{Name: r.Name, Priority: r.Priority, When: r.When}
		if got := byRule[r.Name]; got != nil {
			st.Deployments, st.Services, st.Teams = got.count, len(got.services), len(got.teams)
			st.TopServices = got.top()
			st.Matched = true
		}
		out.ActionableRules = append(out.ActionableRules, st)
	}
	// A rule that decided findings but is not in the configured set. It can only mean
	// the config changed after this assessment ran, and dropping it silently would
	// make the rule counts fail to add up to the actionable total.
	out.ActionableRules = append(out.ActionableRules, orphans(byRule, a.Policy.Actionable)...)

	for _, r := range a.Policy.Suppress {
		st := SuppressStat{Name: r.Name, When: r.When, Until: r.Until}
		if got := bySuppress[r.Name]; got != nil {
			st.Deployments, st.Services = got.count, len(got.services)
			st.TopServices = got.top()
		}
		switch {
		case r.Until == "":
			st.NoExpiry = true
		default:
			if end, err := time.Parse("2006-01-02", r.Until); err == nil {
				// End of the named day, matching config.PolicyRule.Expiry: a rule
				// expiring today still applies today.
				end = end.AddDate(0, 0, 1)
				if !now.Before(end) {
					st.Expired = true
				} else {
					d := int(end.Sub(now).Hours() / 24)
					st.ExpiresInDays = &d
				}
			}
		}
		out.SuppressRules = append(out.SuppressRules, st)
	}

	for p, got := range byPriority {
		out.ByPriority = append(out.ByPriority, PriorityStat{
			Priority: p, Deployments: got.count, Services: len(got.services),
			WorkItems: itemsByPriority[p],
		})
	}
	sort.Slice(out.ByPriority, func(i, j int) bool {
		ri, rj := model.PriorityRank(out.ByPriority[i].Priority), model.PriorityRank(out.ByPriority[j].Priority)
		if ri != rj {
			return ri > rj
		}
		return out.ByPriority[i].Priority < out.ByPriority[j].Priority
	})

	for _, k := range teamOrder {
		out.ByTeam = append(out.ByTeam, *byTeam[k])
	}
	sort.SliceStable(out.ByTeam, func(i, j int) bool {
		if out.ByTeam[i].Actionable != out.ByTeam[j].Actionable {
			return out.ByTeam[i].Actionable > out.ByTeam[j].Actionable
		}
		return out.ByTeam[i].Team < out.ByTeam[j].Team
	})

	out.Unmatched.Deployments = unmatched.count
	out.Unmatched.Services = len(unmatched.services)
	out.Unmatched.TopServices = unmatched.top()

	out.Caveats = policyCaveats(a, out)
	return out
}

// orphans reports rules that decided findings but are no longer configured.
func orphans(byRule map[string]*ruleAcc, configured []PolicyRuleDef) []RuleStat {
	known := make(map[string]bool, len(configured))
	for _, r := range configured {
		known[r.Name] = true
	}
	var out []RuleStat
	for name, got := range byRule {
		if known[name] || name == "" {
			continue
		}
		out = append(out, RuleStat{
			Name: name, Deployments: got.count, Services: len(got.services),
			Teams: len(got.teams), TopServices: got.top(), Matched: true,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ruleAcc collects what one rule caught.
type ruleAcc struct {
	count    int
	services map[string]int
	teams    map[string]bool
}

func acc(m map[string]*ruleAcc, key string) *ruleAcc {
	if m[key] == nil {
		m[key] = &ruleAcc{}
	}
	return m[key]
}

func (r *ruleAcc) add(f *sink.FindingView) {
	r.count++
	if r.services == nil {
		r.services = map[string]int{}
		r.teams = map[string]bool{}
	}
	r.services[f.Repository]++
	r.teams[f.Owner.Class+"/"+f.Owner.Team] = true
}

// top names the worst-affected services, most deployments first, bounded.
func (r *ruleAcc) top() []string {
	type sc struct {
		name string
		n    int
	}
	all := make([]sc, 0, len(r.services))
	for name, n := range r.services {
		all = append(all, sc{name, n})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].name < all[j].name
	})
	out := make([]string, 0, maxNamed)
	for _, s := range all {
		if len(out) == maxNamed {
			break
		}
		out = append(out, s.name)
	}
	return out
}

// policyCaveats states what this report cannot support. Ordered by how badly each
// one would mislead somebody signing the report off.
func policyCaveats(a Assessment, r PolicyReport) []string {
	// First, always: the report is a photograph, and it will be read as a film.
	out := []string{
		"This is the state of the estate at the moment the assessment ran, not a record of " +
			"what happened over any period. It cannot say what was raised, fixed or regressed " +
			"since the last report - patchwright keeps no history.",
	}
	out = append(out, configCaveats(a, r.Coverage)...)

	if len(a.Policy.Actionable) == 0 && len(a.Policy.Suppress) == 0 {
		out = append(out, "The rule definitions were not available to this report, so rules that "+
			"matched NOTHING cannot be listed. A rule missing from actionable_rules here may be "+
			"configured and quiet, or may not exist at all.")
	}
	if r.Coverage.Assessed < r.Coverage.Total {
		out = append(out, fmt.Sprintf(
			"%d of %d deployments were never assessed by the scan provider. A rule that did not "+
				"match one of those has not cleared it: there was nothing for it to match on.",
			r.Coverage.Total-r.Coverage.Assessed, r.Coverage.Total))
	}
	if r.Verdicts.NoRuleMatched > 0 {
		msg := fmt.Sprintf(
			"%d deployments matched no rule at all, so they appear in neither the queue nor the "+
				"suppression list.", r.Verdicts.NoRuleMatched)
		if r.Unmatched.WithCriticals > 0 {
			msg += fmt.Sprintf(" %d of them carry a critical the provider reported.", r.Unmatched.WithCriticals)
		}
		out = append(out, msg)
	}
	var expired, noExpiry int
	for _, s := range r.SuppressRules {
		if s.Expired {
			expired++
		}
		if s.NoExpiry && s.Deployments > 0 {
			noExpiry++
		}
	}
	if expired > 0 {
		out = append(out, fmt.Sprintf(
			"%d suppression rules have lapsed. The findings they were hiding are back in the "+
				"queue, so a rise since the last report may be a policy decision expiring rather "+
				"than the estate getting worse.", expired))
	}
	if noExpiry > 0 {
		out = append(out, fmt.Sprintf(
			"%d suppression rules holding findings have no expiry date, so nothing will ever "+
				"bring them back for review. Accepted risk with no expiry is accepted risk forever.",
			noExpiry))
	}
	return out
}
