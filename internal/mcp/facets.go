package mcp

import (
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/group"
)

// Facets is the vocabulary of this assessment: the team names, priorities, exposures
// and classes that actually appear, with counts.
//
// It exists because a miss was not recoverable. Asked about "the payments team", a
// model called team_report("payments"), got nothing, and had to come back and ask
// what the team was called - when the assessment knew the answer all along. One call
// here turns a guess into a lookup, and a wrong guess into a correction rather than a
// dead end.
//
// Counts are included so a reader can tell a real owner from a stray label: a team
// with one work item is usually a typo in ownership config, not a team.
type Facets struct {
	Freshness Freshness `json:"freshness"`

	Teams      []Facet `json:"teams"`
	Classes    []Facet `json:"owner_classes"`
	Priorities []Facet `json:"priorities"`
	Exposures  []Facet `json:"exposures"`
	Signals    []Facet `json:"signals"`

	// Unattributed is work items with no owning team. Reported as its own number
	// because it is the reason a team's total can be smaller than it should be, and
	// it is nobody's queue until somebody fixes ownership.
	Unattributed int `json:"unattributed_work_items"`

	Caveats []string `json:"caveats,omitempty"`
}

// Facet is one value and how many work items carry it.
type Facet struct {
	Value string `json:"value"`
	Items int    `json:"items"`
}

func facets(a Assessment) Facets {
	out := Facets{Freshness: freshness(a)}
	teams, classes, priorities, exposures, signals := counter{}, counter{}, counter{}, counter{}, counter{}
	for _, it := range a.items() {
		if it.Team == "" {
			out.Unattributed++
		} else {
			teams.add(it.Team)
		}
		classes.add(it.Class)
		priorities.add(it.Priority)
		exposures.add(it.Exposure)
		for _, s := range it.Signals {
			signals.add(s)
		}
	}
	out.Teams = teams.sorted()
	out.Classes = classes.sorted()
	out.Priorities = priorities.sorted()
	out.Exposures = exposures.sorted()
	out.Signals = signals.sorted()
	if out.Unattributed > 0 {
		out.Caveats = append(out.Caveats, "Some work items have no owning team, so no team_report includes "+
			"them. They are unowned rather than unproblematic.")
	}
	return out
}

type counter map[string]int

func (c counter) add(v string) {
	if v != "" {
		c[v]++
	}
}

// sorted returns the values commonest first, which is the order somebody scanning
// for "which of these is the team I meant" wants.
func (c counter) sorted() []Facet {
	out := make([]Facet, 0, len(c))
	for v, n := range c {
		out = append(out, Facet{Value: v, Items: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Items != out[j].Items {
			return out[i].Items > out[j].Items
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// matchTeam resolves a team name the way somebody says it out loud rather than the
// way ownership config spells it: case-insensitively, and by substring when nothing
// matches exactly, so "payments" finds "payments-platform".
//
// Exact wins outright. A substring match is accepted only when it is unambiguous -
// answering for one of three candidate teams would be worse than saying so, because
// the answer would look authoritative and be about somebody else's queue.
func matchTeam(items []group.Item, want string) (resolved string, candidates []string) {
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" {
		return "", nil
	}
	seen := map[string]bool{}
	var all []string
	for _, it := range items {
		if it.Team == "" || seen[it.Team] {
			continue
		}
		seen[it.Team] = true
		all = append(all, it.Team)
	}
	sort.Strings(all)

	for _, t := range all {
		if strings.EqualFold(t, want) {
			return t, nil
		}
	}
	for _, t := range all {
		if strings.Contains(strings.ToLower(t), want) {
			candidates = append(candidates, t)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) == 0 {
		// Nothing like it: hand back the whole vocabulary rather than nothing, so the
		// caller can correct itself instead of coming back to ask.
		candidates = all
	}
	if len(candidates) > maxNamed {
		candidates = candidates[:maxNamed]
	}
	return "", candidates
}

// matchService resolves a service name the same way, and for the same reason.
func matchService(a Assessment, want string) (candidates []string) {
	want = strings.ToLower(strings.TrimSpace(want))
	seen := map[string]bool{}
	for _, f := range a.Findings {
		repo := f.Repository
		if seen[repo] {
			continue
		}
		if strings.Contains(strings.ToLower(repo), want) {
			seen[repo] = true
			candidates = append(candidates, repo)
		}
	}
	sort.Strings(candidates)
	if len(candidates) > maxNamed {
		candidates = candidates[:maxNamed]
	}
	return candidates
}
