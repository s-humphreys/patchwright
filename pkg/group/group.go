// Package group collapses findings into the units people act on: one piece of work
// per service and upgrade target, and one row per CVE across the estate.
//
// Both are aggregations of the same findings, and both were browser-side first. Moving
// them here makes them queryable — a component page in a service catalogue asking
// "what does this service owe" should not be pulling forty megabytes of findings and
// summing them itself.
//
// Aggregation is where a report starts lying, so the rules are explicit:
//
//   - The worst of anything is reported WITH where it came from. The same image is
//     urgent in production and medium in development, and "urgent" alone throws away
//     the answer to "urgent where?".
//   - Partial coverage is stated, never averaged. Counts from a group where some
//     images were never assessed are the worst KNOWN, and say so.
//   - A check counts as done only when it ran for every member. One unchecked
//     deployment means the group cannot claim to have looked.
package group

import (
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Item is one piece of work: a service, its owner, and the upgrade it needs. It is the
// same unit a ticket covers, so a queue row, an API item and a ticket are one thing.
type Item struct {
	// Key identifies the item across runs: owner and service and target.
	Key        string `json:"key"`
	Repository string `json:"repository"`
	Team       string `json:"team"`
	Class      string `json:"class"`

	// Priority is the worst verdict among the deployments, and PriorityWhere the
	// account or namespace that earned it. Without the second, an environment-tiered
	// policy's whole output is flattened into one word.
	Priority      string `json:"priority"`
	PriorityWhere string `json:"priority_where,omitempty"`
	// Rule is the policy rule behind that verdict.
	Rule string `json:"rule,omitempty"`

	// Upgrade is the change every deployment here needs; grouping is by target, so
	// they cannot differ. Nil when there is nothing to move to.
	Upgrade *sink.UpgradeView `json:"upgrade,omitempty"`

	// Critical and High are the worst counts across assessed deployments.
	// AssessedImages of Deployments says how many were assessed at all: when it is
	// short of the total these are the worst KNOWN, not the worst.
	Critical       int `json:"critical"`
	High           int `json:"high"`
	Deployments    int `json:"deployments"`
	AssessedImages int `json:"assessed_images"`
	ScannedImages  int `json:"scanned_images"`

	// Exposure is public when any deployment is reachable from the internet,
	// internal when all reporting ones are internal, unknown when none reported.
	Exposure string   `json:"exposure"`
	Signals  []string `json:"signals,omitempty"`

	// InFlight is an open pull request applying the upgrade, and InFlightChecked is
	// true only when every deployment was checked.
	InFlight        *sink.InFlightView `json:"in_flight,omitempty"`
	InFlightChecked bool               `json:"in_flight_checked"`

	// Tags, Accounts and Namespaces are where this service is deployed.
	Tags       []string `json:"tags"`
	Accounts   []string `json:"accounts,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	// Images are the full references, so a consumer can fetch any deployment's
	// finding for the detail this deliberately summarises.
	Images    []string `json:"images"`
	Workloads int      `json:"workloads"`
}

var priorityRank = map[string]int{"urgent": 4, "high": 3, "medium": 2, "low": 1}

// Items collapses findings into work items, worst first.
func Items(findings []sink.FindingView) []Item {
	order := []string{}
	members := map[string][]sink.FindingView{}
	for _, f := range findings {
		k := key(f)
		if _, seen := members[k]; !seen {
			order = append(order, k)
		}
		members[k] = append(members[k], f)
	}

	out := make([]Item, 0, len(order))
	for _, k := range order {
		out = append(out, item(k, members[k]))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if priorityRank[out[i].Priority] != priorityRank[out[j].Priority] {
			return priorityRank[out[i].Priority] > priorityRank[out[j].Priority]
		}
		if out[i].Critical != out[j].Critical {
			return out[i].Critical > out[j].Critical
		}
		return out[i].Repository < out[j].Repository
	})
	return out
}

// key is the grouping identity: owner, service, and what it upgrades to.
//
// The owner is part of it because a repository can be shared between teams, and a row
// belonging to two teams belongs to nobody. The target is part of it because two
// different moves are two different changes.
func key(f sink.FindingView) string {
	var name, latest string
	if f.Upgrade != nil {
		name, latest = f.Upgrade.Name, f.Upgrade.Latest
	}
	return strings.Join([]string{f.Owner.Team, f.Owner.Class, f.Repository, name, latest}, "|")
}

func item(k string, members []sink.FindingView) Item {
	lead := members[0]
	for _, f := range members {
		if priorityRank[f.Priority] > priorityRank[lead.Priority] {
			lead = f
		}
	}

	it := Item{
		Key: k, Repository: lead.Repository,
		Team: lead.Owner.Team, Class: lead.Owner.Class,
		Priority: lead.Priority, Upgrade: lead.Upgrade,
		InFlight: lead.InFlight, InFlightChecked: true,
		Deployments: len(members),
	}
	if len(lead.Reasons) > 0 {
		it.Rule = ruleName(lead.Reasons[0])
	}
	if len(lead.Dimensions["account"]) > 0 {
		it.PriorityWhere = lead.Dimensions["account"][0]
	} else if len(lead.Dimensions["namespace"]) > 0 {
		it.PriorityWhere = lead.Dimensions["namespace"][0]
	}

	accounts, namespaces, signals := &set{}, &set{}, &set{}
	exposedAny, internalKnown := false, false
	for _, f := range members {
		it.Tags = append(it.Tags, f.Tag)
		it.Images = append(it.Images, f.Image)
		it.Workloads += f.WorkloadCount
		if f.ProviderAssessed {
			it.AssessedImages++
			if c := f.Counts["critical"]; c > it.Critical {
				it.Critical = c
			}
			if h := f.Counts["high"]; h > it.High {
				it.High = h
			}
		}
		if f.Scanned {
			it.ScannedImages++
		}
		if !f.InFlightChecked {
			it.InFlightChecked = false
		}
		switch f.Exposure {
		case "public":
			exposedAny = true
		case "internal":
			internalKnown = true
		}
		for _, s := range f.Signals {
			signals.add(s)
		}
		for _, a := range f.Dimensions["account"] {
			accounts.add(a)
		}
		for _, n := range f.Dimensions["namespace"] {
			namespaces.add(n)
		}
	}
	switch {
	case exposedAny:
		it.Exposure = "public"
	case internalKnown:
		it.Exposure = "internal"
	default:
		it.Exposure = "unknown"
	}
	it.Signals, it.Accounts, it.Namespaces = signals.sorted(), accounts.sorted(), namespaces.sorted()
	sort.Strings(it.Tags)
	sort.Strings(it.Images)
	return it
}

// ruleName pulls the rule out of a recorded reason ('matched actionable rule "x"').
func ruleName(reason string) string {
	if i := strings.Index(reason, `"`); i >= 0 {
		if j := strings.LastIndex(reason, `"`); j > i {
			return reason[i+1 : j]
		}
	}
	return reason
}

type set struct{ m map[string]struct{} }

func (s *set) add(v string) {
	if v == "" {
		return
	}
	if s.m == nil {
		s.m = map[string]struct{}{}
	}
	s.m[v] = struct{}{}
}

func (s *set) sorted() []string {
	out := make([]string, 0, len(s.m))
	for v := range s.m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
