package server

import (
	"strconv"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// The question a security reviewer actually asks: which teams are carrying the sharp
// end, not which are carrying the most work. A row with 300 findings and no KEV needs a
// different conversation from a row with 3 findings, two of them exploited and one on a
// runtime nobody maintains, and the totals cannot tell those apart.
func TestOwnerStatsCountTheSharpEndPerTeam(t *testing.T) {
	kev := model.Finding{
		Image:      model.ParseImageRef("acr.io/a:1"),
		Owner:      model.Owner{Class: "engineering", Team: "orders"},
		Priority:   model.PriorityUrgent,
		Actionable: true,
		Counts:     model.Counts{model.SeverityCritical: 1},
		Vulns:      []model.Vulnerability{{ID: "CVE-1", Severity: model.SeverityCritical, KEV: true}},
	}
	eol := model.Finding{
		Image:      model.ParseImageRef("acr.io/b:2"),
		Owner:      model.Owner{Class: "engineering", Team: "orders"},
		Priority:   model.PriorityHigh,
		Actionable: true,
		Upgrade: &model.Upgrade{Kind: "base", Resolved: true, Support: &model.Support{
			Product: "nodejs", Cycle: "20", Known: true, Supported: false, EOL: "2026-04-30",
		}},
	}
	quiet := model.Finding{
		Image: model.ParseImageRef("acr.io/c:3"),
		Owner: model.Owner{Class: "engineering", Team: "payments"},
	}
	// Suppressed findings are already excluded from these rows, and must not creep
	// into the sharp-end counts by another route.
	hidden := model.Finding{
		Image:      model.ParseImageRef("acr.io/d:4"),
		Owner:      model.Owner{Class: "engineering", Team: "payments"},
		Priority:   model.PriorityUrgent,
		Suppressed: true,
		Vulns:      []model.Vulnerability{{ID: "CVE-2", KEV: true}},
	}

	stats := buildOwnerStats([]model.Finding{kev, eol, quiet, hidden}, nil)
	byTeam := map[string]ownerStats{}
	for _, o := range stats {
		byTeam[o.Team] = o
	}

	orders := byTeam["orders"]
	if orders.Urgent != 1 {
		t.Errorf("orders urgent = %d, want 1", orders.Urgent)
	}
	if orders.KnownExploited != 1 {
		t.Errorf("orders known_exploited = %d, want 1", orders.KnownExploited)
	}
	if orders.EndOfLife != 1 {
		t.Errorf("orders end_of_life = %d, want 1", orders.EndOfLife)
	}

	payments := byTeam["payments"]
	if payments.Urgent != 0 || payments.KnownExploited != 0 {
		t.Errorf("payments = %+v, want no sharp-end counts: its only urgent KEV finding is suppressed", payments)
	}
	if payments.Total != 1 {
		t.Errorf("payments total = %d, want 1 (the suppressed finding is excluded)", payments.Total)
	}
}

// A percentage over 100 is never a rounding artefact: it means the numerator and
// denominator were drawn from different sets. The breakdown showed "50 104%" under
// Fixable because Fixable counted every finding while the share divided by Actionable.
//
// Asserted as an invariant over the counters rather than as one fixed case, so the next
// counter added to this struct cannot reintroduce it quietly.
func TestCountersThatAreReportedAsSharesStayWithinTheirDenominator(t *testing.T) {
	mk := func(team string, actionable bool, fixableCritical bool) model.Finding {
		f := model.Finding{
			Image:       model.ParseImageRef("acr.io/" + team + "-" + strconv.Itoa(len(team)) + ":1"),
			Owner:       model.Owner{Class: "engineering", Team: team},
			Actionable:  actionable,
			Occurrences: []model.Occurrence{{Assessed: true}},
		}
		if fixableCritical {
			f.Counts = model.Counts{model.SeverityCritical: 1}
			f.Vulns = []model.Vulnerability{{
				ID: "CVE-1", Severity: model.SeverityCritical, FixAvailable: true, FixedVersion: "2",
			}}
			f.Scanned = true
		}
		return f
	}

	// The shape that produced 104%: more findings carry a fixable critical than policy
	// marked actionable.
	findings := []model.Finding{
		mk("orders", true, true),
		mk("orders2", false, true),
		mk("orders3", false, true),
		mk("orders4", true, false),
	}
	for i := range findings {
		findings[i].Owner.Team = "orders"
	}

	for _, row := range buildOwnerStats(findings, nil) {
		if row.Actionable > row.Total {
			t.Errorf("%s: actionable %d > total %d", row.Team, row.Actionable, row.Total)
		}
		// Every counter the breakdown renders as a share of Actionable.
		for _, c := range []struct {
			name string
			n    int
		}{
			{"fixable", row.Fixable},
			{"direct", row.Direct},
			{"managed", row.Managed},
			{"ticketed", row.Ticketed},
		} {
			if c.n > row.Actionable {
				t.Errorf("%s: %s %d exceeds actionable %d, which renders as a percentage over 100",
					row.Team, c.name, c.n, row.Actionable)
			}
		}
		if row.Direct+row.Managed > row.Actionable {
			t.Errorf("%s: direct+managed %d exceeds actionable %d",
				row.Team, row.Direct+row.Managed, row.Actionable)
		}
	}
}
