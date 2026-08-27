package server

import (
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
