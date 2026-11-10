package mcp

import (
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// An exploited CVE whose origin the differential could not determine might be
// cleared by the rebuild, so the ticket planner (ticket.packageOnly) keeps the
// rebuild ticket. fix_plan must not tell the same team not to rebuild.
func TestQAPlanDoesNotRuleOutARebuildThatMightClear(t *testing.T) {
	a := withAppKEV(fixture(), false)
	unknown := sink.VulnView{ID: "CVE-2026-99", Severity: "critical", KEV: true, FixAvailable: true}
	for i := range a.Findings {
		a.Findings[i].Vulns = append(a.Findings[i].Vulns, unknown)
	}
	p, ok := fixPlan(a, "storefront")
	if !ok {
		t.Fatal("no plan")
	}
	if strings.Contains(strings.Join(p.DoNot, " "), "Do not rebuild") {
		t.Errorf("rebuild ruled out although %s may be in the base: do %+v, do_not %v", unknown.ID, p.Do, p.DoNot)
	}
}
