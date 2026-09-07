package mcp

import (
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// policyFixture mirrors the shape of a real rule set: tiered actionable rules, a
// suppression that expires and one that never does, and - the point of most of these
// tests - a finding no rule speaks to at all.
func policyFixture() Assessment {
	f := func(repo, team, rule, kind, priority string, crit int) sink.FindingView {
		v := sink.FindingView{
			Image: "reg.example/" + repo + ":1", Repository: repo,
			Owner:    sink.OwnerView{Team: team, Class: "product"},
			Counts:   map[string]int{"critical": crit},
			Rule:     rule,
			RuleKind: kind,
			Priority: priority,
			Exposure: "internal",
			// Assessed, so a zero count is a measurement rather than a coverage gap
			// and the caveats under test are the policy ones.
			ProviderAssessed: true,
		}
		switch kind {
		case model.RuleKindActionable:
			v.Actionable = true
		case model.RuleKindSuppress:
			v.Suppressed = true
		}
		return v
	}

	return Assessment{
		GeneratedAt: ts("2026-09-04T09:00:00Z"),
		Version:     "v2.2.0",
		Sources:     model.Sources{Provider: "rapid7", VulnSource: "rapid7", LiveSource: "kube"},
		Findings: []sink.FindingView{
			f("apps/storefront", "payments", "exploited-fixable-critical", model.RuleKindActionable, "urgent", 3),
			f("apps/ledger", "payments", "production-critical", model.RuleKindActionable, "high", 2),
			f("apps/rewards", "orders", "production-critical", model.RuleKindActionable, "high", 1),
			f("apps/legacy", "orders", "not-running", model.RuleKindSuppress, "", 4),
			f("apps/aks-csi", "", "cloud-provider-managed", model.RuleKindSuppress, "", 9),
			// No rule matched: in neither the queue nor the suppression list, and
			// carrying a critical.
			f("apps/orphan", "orders", "", model.RuleKindNone, "", 2),
		},
		Policy: PolicyRules{
			Actionable: []PolicyRuleDef{
				{Name: "exploited-fixable-critical", Priority: "urgent", When: "vulns.exists(...)"},
				{Name: "production-critical", Priority: "high", When: "counts['critical'] > 0"},
				// Configured and quiet. The report has to show it.
				{Name: "prelive-critical", Priority: "medium", When: "counts['critical'] > 0"},
			},
			Suppress: []PolicyRuleDef{
				{Name: "cloud-provider-managed", When: "owner['class'] == 'cloud-provider'"},
				{Name: "not-running", When: "reconciled && !live", Until: "2026-12-31"},
				// Holding nothing, so it is dead config rather than accepted risk.
				{Name: "old-exception", When: "image.repository == 'gone'", Until: "2026-01-01"},
			},
		},
	}
}

var policyNow = ts("2026-09-04T09:00:00Z")

func TestPolicyReportPartitionsEveryDeployment(t *testing.T) {
	r := NewPolicyReport(policyFixture(), policyNow)

	if r.Scope.Deployments != 6 {
		t.Errorf("deployments = %d, want 6", r.Scope.Deployments)
	}
	// The documented invariant: the three verdicts account for everything, so a
	// reader can check the arithmetic rather than trust it.
	sum := r.Verdicts.Actionable + r.Verdicts.Suppressed + r.Verdicts.NoRuleMatched
	if sum != r.Scope.Deployments {
		t.Errorf("verdicts %d + %d + %d != %d deployments",
			r.Verdicts.Actionable, r.Verdicts.Suppressed, r.Verdicts.NoRuleMatched, r.Scope.Deployments)
	}
	if r.Verdicts.Actionable != 3 || r.Verdicts.Suppressed != 2 || r.Verdicts.NoRuleMatched != 1 {
		t.Errorf("verdicts = %+v", r.Verdicts)
	}
	// Coverage is over unsuppressed deployments, matching estate_summary. Stated in
	// the field comment, and asserted here so the two cannot drift apart.
	if r.Coverage.Total != r.Verdicts.Actionable+r.Verdicts.NoRuleMatched {
		t.Errorf("coverage total %d should be actionable + unmatched", r.Coverage.Total)
	}
}

func TestPolicyReportKeepsConfiguredOrderAndShowsQuietRules(t *testing.T) {
	r := NewPolicyReport(policyFixture(), policyNow)

	var names []string
	for _, rule := range r.ActionableRules {
		names = append(names, rule.Name)
	}
	// Configured order, NOT by size: the policy's own ordering is its statement of
	// severity, and production-critical caught more than the urgent rule here.
	want := []string{"exploited-fixable-critical", "production-critical", "prelive-critical"}
	for i, w := range want {
		if i >= len(names) || names[i] != w {
			t.Fatalf("rules = %v, want configured order %v", names, want)
		}
	}

	quiet := r.ActionableRules[2]
	if quiet.Matched || quiet.Deployments != 0 {
		t.Errorf("a rule that caught nothing should be listed as unmatched: %+v", quiet)
	}
	if quiet.Priority != "medium" || quiet.When == "" {
		t.Errorf("a quiet rule still needs its definition to be reviewable: %+v", quiet)
	}

	prod := r.ActionableRules[1]
	if prod.Deployments != 2 || prod.Services != 2 || prod.Teams != 2 {
		t.Errorf("production-critical = %+v, want 2 deployments across 2 services and 2 teams", prod)
	}
}

func TestPolicyReportDatesEverySuppression(t *testing.T) {
	r := NewPolicyReport(policyFixture(), policyNow)

	byName := map[string]SuppressStat{}
	for _, s := range r.SuppressRules {
		byName[s.Name] = s
	}

	// Accepted risk with no expiry is the thing a review most needs pointed at.
	if cp := byName["cloud-provider-managed"]; !cp.NoExpiry || cp.Deployments != 1 {
		t.Errorf("cloud-provider-managed = %+v, want no_expiry with 1 deployment", cp)
	}
	nr := byName["not-running"]
	if nr.Expired || nr.ExpiresInDays == nil {
		t.Errorf("not-running = %+v, want a countdown", nr)
	}
	if *nr.ExpiresInDays != 118 {
		t.Errorf("expires_in_days = %d, want 118 (to end of 2026-12-31)", *nr.ExpiresInDays)
	}
	// Lapsed, and holding nothing. Both facts are reportable: the findings it hid are
	// back in the queue, which reads as the estate getting worse unless it is said.
	if old := byName["old-exception"]; !old.Expired || old.Deployments != 0 {
		t.Errorf("old-exception = %+v, want expired and empty", old)
	}
}

func TestPolicyReportSurfacesWhatNoRuleSpeaksTo(t *testing.T) {
	r := NewPolicyReport(policyFixture(), policyNow)

	if r.Unmatched.Deployments != 1 || r.Unmatched.WithCriticals != 1 {
		t.Errorf("unmatched = %+v, want one deployment carrying a critical", r.Unmatched)
	}
	if len(r.Unmatched.TopServices) != 1 || r.Unmatched.TopServices[0] != "apps/orphan" {
		t.Errorf("unmatched services = %v", r.Unmatched.TopServices)
	}

	var said bool
	for _, c := range r.Caveats {
		if contains(c, "matched no rule at all") && contains(c, "carry a critical") {
			said = true
		}
	}
	if !said {
		t.Errorf("a critical no rule has an opinion about must be stated, got %v", r.Caveats)
	}
}

// The report is a photograph and will be read as a film. Nothing else in it warns
// against the reading a monthly report invites most.
func TestPolicyReportLeadsWithBeingASnapshot(t *testing.T) {
	r := NewPolicyReport(policyFixture(), policyNow)
	if len(r.Caveats) == 0 || !contains(r.Caveats[0], "not a record of what happened over any period") {
		t.Errorf("first caveat = %q", firstOr(r.Caveats))
	}
}

func TestPolicyReportSaysWhenItCannotSeeTheRules(t *testing.T) {
	a := policyFixture()
	a.Policy = PolicyRules{}
	r := NewPolicyReport(a, policyNow)

	// The rules that fired are still reported, recovered from the findings.
	if len(r.ActionableRules) != 2 {
		t.Errorf("rules that fired should still be listed, got %d", len(r.ActionableRules))
	}
	var warned bool
	for _, c := range r.Caveats {
		if contains(c, "matched NOTHING cannot be listed") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("without the rule set, a quiet rule is indistinguishable from a missing one: %v", r.Caveats)
	}
}

func TestPolicyReportSplitsByPriorityAndTeam(t *testing.T) {
	r := NewPolicyReport(policyFixture(), policyNow)

	if len(r.ByPriority) != 2 || r.ByPriority[0].Priority != "urgent" {
		t.Fatalf("by_priority = %+v, want urgent first", r.ByPriority)
	}
	if r.ByPriority[1].Priority != "high" || r.ByPriority[1].Deployments != 2 {
		t.Errorf("high = %+v, want 2 deployments", r.ByPriority[1])
	}

	byTeam := map[string]TeamPolicyStat{}
	for _, t := range r.ByTeam {
		byTeam[t.Team] = t
	}
	if p := byTeam["payments"]; p.Actionable != 2 || p.ByPriority["urgent"] != 1 {
		t.Errorf("payments = %+v", p)
	}
	// The team carrying the unmatched finding and a suppression, neither of which is
	// visible in an actionable count alone.
	if o := byTeam["orders"]; o.Actionable != 1 || o.Suppressed != 1 || o.NoRuleMatched != 1 {
		t.Errorf("orders = %+v", o)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func firstOr(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
