package mcp

import (
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// The question this answers is "I have a ticket for this, what do I do" - so the tests
// are about whether somebody holding that ticket could act on the answer without knowing
// the vocabulary of the rest of the tools.

func TestAPlanSaysWhatToChangeAndWhatItAchieves(t *testing.T) {
	a := fixture()
	a.Findings[0].Upgrade.Ceiling = "3.12"
	a.Findings[0].Upgrade.CeilingReason = "the analytics toolkit is not 3.14 ready (data team, Aug 2026)"
	a.Findings[0].Upgrade.Newest = "3.14.7"
	a.Findings[0].Upgrade.Actionable = true

	p, ok := fixPlan(a, "storefront")
	if !ok {
		t.Fatal("want a plan")
	}
	if p.Do == nil {
		t.Fatal("want an action")
	}
	if !strings.Contains(p.Do.Change, "base image") {
		t.Errorf("change = %q, want it to name the thing to edit", p.Do.Change)
	}
	if p.Do.To == "" || p.Do.From == "" {
		t.Errorf("want a from and a to: %+v", p.Do)
	}
	if !p.Do.Yours {
		t.Error("this one is directly actionable, so it is the team's own change")
	}
	if p.Do.Deployments != 2 {
		t.Errorf("deployments = %d, want 2 - the change has to reach all of them", p.Do.Deployments)
	}

	// The constraint, with the reason a human wrote. Without it the answer looks wrong to
	// anybody who can see there is a 3.14.
	joined := strings.Join(p.DoNot, " ")
	if !strings.Contains(joined, "3.14.7") || !strings.Contains(joined, "the analytics toolkit is not 3.14 ready") {
		t.Errorf("want the ceiling and its reason: %v", p.DoNot)
	}

	// What it achieves, and what was never theirs.
	if p.Result == nil {
		t.Fatal("want a result")
	}
	if p.Result.Clears != 2 || p.Result.Of != 6 {
		t.Errorf("clears %d of %d, want 2 of 6", p.Result.Clears, p.Result.Of)
	}
	if p.Result.ClearsKnownExploited != 1 {
		t.Errorf("clears_known_exploited = %d, want 1 - the number that justifies doing it now",
			p.Result.ClearsKnownExploited)
	}
	if p.Result.Introduces != 1 {
		t.Errorf("introduces = %d, want it reported even though it is bad news", p.Result.Introduces)
	}
	if p.Result.NotYours != 2 || p.Result.NotYoursWhy == "" {
		t.Errorf("want the remainder attributed away from the team: %+v", p.Result)
	}
	if p.Result.StillYours != 1 {
		t.Errorf("still_yours = %d, want 1", p.Result.StillYours)
	}

	// And the honest gap: patchwright cannot say where the build lives.
	if !strings.Contains(strings.Join(p.Unknown, " "), "which repository") {
		t.Errorf("want the repository gap named rather than left silent: %v", p.Unknown)
	}
}

// Nothing to move to is not "no work": it is a decision, and the plan must say which.
func TestAPlanWithNothingToUpgradeAsksForADecision(t *testing.T) {
	a := fixture()
	for i := range a.Findings {
		a.Findings[i].Upgrade = &sink.UpgradeView{
			Kind: "chart", Name: "wiremock", Current: "1.11.0", Latest: "1.11.0",
			Resolved: true, Available: false,
		}
	}
	p, ok := fixPlan(a, "storefront")
	if !ok {
		t.Fatal("want a plan")
	}
	if p.Do != nil {
		t.Errorf("want no action when there is nothing to move to, got %+v", p.Do)
	}
	if !strings.Contains(strings.Join(p.Decide, " "), "newest version available") {
		t.Errorf("want a decision rather than a bump: %v", p.Decide)
	}
}

// A tag somebody else owns: editing the build would do nothing, and the plan has to say so
// before an engineer spends an afternoon on it.
func TestAPlanSaysWhenTheChangeIsNotYours(t *testing.T) {
	a := fixture()
	for i := range a.Findings {
		u := *a.Findings[i].Upgrade
		u.Actionable, u.Managed, u.Manager = false, "helm chart", "flux"
		a.Findings[i].Upgrade = &u
	}
	p, _ := fixPlan(a, "storefront")
	if p.Do == nil {
		t.Fatal("there is still a change, it is just applied elsewhere")
	}
	if p.Do.Yours {
		t.Error("want yours=false when a chart owns the tag")
	}
	if !strings.Contains(p.Do.AppliedIn, "helm chart") {
		t.Errorf("applied_in = %q, want the mechanism named", p.Do.AppliedIn)
	}
	if !strings.Contains(strings.Join(p.DoNot, " "), "Do not edit the build") {
		t.Errorf("want the warning: %v", p.DoNot)
	}
}

// An end-of-life line is a migration, and calling it a bump wastes somebody's sprint.
func TestAPlanCallsAMigrationAMigration(t *testing.T) {
	a := fixture()
	for i := range a.Findings {
		u := *a.Findings[i].Upgrade
		u.OutOfTrack = true
		u.Support = &sink.SupportView{
			Known: true, Supported: false, Product: "dotnet", Cycle: "8.0", EOL: "2026-11-10",
		}
		a.Findings[i].Upgrade = &u
	}
	p, _ := fixPlan(a, "storefront")
	joined := strings.Join(p.DoNot, " ")
	if !strings.Contains(joined, "migration to plan") {
		t.Errorf("want it called a migration: %v", p.DoNot)
	}
	if !strings.Contains(joined, "END OF LIFE") {
		t.Errorf("want the support status: %v", p.DoNot)
	}
}

// Work already open must surface, including the two cases that look like progress and are
// not: a stale pull request, and one moving to a different version.
func TestAPlanSurfacesWorkAlreadyOpen(t *testing.T) {
	for _, c := range []struct {
		name string
		fl   sink.InFlightView
		says string
	}{
		{"open", sink.InFlightView{URL: "https://pr/1", OpenDays: 2, Exact: true}, "open 2 days"},
		{"stale", sink.InFlightView{URL: "https://pr/2", OpenDays: 90, Stale: true, Exact: true}, "stale"},
		{"different version", sink.InFlightView{URL: "https://pr/3", OpenDays: 1}, "DIFFERENT version"},
	} {
		a := fixture()
		fl := c.fl
		a.Findings[0].InFlight = &fl
		a.Findings[0].InFlightChecked = true
		a.Findings[1].InFlight = &fl
		a.Findings[1].InFlightChecked = true
		p, _ := fixPlan(a, "storefront")
		if p.Do == nil || !strings.Contains(p.Do.InProgress, c.says) {
			got := ""
			if p.Do != nil {
				got = p.Do.InProgress
			}
			t.Errorf("%s: in_progress = %q, want it to mention %q", c.name, got, c.says)
		}
	}
}

func TestAPlanForAnUnknownServiceMissesCleanly(t *testing.T) {
	if _, ok := fixPlan(fixture(), "no-such-thing"); ok {
		t.Error("want a miss rather than an empty plan, which would read as no work")
	}
}

// What a coding agent needs beyond the change itself: where the code is, which CVEs to
// name in the pull request, and what the service should look like afterwards so a
// remainder is not read as the change having failed.
func TestAPlanCarriesWhatAnAgentNeedsToAct(t *testing.T) {
	a := fixture()
	for i := range a.Findings {
		a.Findings[i].BuildRepo = "https://dev.example/org/proj/_git/storefront"
	}
	p, ok := fixPlan(a, "storefront")
	if !ok {
		t.Fatal("want a plan")
	}
	if p.Do.Repository != "https://dev.example/org/proj/_git/storefront" {
		t.Errorf("repository = %q, want the build repo the image records", p.Do.Repository)
	}
	// With the repo known, it is no longer an unknown.
	if strings.Contains(strings.Join(p.Unknown, " "), "which repository") {
		t.Errorf("repository is known, so it must not also be listed as unknown: %v", p.Unknown)
	}

	// The exploited CVEs, named, each with whether this change deals with it.
	if len(p.Result.KnownExploited) != 1 {
		t.Fatalf("want the exploited CVE named, got %+v", p.Result.KnownExploited)
	}
	kev := p.Result.KnownExploited[0]
	if kev.ID != "CVE-2026-1" || !kev.ClearedByThis {
		t.Errorf("wrong verdict on the exploited CVE: %+v", kev)
	}
	if !strings.HasSuffix(kev.Reference, "CVE-2026-1") {
		t.Errorf("want a public reference: %q", kev.Reference)
	}

	// And what to expect afterwards, so the remainder is not mistaken for a failure.
	if !strings.Contains(p.Result.Verify, "remainder is expected") {
		t.Errorf("verify = %q, want it to say a remainder is expected", p.Result.Verify)
	}
}

// No label, no repository - and the plan says which config would supply one rather than
// leaving an agent to guess.
func TestAPlanSaysWhyTheRepositoryIsMissing(t *testing.T) {
	p, ok := fixPlan(fixture(), "storefront")
	if !ok {
		t.Fatal("want a plan")
	}
	if p.Do.Repository != "" {
		t.Errorf("want no repository when the image records no label, got %q", p.Do.Repository)
	}
	joined := strings.Join(p.Unknown, " ")
	if !strings.Contains(joined, "repoLabels") {
		t.Errorf("want the config that would supply it named: %v", p.Unknown)
	}
}

// An exploited CVE the change does NOT clear must be named too: a ticket that lists only
// the wins leaves somebody believing the service is clean of them afterwards.
func TestAPlanNamesTheExploitedCVEsItDoesNotClear(t *testing.T) {
	a := fixture()
	for i := range a.Findings {
		for j := range a.Findings[i].Vulns {
			if a.Findings[i].Vulns[j].ID == "CVE-2026-2" {
				a.Findings[i].Vulns[j].KEV = true
			}
		}
	}
	p, _ := fixPlan(a, "storefront")
	var cleared, stays int
	for _, k := range p.Result.KnownExploited {
		if k.ClearedByThis {
			cleared++
		} else {
			stays++
		}
	}
	if cleared != 1 || stays != 1 {
		t.Errorf("want one cleared and one surviving, got %d and %d: %+v",
			cleared, stays, p.Result.KnownExploited)
	}
}
