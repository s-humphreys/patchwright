package ticket

import (
	"os"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

func routedView(class, team, repo string) sink.FindingView {
	return sink.FindingView{
		Image:      repo + ":1.0",
		Repository: repo,
		Owner:      sink.OwnerView{Class: class, Team: team},
		Actionable: true,
		Priority:   "high",
		Upgrade: &sink.UpgradeView{
			Kind: "image", Current: "1.0", Latest: "1.1",
			Available: true, Actionable: true, Resolved: true,
		},
		RemediationChecked: true,
	}
}

func sreRoutes() []config.TicketRoute {
	return []config.TicketRoute{
		{Name: "sre", When: "owner['team'] == 'sre'", Project: "SRE", IssueType: "Bug"},
		{Name: "platform", When: "owner['class'] == 'platform'", Project: "DVOP"},
	}
}

func TestRouteMatchesFirstRuleAndFallsBackToDefault(t *testing.T) {
	r, err := newRoutes(sreRoutes())
	if err != nil {
		t.Fatalf("newRoutes: %v", err)
	}
	for _, tc := range []struct{ class, team, want string }{
		{"platform", "sre", "sre"}, // first match wins, not the broader class rule
		{"platform", "cpo", "platform"},
		{"engineering", "orders", routeName},
		{"", "", routeName},
	} {
		if got := r.match(routedView(tc.class, tc.team, "acr.io/x")); got != tc.want {
			t.Errorf("class=%q team=%q routed to %q, want %q", tc.class, tc.team, got, tc.want)
		}
	}
}

// A malformed expression must not stop every other team's tickets, and must not
// claim a match it cannot prove.
func TestRouteEvaluationErrorDoesNotMatch(t *testing.T) {
	r, err := newRoutes([]config.TicketRoute{
		{Name: "broken", When: `dimensions['nope'][0] == 'x'`, Project: "X"},
		{Name: "sre", When: "owner['team'] == 'sre'", Project: "SRE"},
	})
	if err != nil {
		t.Skipf("expression rejected at compile time, which is also acceptable: %v", err)
	}
	if got := r.match(routedView("platform", "sre", "acr.io/x")); got != "sre" {
		t.Errorf("routed to %q, want the later rule to still be reachable", got)
	}
}

func TestRoutesRejectBadConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		routes     []config.TicketRoute
	}{
		{"no name", "missing name", []config.TicketRoute{{When: "true"}}},
		{"no when", "missing when", []config.TicketRoute{{Name: "x"}}},
		{"reserved name", "reserved", []config.TicketRoute{{Name: routeName, When: "true"}}},
		{"bad expression", "sre", []config.TicketRoute{{Name: "sre", When: "owner["}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newRoutes(tc.routes); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// Resolution is a merge: a route states only what differs.
func TestResolveInheritsEverythingNotOverridden(t *testing.T) {
	base := config.JiraConfig{
		Board: 1, Project: "DVOP", Template: "t.tmpl", ImageField: "customfield_1",
		IssueType: "Container Vulnerability", Priority: "Medium",
		PriorityMap: map[string]string{"urgent": "Highest"},
		Labels:      []string{"patchwright"},
	}
	got := base.Resolve(config.TicketRoute{Name: "sre", When: "true", Project: "SRE", IssueType: "Bug"})

	if got.Project != "SRE" || got.EffectiveIssueType() != "Bug" {
		t.Errorf("overrides not applied: project=%q issuetype=%q", got.Project, got.EffectiveIssueType())
	}
	if got.Template != "t.tmpl" || got.ImageField != "customfield_1" || got.Board != 1 {
		t.Errorf("inherited settings lost: %+v", got)
	}
	if got.JiraPriority("urgent") != "Highest" {
		t.Errorf("priority map not inherited: %v", got.PriorityMap)
	}
	if len(got.Labels) != 1 {
		t.Errorf("labels not inherited: %v", got.Labels)
	}
	// A resolved config must not carry routes, or resolution could recurse.
	if got.Routes != nil {
		t.Errorf("resolved config still carries routes: %+v", got.Routes)
	}
}

// Naming a custom field must switch the lookup off labels, and vice versa:
// writing one and searching the other finds nothing, so every run duplicates.
func TestResolveKeepsTheImageKeyUnambiguous(t *testing.T) {
	labelBase := config.JiraConfig{Board: 1, Project: "P", Template: "t", ImageLabel: true}
	got := labelBase.Resolve(config.TicketRoute{Name: "r", When: "true", ImageField: "customfield_9"})
	if got.ImageLabel || got.ImageField != "customfield_9" {
		t.Errorf("field override left labels on: label=%v field=%q", got.ImageLabel, got.ImageField)
	}

	fieldBase := config.JiraConfig{Board: 1, Project: "P", Template: "t", ImageField: "customfield_1"}
	yes := true
	got = fieldBase.Resolve(config.TicketRoute{Name: "r", When: "true", ImageLabel: &yes})
	if !got.ImageLabel || got.ImageField != "" {
		t.Errorf("label override left a field set: label=%v field=%q", got.ImageLabel, got.ImageField)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("resolved config is invalid: %v", err)
	}
}

// Reconciliation has to search every tracker, or a ticket in another project is
// invisible and the next run raises a duplicate.
func TestProjectsListsEveryTracker(t *testing.T) {
	cfg := config.JiraConfig{Project: "DVOP", Routes: []config.TicketRoute{
		{Name: "sre", When: "true", Project: "SRE"},
		{Name: "also-dvop", When: "true"},           // inherits DVOP
		{Name: "dup", When: "true", Project: "SRE"}, // same project again
	}}
	got := cfg.Projects()
	if len(got) != 2 || got[0] != "DVOP" || got[1] != "SRE" {
		t.Errorf("Projects() = %v, want [DVOP SRE] with the base first", got)
	}
}

func TestValidateRejectsRoutesThatResolveInvalid(t *testing.T) {
	base := config.JiraConfig{Board: 1, Project: "P", Template: "t", ImageField: "customfield_1"}
	base.Routes = []config.TicketRoute{{Name: "dup", When: "true"}, {Name: "dup", When: "true"}}
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate route names accepted: %v", err)
	}
	base.Routes = []config.TicketRoute{{Name: "x", When: ""}}
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "when") {
		t.Errorf("route without a condition accepted: %v", err)
	}
}

// The load-bearing behaviour: a group must never span two trackers. Two findings
// sharing one upgrade still need two tickets when they belong to different teams,
// because an issue cannot exist in two projects and merging them would move one
// team's work onto another team's board.
func TestPlannerNeverGroupsAcrossRoutes(t *testing.T) {
	dir := t.TempDir()
	tmpl := dir + "/ticket.tmpl"
	if err := os.WriteFile(tmpl, []byte("Summary: upgrade {{ .ServiceName }}\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.JiraConfig{
		Board: 1, Project: "DVOP", Template: tmpl, ImageField: "customfield_1",
		Routes: []config.TicketRoute{
			{Name: "sre", When: "owner['team'] == 'sre'", Project: "SRE", IssueType: "Bug"},
		},
	}
	p, err := NewPlanner(cfg)
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}

	// Same image, same upgrade, two owners: the shape that would otherwise merge.
	sre := routedView("platform", "sre", "acr.io/shared")
	other := routedView("engineering", "orders", "acr.io/shared")
	plan, err := p.Plan([]sink.FindingView{sre, other})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 2 {
		t.Fatalf("got %d drafts, want 2 (one per tracker): %+v", len(plan.Drafts), plan.Drafts)
	}
	routes := map[string]bool{}
	for _, d := range plan.Drafts {
		routes[d.Route] = true
		if len(d.Findings) != 1 {
			t.Errorf("draft for route %q covers %d findings, so it spans owners", d.Route, len(d.Findings))
		}
	}
	if !routes["sre"] || !routes[routeName] {
		t.Errorf("drafts routed to %v, want one sre and one default", routes)
	}
}

// Every draft carries a route, so no write has to guess which tracker it meant.
func TestEveryDraftIsRouted(t *testing.T) {
	dir := t.TempDir()
	tmpl := dir + "/ticket.tmpl"
	if err := os.WriteFile(tmpl, []byte("Summary: s\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPlanner(config.JiraConfig{
		Board: 1, Project: "DVOP", Template: tmpl, ImageField: "customfield_1",
	})
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	plan, err := p.Plan([]sink.FindingView{routedView("platform", "cpo", "acr.io/a")})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, d := range plan.Drafts {
		if d.Route == "" {
			t.Errorf("draft %q has no route", d.Summary)
		}
	}
}

// requireRoute: work with no configured tracker is reported, not quietly sent to
// whichever board happens to be the default.
func TestRequireRouteSkipsUnroutedWorkWithAReason(t *testing.T) {
	dir := t.TempDir()
	tmpl := dir + "/ticket.tmpl"
	if err := os.WriteFile(tmpl, []byte("Summary: s\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.JiraConfig{
		Board: 1, Project: "DVOP", Template: tmpl, ImageField: "customfield_1",
		RequireRoute: true,
		Routes: []config.TicketRoute{
			{Name: "platform", When: "owner['class'] == 'platform'", Project: "DVOP"},
		},
	}
	p, err := NewPlanner(cfg)
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	plan, err := p.Plan([]sink.FindingView{
		routedView("platform", "cpo", "acr.io/platform-thing"),
		routedView("engineering", "orders", "acr.io/app"),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 || plan.Drafts[0].Route != "platform" {
		t.Fatalf("got %d drafts %+v, want only the platform one", len(plan.Drafts), plan.Drafts)
	}
	// The unrouted finding must be visible, and say why.
	var found bool
	for _, s := range plan.Skips {
		if strings.Contains(s.Image, "acr.io/app") {
			found = true
			for _, want := range []string{"no ticket route", "engineering/orders", "requireRoute"} {
				if !strings.Contains(s.Reason, want) {
					t.Errorf("skip reason %q does not mention %q", s.Reason, want)
				}
			}
		}
	}
	if !found {
		t.Errorf("the unrouted finding was dropped silently; skips = %+v", plan.Skips)
	}
}

// Without requireRoute the previous behaviour stands, so enabling routing does
// not silently stop tickets for anyone who has not written routes yet.
func TestWithoutRequireRouteUnroutedWorkUsesTheDefault(t *testing.T) {
	dir := t.TempDir()
	tmpl := dir + "/ticket.tmpl"
	if err := os.WriteFile(tmpl, []byte("Summary: s\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPlanner(config.JiraConfig{
		Board: 1, Project: "DVOP", Template: tmpl, ImageField: "customfield_1",
		Routes: []config.TicketRoute{
			{Name: "platform", When: "owner['class'] == 'platform'", Project: "DVOP"},
		},
	})
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	plan, err := p.Plan([]sink.FindingView{routedView("engineering", "orders", "acr.io/app")})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 || plan.Drafts[0].Route != routeName {
		t.Fatalf("got %d drafts %+v, want one on the default route", len(plan.Drafts), plan.Drafts)
	}
}

// minPriority: a tracker holding a hundred tickets nobody will action this quarter is
// one people stop reading, and it takes the urgent ones down with it.
func TestMinPriorityKeepsLowFindingsOutOfTheTracker(t *testing.T) {
	dir := t.TempDir()
	tmpl := dir + "/t.tmpl"
	if err := os.WriteFile(tmpl, []byte("Summary: s\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.JiraConfig{
		Board: 1, Project: "P", Template: tmpl, ImageField: "customfield_1",
		MinPriority: "high",
	}
	p, err := NewPlanner(cfg)
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}

	urgent := routedView("platform", "cpo", "acr.io/urgent")
	urgent.Priority = "urgent"
	high := routedView("platform", "cpo", "acr.io/high")
	high.Priority = "high"
	medium := routedView("platform", "cpo", "acr.io/medium")
	medium.Priority = "medium"
	low := routedView("platform", "cpo", "acr.io/low")
	low.Priority = "low"

	plan, err := p.Plan([]sink.FindingView{urgent, high, medium, low})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	ticketed := map[string]bool{}
	for _, d := range plan.Drafts {
		for _, img := range d.Images {
			ticketed[img] = true
		}
	}
	for _, want := range []string{"acr.io/urgent", "acr.io/high"} {
		if !ticketed[want] {
			t.Errorf("%s was not ticketed despite clearing the threshold", want)
		}
	}
	for _, notWant := range []string{"acr.io/medium", "acr.io/low"} {
		if ticketed[notWant] {
			t.Errorf("%s was ticketed below the threshold", notWant)
		}
	}
	// Skipped, not hidden: the reason has to name the threshold and the finding's own
	// priority, or the queue and the tracker disagreeing looks like a bug.
	var reported int
	for _, s := range plan.Skips {
		if s.Image == "acr.io/medium" || s.Image == "acr.io/low" {
			reported++
			for _, want := range []string{"below the minimum ticket priority", "high", "stays in the queue"} {
				if !strings.Contains(s.Reason, want) {
					t.Errorf("skip reason for %s does not mention %q: %s", s.Image, want, s.Reason)
				}
			}
		}
	}
	if reported != 2 {
		t.Errorf("reported %d skips for the below-threshold findings, want 2", reported)
	}
}

// No threshold means every actionable finding is ticketed, so existing configuration
// is unchanged.
func TestNoMinPriorityTicketsEverything(t *testing.T) {
	dir := t.TempDir()
	tmpl := dir + "/t.tmpl"
	if err := os.WriteFile(tmpl, []byte("Summary: s\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPlanner(config.JiraConfig{
		Board: 1, Project: "P", Template: tmpl, ImageField: "customfield_1",
	})
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	low := routedView("platform", "cpo", "acr.io/low")
	low.Priority = "low"
	plan, err := p.Plan([]sink.FindingView{low})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 {
		t.Errorf("got %d drafts, want 1 with no threshold set", len(plan.Drafts))
	}
}

// A route can hold a stricter threshold than the deployment: one team may want only
// urgent work in its tracker.
func TestMinPriorityIsPerRoute(t *testing.T) {
	dir := t.TempDir()
	tmpl := dir + "/t.tmpl"
	if err := os.WriteFile(tmpl, []byte("Summary: s\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.JiraConfig{
		Board: 1, Project: "P", Template: tmpl, ImageField: "customfield_1",
		MinPriority: "low",
		Routes: []config.TicketRoute{
			{Name: "strict", When: "owner['team'] == 'sre'", Project: "SRE", MinPriority: "urgent"},
		},
	}
	p, err := NewPlanner(cfg)
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	sreHigh := routedView("platform", "sre", "acr.io/sre-high")
	sreHigh.Priority = "high"
	otherHigh := routedView("platform", "cpo", "acr.io/other-high")
	otherHigh.Priority = "high"

	plan, err := p.Plan([]sink.FindingView{sreHigh, otherHigh})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	ticketed := map[string]bool{}
	for _, d := range plan.Drafts {
		for _, img := range d.Images {
			ticketed[img] = true
		}
	}
	if ticketed["acr.io/sre-high"] {
		t.Error("a high finding was ticketed on a route requiring urgent")
	}
	if !ticketed["acr.io/other-high"] {
		t.Error("a high finding was not ticketed on a route allowing low and above")
	}
}

// A typo would rank below everything and silently ticket the lot, which is the
// opposite of what the setting is for.
func TestMinPriorityMustBeARankedLabel(t *testing.T) {
	for _, bad := range []string{"High", "critical", "sev1", "urgentish"} {
		cfg := config.JiraConfig{
			Board: 1, Project: "P", Template: "t", ImageField: "customfield_1",
			MinPriority: bad,
		}
		err := cfg.Validate()
		if bad == "High" {
			// Case matters: the ladder is lowercase, and accepting "High" here while
			// the rules emit "high" would work by accident.
			if err == nil {
				t.Errorf("minPriority %q was accepted", bad)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "not a ranked priority") {
			t.Errorf("minPriority %q: err = %v", bad, err)
		}
	}
	ok := config.JiraConfig{
		Board: 1, Project: "P", Template: "t", ImageField: "customfield_1",
		MinPriority: "high",
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("a valid threshold was rejected: %v", err)
	}
}
