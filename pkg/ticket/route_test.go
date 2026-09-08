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
		{Name: "platform", When: "owner['class'] == 'platform'", Project: "OPS"},
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
		DefaultTemplate: "t.tmpl",
		IssueType:       "Container Vulnerability", Priority: "Medium",
		Labels: []string{"patchwright"},
	}
	got := base.Resolve(config.TicketRoute{
		Name: "sre", When: "true", Project: "SRE", Board: 1, ImageField: "customfield_1",
		IssueType: "Bug", PriorityMap: map[string]string{"urgent": "Highest"},
	})

	if got.Project != "SRE" || got.EffectiveIssueType() != "Bug" {
		t.Errorf("overrides not applied: project=%q issuetype=%q", got.Project, got.EffectiveIssueType())
	}
	// The default template and the deployment-wide settings come through; the
	// tracker comes from the route.
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

// A route picks one image key or the other. Writing one and searching the other
// finds nothing, so every run would duplicate — which is why setting both is a
// configuration error rather than a precedence rule.
func TestRouteImageKeyIsUnambiguous(t *testing.T) {
	base := config.JiraConfig{DefaultTemplate: "t"}

	field := base.Resolve(config.TicketRoute{Name: "r", When: "true", Board: 1, Project: "P",
		ImageField: "customfield_9"})
	if field.ImageLabel || field.ImageField != "customfield_9" {
		t.Errorf("field route: label=%v field=%q", field.ImageLabel, field.ImageField)
	}

	label := base.Resolve(config.TicketRoute{Name: "r", When: "true", Board: 1, Project: "P",
		ImageLabel: boolPtr(true)})
	if !label.ImageLabel || label.ImageField != "" {
		t.Errorf("label route: label=%v field=%q", label.ImageLabel, label.ImageField)
	}

	both := config.JiraConfig{DefaultTemplate: "t", Routes: []config.TicketRoute{
		{Name: "r", When: "true", Board: 1, Project: "P",
			ImageField: "customfield_9", ImageLabel: boolPtr(true)},
	}}
	if err := both.Validate(); err == nil || !strings.Contains(err.Error(), "pick one") {
		t.Errorf("a route setting both image keys was accepted: %v", err)
	}
	neither := config.JiraConfig{DefaultTemplate: "t", Routes: []config.TicketRoute{
		{Name: "r", When: "true", Board: 1, Project: "P"},
	}}
	if err := neither.Validate(); err == nil {
		t.Error("a route with no image key was accepted; every run would duplicate")
	}
}

// Reconciliation has to search every tracker, or a ticket in another project is
// invisible and the next run raises a duplicate.
func TestProjectsListsEveryTracker(t *testing.T) {
	cfg := config.JiraConfig{Routes: []config.TicketRoute{
		{Name: "ops", When: "true", Project: "OPS"},
		{Name: "sre", When: "true", Project: "SRE"},
		{Name: "dup", When: "true", Project: "SRE"}, // same project again
	}}
	got := cfg.Projects()
	if len(got) != 2 || got[0] != "OPS" || got[1] != "SRE" {
		t.Errorf("Projects() = %v, want [OPS SRE], de-duplicated", got)
	}
}

func TestValidateRejectsRoutesThatResolveInvalid(t *testing.T) {
	base := config.JiraConfig{DefaultTemplate: "t"}
	tracker := config.TicketRoute{When: "true", Board: 1, Project: "P", ImageField: "customfield_1"}
	dup1, dup2 := tracker, tracker
	dup1.Name, dup2.Name = "dup", "dup"
	base.Routes = []config.TicketRoute{dup1, dup2}
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
		DefaultTemplate: tmpl,
		Routes: []config.TicketRoute{
			{Name: "ops", When: "owner['team'] != 'sre'", Board: 1, Project: "OPS", ImageField: "customfield_1"},
			{Name: "sre", When: "owner['team'] == 'sre'", Board: 2, Project: "SRE", ImageField: "customfield_1", IssueType: "Bug"},
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
	if !routes["sre"] || !routes["ops"] {
		t.Errorf("drafts routed to %v, want one sre and one ops", routes)
	}
}

// Every draft carries a route, so no write has to guess which tracker it meant.
func TestEveryDraftIsRouted(t *testing.T) {
	dir := t.TempDir()
	tmpl := dir + "/ticket.tmpl"
	if err := os.WriteFile(tmpl, []byte("Summary: s\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPlanner(config.JiraConfig{DefaultTemplate: tmpl, Routes: []config.TicketRoute{
		{Name: "all", When: "true", Board: 1, Project: "OPS", ImageField: "customfield_1"}}})
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

// Work with no configured tracker is reported, not quietly sent to whichever
// board happens to be first: a tracker exists only on a route.
func TestUnroutedWorkIsSkippedWithAReason(t *testing.T) {
	dir := t.TempDir()
	tmpl := dir + "/ticket.tmpl"
	if err := os.WriteFile(tmpl, []byte("Summary: s\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.JiraConfig{
		DefaultTemplate: tmpl,
		Routes: []config.TicketRoute{
			{Name: "platform", When: "owner['class'] == 'platform'",
				Project: "OPS", Board: 1, ImageField: "customfield_1"},
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
			for _, want := range []string{"no ticket route", "engineering/orders"} {
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

// minPriority: a tracker holding a hundred tickets nobody will action this quarter is
// one people stop reading, and it takes the urgent ones down with it.
func TestMinPriorityKeepsLowFindingsOutOfTheTracker(t *testing.T) {
	dir := t.TempDir()
	tmpl := dir + "/t.tmpl"
	if err := os.WriteFile(tmpl, []byte("Summary: s\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := oneRoute(tmpl)
	cfg.MinPriority = "high"
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
	p, err := NewPlanner(config.JiraConfig{DefaultTemplate: tmpl, Routes: []config.TicketRoute{
		{Name: "all", When: "true", Board: 1, Project: "P", ImageField: "customfield_1"}}})
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
		DefaultTemplate: tmpl,
		MinPriority:     "low",
		Routes: []config.TicketRoute{
			{Name: "strict", When: "owner['team'] == 'sre'", Board: 2, Project: "SRE",
				ImageField: "customfield_1", MinPriority: "urgent"},
			{Name: "rest", When: "true", Board: 1, Project: "P", ImageField: "customfield_1"},
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
		cfg := oneRoute("t")
		cfg.MinPriority = bad
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
	ok := oneRoute("t")
	ok.MinPriority = "high"
	if err := ok.Validate(); err != nil {
		t.Errorf("a valid threshold was rejected: %v", err)
	}
}

// boolPtr is for the pointer fields a route uses to distinguish "not set" from
// "set false".
func boolPtr(b bool) *bool { return &b }

// oneRoute is the config shape a test needs when it does not care about routing:
// a default template plus a single tracker everything matches.
func oneRoute(tmpl string) config.JiraConfig {
	return config.JiraConfig{
		DefaultTemplate: tmpl,
		Routes: []config.TicketRoute{
			{Name: "all", When: "true", Board: 1, Project: "PROJ", ImageField: "customfield_1"},
		},
	}
}

// Wording is what teams disagree about, so a route can carry its own template
// while sharing every other setting. A route that says nothing gets the default.
func TestRouteTemplateOverridesTheDefault(t *testing.T) {
	dir := t.TempDir()
	def, own := dir+"/default.tmpl", dir+"/sre.tmpl"
	if err := os.WriteFile(def, []byte("Summary: default {{ .ServiceName }}\n\nthe shared body\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("Summary: sre {{ .ServiceName }}\n\nthe sre body\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPlanner(config.JiraConfig{
		DefaultTemplate: def,
		Routes: []config.TicketRoute{
			{Name: "sre", When: "owner['team'] == 'sre'", Board: 2, Project: "SRE",
				ImageField: "customfield_1", Template: own},
			{Name: "rest", When: "true", Board: 1, Project: "OPS", ImageField: "customfield_1"},
		},
	})
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	plan, err := p.Plan([]sink.FindingView{
		routedView("platform", "sre", "acr.io/sre-thing"),
		routedView("platform", "cpo", "acr.io/other-thing"),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	bodies := map[string]string{}
	for _, d := range plan.Drafts {
		bodies[d.Route] = d.Summary + "|" + d.Description
	}
	if !strings.Contains(bodies["sre"], "the sre body") {
		t.Errorf("sre route did not use its own template: %q", bodies["sre"])
	}
	if !strings.Contains(bodies["rest"], "the shared body") {
		t.Errorf("route without a template did not fall back to the default: %q", bodies["rest"])
	}
}

// A route naming a template that does not parse must fail at startup, not on the
// first ticket of the month for one team.
func TestRouteTemplateIsParsedAtStartup(t *testing.T) {
	dir := t.TempDir()
	def, broken := dir+"/default.tmpl", dir+"/broken.tmpl"
	if err := os.WriteFile(def, []byte("Summary: s\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(broken, []byte("Summary: s\n\n{{ .Nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewPlanner(config.JiraConfig{
		DefaultTemplate: def,
		Routes: []config.TicketRoute{
			{Name: "sre", When: "true", Board: 1, Project: "SRE",
				ImageField: "customfield_1", Template: broken},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "sre") {
		t.Errorf("a route template that does not parse was accepted: %v", err)
	}
}
