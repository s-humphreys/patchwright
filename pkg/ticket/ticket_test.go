package ticket

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// newTestPlanner builds a planner over a minimal template that echoes the fields
// a test cares about, so assertions are about planning rather than wording.
func newTestPlanner(t *testing.T, tmpl string) *Planner {
	t.Helper()
	if tmpl == "" {
		tmpl = "Summary: Upgrade {{ .ServiceName }}{{ if .Upgrade }} to {{ .Upgrade.Latest }}{{ end }}\n\nimages={{ .ImageCount }}\n"
	}
	path := filepath.Join(t.TempDir(), "t.tmpl")
	if err := os.WriteFile(path, []byte(tmpl), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPlanner(config.JiraConfig{
		Board: 1, Project: "PROJ", Template: path, ImageField: "customfield_1",
	})
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	return p
}

func finding(repo string, opts ...func(*sink.FindingView)) sink.FindingView {
	f := sink.FindingView{
		Image:              "reg.example.com/" + repo + ":1.0.0",
		Repository:         repo,
		Actionable:         true,
		Priority:           "high",
		RemediationChecked: true,
		Counts:             map[string]int{},
		Dimensions:         map[string][]string{},
		Upgrade: &sink.UpgradeView{
			Kind: "image", Name: repo, Current: "1.0.0", Latest: "2.0.0",
			Available: true, Resolved: true, Actionable: true,
		},
	}
	for _, o := range opts {
		o(&f)
	}
	return f
}

// requireUpgrade must skip only what genuinely has nowhere to go, and each skip
// needs a distinct reason: "on the latest version" and "we could not find out"
// look identical in the data but demand opposite responses.
func TestPlanSkipReasons(t *testing.T) {
	p := newTestPlanner(t, "")

	cases := []struct {
		name       string
		mutate     func(*sink.FindingView)
		wantSkip   bool
		wantReason string
	}{
		{"has an upgrade", func(f *sink.FindingView) {}, false, ""},
		{
			"on the latest version",
			func(f *sink.FindingView) { f.Upgrade.Available = false },
			true, "already on the latest",
		},
		{
			"versions unresolved",
			func(f *sink.FindingView) { f.Upgrade.Resolved = false; f.Upgrade.Available = false },
			true, "could not be resolved",
		},
		{
			"detection ran, nothing resolved",
			func(f *sink.FindingView) { f.Upgrade = nil },
			true, "could not resolve any version",
		},
		{
			"detection never ran",
			func(f *sink.FindingView) { f.Upgrade = nil; f.RemediationChecked = false },
			true, "did not run",
		},
	}
	for _, c := range cases {
		plan, err := p.Plan([]sink.FindingView{finding("acme/app", c.mutate)})
		if err != nil {
			t.Fatalf("%s: Plan: %v", c.name, err)
		}
		if c.wantSkip {
			if len(plan.Skips) != 1 || len(plan.Drafts) != 0 {
				t.Errorf("%s: got %d skips %d drafts, want 1 skip 0 drafts", c.name, len(plan.Skips), len(plan.Drafts))
				continue
			}
			if !strings.Contains(plan.Skips[0].Reason, c.wantReason) {
				t.Errorf("%s: reason %q does not mention %q", c.name, plan.Skips[0].Reason, c.wantReason)
			}
		} else if len(plan.Drafts) != 1 || len(plan.Skips) != 0 {
			t.Errorf("%s: got %d drafts %d skips, want 1 draft 0 skips", c.name, len(plan.Drafts), len(plan.Skips))
		}
	}
}

// requireUpgrade: false raises them anyway, for teams that want the tracking.
func TestPlanRequireUpgradeDisabled(t *testing.T) {
	off := false
	path := filepath.Join(t.TempDir(), "t.tmpl")
	if err := os.WriteFile(path, []byte("Summary: x\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPlanner(config.JiraConfig{
		Board: 1, Project: "PROJ", Template: path, ImageField: "cf", RequireUpgrade: &off,
	})
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	plan, err := p.Plan([]sink.FindingView{finding("acme/app", func(f *sink.FindingView) { f.Upgrade = nil })})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 || len(plan.Skips) != 0 {
		t.Errorf("got %d drafts %d skips, want 1 draft 0 skips", len(plan.Drafts), len(plan.Skips))
	}
}

// Suppressed and non-actionable findings must never become tickets: policy has
// already decided about them, and ticketing would undo that decision.
func TestPlanIgnoresSuppressedAndNonActionable(t *testing.T) {
	p := newTestPlanner(t, "")
	plan, err := p.Plan([]sink.FindingView{
		finding("acme/suppressed", func(f *sink.FindingView) { f.Suppressed = true }),
		finding("acme/inactionable", func(f *sink.FindingView) { f.Actionable = false }),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 0 || len(plan.Skips) != 0 {
		t.Errorf("got %d drafts %d skips, want none of either", len(plan.Drafts), len(plan.Skips))
	}
}

// Findings sharing a deployment source are fixed by one change, so they belong
// on one ticket.
func TestPlanGroupsBySharedSource(t *testing.T) {
	shared := func(f *sink.FindingView) {
		f.Upgrade.Manager = "flux-operator"
		f.Upgrade.Actionable = false
		f.Upgrade.Managed = "operator"
	}
	p := newTestPlanner(t, "")
	plan, err := p.Plan([]sink.FindingView{
		finding("fluxcd/source-controller", shared),
		finding("fluxcd/helm-controller", shared),
		finding("acme/standalone"),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 2 {
		t.Fatalf("got %d drafts, want 2 (one grouped, one standalone)", len(plan.Drafts))
	}
	var grouped *Draft
	for i := range plan.Drafts {
		if len(plan.Drafts[i].Images) == 2 {
			grouped = &plan.Drafts[i]
		}
	}
	if grouped == nil {
		t.Fatal("no draft covering both flux images")
	}
	if got := grouped.Images; got[0] != "fluxcd/helm-controller" || got[1] != "fluxcd/source-controller" {
		t.Errorf("grouped images not sorted/complete: %v", got)
	}
}

// A ticket covering several images must not be titled after one of them, nor
// claim a single target version when they differ. A ticket saying "Upgrade
// helm-controller to 1.6.3" that actually moves six controllers misdirects
// whoever picks it up.
func TestGroupedTicketDoesNotClaimOneImagesVersion(t *testing.T) {
	p := newTestPlanner(t, "")
	mk := func(repo, latest string) sink.FindingView {
		return finding(repo, func(f *sink.FindingView) {
			f.Upgrade.Manager = "flux-operator"
			f.Upgrade.Latest = latest
			f.Upgrade.Actionable = false
			f.Upgrade.Managed = "operator"
		})
	}
	plan, err := p.Plan([]sink.FindingView{
		mk("fluxcd/helm-controller", "1.6.3"),
		mk("fluxcd/source-controller", "1.9.4"),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("got %d drafts, want 1", len(plan.Drafts))
	}
	got := plan.Drafts[0].Summary
	for _, forbidden := range []string{"1.6.3", "1.9.4", "helm-controller", "source-controller"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("grouped summary %q must not name a single image or its version (%q)", got, forbidden)
		}
	}
	if !strings.Contains(got, "flux-operator") {
		t.Errorf("grouped summary %q should name the shared subject", got)
	}
}

// When every image does share a target version, the single-version summary is
// truthful and should be used.
func TestGroupedTicketUsesSharedVersionWhenGenuinelyShared(t *testing.T) {
	p := newTestPlanner(t, "")
	mk := func(repo string) sink.FindingView {
		return finding(repo, func(f *sink.FindingView) {
			f.Upgrade.Source = "https://charts.example.com/nats"
			f.Upgrade.Kind = "chart"
			f.Upgrade.Name = "nats"
		})
	}
	plan, err := p.Plan([]sink.FindingView{mk("natsio/nats-a"), mk("natsio/nats-b")})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if got := plan.Drafts[0].Summary; !strings.Contains(got, "2.0.0") {
		t.Errorf("summary %q should state the shared target version", got)
	}
}

// The same CVE in a shared base layer must be listed once, not once per image.
func TestTemplateDataDeduplicatesCVEsAndOrdersByEPSS(t *testing.T) {
	vulns := []sink.VulnView{
		{ID: "CVE-1", Severity: "critical", FixAvailable: true, EPSS: 0.01},
		{ID: "CVE-2", Severity: "critical", FixAvailable: true, EPSS: 0.90},
		{ID: "CVE-3", Severity: "critical", FixAvailable: false, EPSS: 0.99}, // no fix: excluded
		{ID: "CVE-4", Severity: "high", FixAvailable: true, EPSS: 0.50},      // not critical
	}
	mk := func(repo string) sink.FindingView {
		return finding(repo, func(f *sink.FindingView) {
			f.Upgrade.Source = "shared"
			f.Vulns = vulns
		})
	}
	d := newTemplateData(ticketGroup{primary: []sink.FindingView{mk("a/one"), mk("b/two")}})

	if len(d.FixableCriticals) != 2 {
		t.Fatalf("got %d fixable criticals, want 2 (deduped, fix-available criticals only): %+v", len(d.FixableCriticals), d.FixableCriticals)
	}
	if d.FixableCriticals[0].ID != "CVE-2" {
		t.Errorf("highest EPSS should lead, got %s", d.FixableCriticals[0].ID)
	}
	if d.MaxEPSS != 0.99 {
		t.Errorf("MaxEPSS = %v, want 0.99 (across all CVEs, fixable or not)", d.MaxEPSS)
	}
}

// A template must not present zero counts as evidence when the provider never
// assessed the images, so the flag has to reach the template data.
func TestTemplateDataCarriesProviderAssessed(t *testing.T) {
	unassessed := newTemplateData(ticketGroup{primary: []sink.FindingView{finding("a/one")}})
	if unassessed.ProviderAssessed {
		t.Error("provider_assessed false in findings should stay false")
	}
	assessed := newTemplateData(ticketGroup{primary: []sink.FindingView{
		finding("a/one", func(f *sink.FindingView) { f.ProviderAssessed = true; f.Counts["critical"] = 3 }),
	}})
	if !assessed.ProviderAssessed || assessed.CriticalCount != 3 {
		t.Errorf("assessed=%v criticals=%d, want true/3", assessed.ProviderAssessed, assessed.CriticalCount)
	}
}

func TestSplitSummary(t *testing.T) {
	summary, body, err := splitSummary("Summary: Upgrade thing to 2.0\n\nBody text here.\n")
	if err != nil {
		t.Fatalf("splitSummary: %v", err)
	}
	if summary != "Upgrade thing to 2.0" {
		t.Errorf("summary = %q", summary)
	}
	if body != "Body text here." {
		t.Errorf("body = %q", body)
	}

	for _, bad := range []string{
		"Upgrade thing\n\nbody",  // no Summary: prefix
		"Summary: only one line", // no body
		"Summary:\n\nbody",       // empty summary
	} {
		if _, _, err := splitSummary(bad); err == nil {
			t.Errorf("splitSummary(%q): want error, got nil", bad)
		}
	}
}

func TestNewPlannerRejectsUnusableConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.tmpl")
	if err := os.WriteFile(path, []byte("Summary: x\n\ny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]config.JiraConfig{
		"no board":           {Project: "P", Template: path, ImageField: "cf"},
		"no project":         {Board: 1, Template: path, ImageField: "cf"},
		"no template":        {Board: 1, Project: "P", ImageField: "cf"},
		"no image key":       {Board: 1, Project: "P", Template: path},
		"both image keys":    {Board: 1, Project: "P", Template: path, ImageField: "cf", ImageLabel: true},
		"missing template f": {Board: 1, Project: "P", Template: "/nope/nope.tmpl", ImageField: "cf"},
	}
	for name, cfg := range cases {
		if _, err := NewPlanner(cfg); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestImageLabelIsJiraSafe(t *testing.T) {
	if got, want := ImageLabel("fluxcd/source-controller"), "patchwright-fluxcd_source-controller"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := ImageLabel("a/b:1.0 x"); strings.ContainsAny(got, " :/") {
		t.Errorf("label %q still contains characters Jira labels reject", got)
	}
}

// Some controllers give each managed package its own object, so grouping on the
// raw source produces one ticket per package. Collapsing the object name keeps
// families together, without touching chart URLs, GitOps paths, or the
// registry paths that happen to have the same number of slashes.
func TestCollapseObjectRef(t *testing.T) {
	cases := map[string]string{
		// Kubernetes object references collapse to Kind/namespace.
		"ProviderRevision/crossplane-system/provider-azuread-7abdea7d":  "ProviderRevision/crossplane-system",
		"FunctionRevision/crossplane-system/function-sequencer-8b9e4e6": "FunctionRevision/crossplane-system",
		"Kiali/istio-system/kiali":                                      "Kiali/istio-system",
		// Everything else is left exactly as it is.
		"ghcr.io/controlplaneio-fluxcd/flux-operator": "ghcr.io/controlplaneio-fluxcd/flux-operator",
		"https://charts.crossplane.io/stable":         "https://charts.crossplane.io/stable",
		"https://a.example.com/x/y/z":                 "https://a.example.com/x/y/z",
		"flux-operator":                               "flux-operator",
		"bases/apps/example":                          "bases/apps/example",
	}
	for in, want := range cases {
		if got := collapseObjectRef(in); got != want {
			t.Errorf("collapseObjectRef(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGroupNoun(t *testing.T) {
	cases := map[string]string{
		"ProviderRevision/crossplane-system":  "providers",
		"FunctionRevision/crossplane-system":  "functions",
		"Kiali/istio-system":                  "kialis",
		"flux-operator":                       "images",
		"https://charts.crossplane.io/stable": "images",
		"bases/apps/example":                  "images",
	}
	for in, want := range cases {
		if got := groupNoun(in); got != want {
			t.Errorf("groupNoun(%q) = %q, want %q", in, got, want)
		}
	}
}

// The whole point of collapsing: a family becomes one ticket that still lists
// each package's own version move.
func TestPlanGroupsPackageFamiliesIntoOneTicket(t *testing.T) {
	p := newTestPlanner(t, "Summary: Upgrade {{ .ServiceName }} {{ .GroupNoun }} ({{ .ImageCount }})\n\n{{ range .Upgrades }}{{ .Repo }}:{{ .Current }}->{{ .Latest }}\n{{ end }}")
	mk := func(repo, latest, obj string) sink.FindingView {
		return finding(repo, func(f *sink.FindingView) {
			f.Upgrade.Source = "ProviderRevision/crossplane-system/" + obj
			f.Upgrade.Latest = latest
		})
	}
	plan, err := p.Plan([]sink.FindingView{
		mk("crossplane-contrib/provider-azuread", "2.4.0", "provider-azuread-aaa"),
		mk("crossplane-contrib/provider-kubernetes", "1.2.1", "provider-kubernetes-bbb"),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("got %d drafts, want 1 (one family, one ticket)", len(plan.Drafts))
	}
	d := plan.Drafts[0]
	if want := "Upgrade crossplane-system providers (2)"; d.Summary != want {
		t.Errorf("summary = %q, want %q", d.Summary, want)
	}
	// Each package's own bump must survive the grouping.
	for _, want := range []string{"provider-azuread:1.0.0->2.4.0", "provider-kubernetes:1.0.0->1.2.1"} {
		if !strings.Contains(d.Description, want) {
			t.Errorf("description missing %q:\n%s", want, d.Description)
		}
	}
}

// A ticket-level change target must only appear when every image shares it.
// Collapsed families do not: each Crossplane package has its own
// ProviderRevision, so naming the first would misdescribe the other six.
func TestSharedChangeTargetOnlyWhenGenuinelyShared(t *testing.T) {
	mkObj := func(repo, obj string) sink.FindingView {
		return finding(repo, func(f *sink.FindingView) {
			f.Upgrade.Source = "ProviderRevision/crossplane-system/" + obj
		})
	}
	collapsed := newTemplateData(ticketGroup{primary: []sink.FindingView{
		mkObj("contrib/provider-a", "provider-a-aaa"),
		mkObj("contrib/provider-b", "provider-b-bbb"),
	}})
	if collapsed.Source != "" {
		t.Errorf("Source = %q, want empty: the group's members have different targets", collapsed.Source)
	}
	// Each member must still carry its own, or the ticket says nothing about where
	// to make the change.
	for _, u := range collapsed.Upgrades {
		if u.Source == "" {
			t.Errorf("%s has no per-image change target", u.Repo)
		}
	}

	mkShared := func(repo string) sink.FindingView {
		return finding(repo, func(f *sink.FindingView) {
			f.Upgrade.Source = "https://dev.example.com/_git/infra"
			f.Upgrade.SourcePath = "bases/apps/example"
		})
	}
	shared := newTemplateData(ticketGroup{primary: []sink.FindingView{mkShared("natsio/a"), mkShared("natsio/b")}})
	if shared.Source != "https://dev.example.com/_git/infra" || shared.SourcePath != "bases/apps/example" {
		t.Errorf("shared target not surfaced: source=%q path=%q", shared.Source, shared.SourcePath)
	}
}

// The repository URL and the path must stay separate all the way to the template:
// joined with kustomize's "//" the result looks like a link and is not one.
func TestSourcePathStaysSeparateFromURL(t *testing.T) {
	d := newTemplateData(ticketGroup{primary: []sink.FindingView{
		finding("acme/app", func(f *sink.FindingView) {
			f.Upgrade.Source = "https://dev.example.com/_git/infra"
			f.Upgrade.SourcePath = "bases/app"
		}),
	}})
	if strings.Contains(d.Source, "//bases") {
		t.Errorf("Source %q has the path joined into it", d.Source)
	}
	if d.SourcePath != "bases/app" {
		t.Errorf("SourcePath = %q, want bases/app", d.SourcePath)
	}
}

// Exclusions keep work out of ticket creation without hiding it: excluded
// findings are reported as skipped, with the configured reason, so "why was this
// not ticketed?" is answerable from the output rather than from the config file.
func TestPlanExclusions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.tmpl")
	if err := os.WriteFile(path, []byte("Summary: Upgrade {{ .ServiceName }}\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPlanner(config.JiraConfig{
		Board: 1, Project: "PROJ", Template: path, ImageField: "cf",
		Exclude: []config.ExcludeRule{{
			Name:   "crossplane",
			When:   "dimensions['namespace'].exists(n, n == 'crossplane-system')",
			Reason: "upgraded on their own cadence",
		}},
	})
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}

	inNS := finding("contrib/provider-azuread", func(f *sink.FindingView) {
		f.Dimensions["namespace"] = []string{"crossplane-system"}
	})
	elsewhere := finding("acme/app", func(f *sink.FindingView) {
		f.Dimensions["namespace"] = []string{"apps"}
	})

	plan, err := p.Plan([]sink.FindingView{inNS, elsewhere})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 || plan.Drafts[0].Images[0] != "acme/app" {
		t.Fatalf("got %d drafts (%v), want only the non-excluded one", len(plan.Drafts), plan.Drafts)
	}
	if len(plan.Skips) != 1 {
		t.Fatalf("got %d skips, want 1", len(plan.Skips))
	}
	if got := plan.Skips[0].Reason; !strings.Contains(got, `"crossplane"`) || !strings.Contains(got, "own cadence") {
		t.Errorf("skip reason %q should name the rule and its reason", got)
	}
}

// An excluded finding must report exclusion, not "nothing to upgrade to": the
// second is a statement about the world and would be the wrong explanation.
func TestExclusionTakesPrecedenceOverUpgradeCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.tmpl")
	if err := os.WriteFile(path, []byte("Summary: x\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewPlanner(config.JiraConfig{
		Board: 1, Project: "PROJ", Template: path, ImageField: "cf",
		Exclude: []config.ExcludeRule{{Name: "all", When: "true"}},
	})
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	plan, err := p.Plan([]sink.FindingView{
		finding("acme/app", func(f *sink.FindingView) { f.Upgrade.Available = false }),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Skips) != 1 {
		t.Fatalf("got %d skips, want 1", len(plan.Skips))
	}
	if got := plan.Skips[0].Reason; !strings.Contains(got, "excluded") {
		t.Errorf("reason %q should report exclusion, not the upgrade state", got)
	}
}

// Exclusions evaluate the same variables as policy rules, so an expression a
// user already knows works here too.
func TestExclusionSharesThePolicyVocabulary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.tmpl")
	if err := os.WriteFile(path, []byte("Summary: x\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, expr := range []string{
		"image.registry == 'xpkg.crossplane.io'",
		"owner['team'] == 'platform-team'",
		"counts['critical'] > 100",
		"labels.exists(k, k == 'nope')",
		"vulns.exists(v, v.kev)",
		"risk > 10000.0",
		"live && reconciled",
		"upgrade_available",
	} {
		p, err := NewPlanner(config.JiraConfig{
			Board: 1, Project: "PROJ", Template: path, ImageField: "cf",
			Exclude: []config.ExcludeRule{{Name: "r", When: expr}},
		})
		if err != nil {
			t.Errorf("expression %q rejected: %v", expr, err)
			continue
		}
		if _, err := p.Plan([]sink.FindingView{finding("acme/app")}); err != nil {
			t.Errorf("expression %q failed to evaluate: %v", expr, err)
		}
	}
}

func TestExclusionRejectsBadRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.tmpl")
	if err := os.WriteFile(path, []byte("Summary: x\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, rule := range map[string]config.ExcludeRule{
		"no name":     {When: "true"},
		"no when":     {Name: "r"},
		"not boolean": {Name: "r", When: "image.registry"},
		"bad syntax":  {Name: "r", When: "dimensions['ns' =="},
		"unknown var": {Name: "r", When: "nonesuch == 1"},
	} {
		_, err := NewPlanner(config.JiraConfig{
			Board: 1, Project: "PROJ", Template: path, ImageField: "cf",
			Exclude: []config.ExcludeRule{rule},
		})
		if err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

// Six Flux controllers are owned by flux-operator, whose own tag is owned by its
// chart. Left alone that is two tickets, neither actionable. The ticket must ask
// for the one change a human can make, and list the rest as consequences.
func TestMergeChainsFoldsManagedImagesIntoTheirManager(t *testing.T) {
	p := newTestPlanner(t, "Summary: Upgrade {{ .ServiceName }} to {{ if .Upgrade }}{{ .Upgrade.Latest }}{{ else }}latest{{ end }}\n\napply={{ len .Upgrades }} fixes={{ len .Fixes }}\n")

	controller := func(repo, latest string) sink.FindingView {
		return finding(repo, func(f *sink.FindingView) {
			f.Upgrade.Manager = "flux-operator"
			f.Upgrade.Managed = "operator"
			f.Upgrade.Actionable = false
			f.Upgrade.Latest = latest
		})
	}
	operator := finding("controlplaneio-fluxcd/flux-operator", func(f *sink.FindingView) {
		f.Upgrade.Source = "ghcr.io/controlplaneio-fluxcd/flux-operator"
		f.Upgrade.Managed = "helm"
		f.Upgrade.Actionable = false
		f.Upgrade.Current = "v0.33.0"
		f.Upgrade.Latest = "0.58.0"
	})

	plan, err := p.Plan([]sink.FindingView{
		controller("fluxcd/helm-controller", "1.6.3"),
		controller("fluxcd/source-controller", "1.9.4"),
		operator,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("got %d drafts, want 1 merged ticket: %v", len(plan.Drafts), summaries(plan.Drafts))
	}
	d := plan.Drafts[0]

	// The ticket asks for the operator bump, not the controllers'.
	if want := "Upgrade flux-operator to 0.58.0"; d.Summary != want {
		t.Errorf("summary = %q, want %q", d.Summary, want)
	}
	if !strings.Contains(d.Description, "apply=1") {
		t.Errorf("should apply exactly one upgrade (the manager): %s", d.Description)
	}
	if !strings.Contains(d.Description, "fixes=2") {
		t.Errorf("should list both controllers as consequences: %s", d.Description)
	}
	// Idempotency must still cover every image the ticket accounts for.
	if len(d.Images) != 3 {
		t.Errorf("got %d images, want 3 so the duplicate check covers them all: %v", len(d.Images), d.Images)
	}
}

// With no Manager resolved there is nothing to merge on. The live source names
// the manager from a label or the CR's own labels; where it cannot, the tool must
// not invent one from a Kind or a URL, so the groups stay separate.
func TestMergeChainsDeclinesWhenTheManagerIsNotNamed(t *testing.T) {
	p := newTestPlanner(t, "")
	for name, source := range map[string]string{
		"object reference": "Kiali/istio-system/kiali",
		"repository URL":   "https://kiali.org/helm-charts",
		"registry path":    "ghcr.io/org/thing",
	} {
		managed := finding("kiali/kiali", func(f *sink.FindingView) {
			f.Upgrade.Source = source // no Manager resolved
			f.Upgrade.Managed = "operator"
			f.Upgrade.Actionable = false
		})
		candidate := finding("kiali/kiali-operator")
		plan, err := p.Plan([]sink.FindingView{managed, candidate})
		if err != nil {
			t.Fatalf("%s: Plan: %v", name, err)
		}
		if len(plan.Drafts) != 2 {
			t.Errorf("%s: got %d drafts, want 2 (no merge without a named manager)", name, len(plan.Drafts))
		}
	}
}

// The Kiali case the Manager field exists for: the CR labels name the operator,
// so the two tickets become one asking for the operator upgrade.
func TestMergeChainsUsesManagerFromCustomResourceLabels(t *testing.T) {
	p := newTestPlanner(t, "Summary: Upgrade {{ .ServiceName }} to {{ if .Upgrade }}{{ .Upgrade.Latest }}{{ else }}latest{{ end }}\n\napply={{ len .Upgrades }} fixes={{ len .Fixes }}\n")
	managed := finding("kiali/kiali", func(f *sink.FindingView) {
		f.Upgrade.Source = "Kiali/istio-system/kiali"
		f.Upgrade.Manager = "kiali-operator" // resolved from the CR's labels
		f.Upgrade.Managed = "operator"
		f.Upgrade.Actionable = false
	})
	operator := finding("kiali/kiali-operator", func(f *sink.FindingView) {
		f.Upgrade.Kind = "chart"
		f.Upgrade.Name = "kiali-operator"
		f.Upgrade.Latest = "2.30.0"
		f.Upgrade.Source = "https://kiali.org/helm-charts"
	})
	plan, err := p.Plan([]sink.FindingView{managed, operator})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("got %d drafts, want 1: %v", len(plan.Drafts), summaries(plan.Drafts))
	}
	if want := "Upgrade kiali-operator to 2.30.0"; plan.Drafts[0].Summary != want {
		t.Errorf("summary = %q, want %q", plan.Drafts[0].Summary, want)
	}
	if !strings.Contains(plan.Drafts[0].Description, "fixes=1") {
		t.Errorf("the kiali image should be listed as a consequence: %s", plan.Drafts[0].Description)
	}
}

// With the manager absent from the finding set there is nothing to merge into,
// and the managed group must still produce its own ticket rather than vanishing.
func TestMergeChainsKeepsGroupWhenManagerIsAbsent(t *testing.T) {
	p := newTestPlanner(t, "")
	plan, err := p.Plan([]sink.FindingView{
		finding("fluxcd/source-controller", func(f *sink.FindingView) {
			f.Upgrade.Manager = "flux-operator"
			f.Upgrade.Managed = "operator"
			f.Upgrade.Actionable = false
		}),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("got %d drafts, want 1", len(plan.Drafts))
	}
}

func summaries(ds []Draft) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Summary
	}
	return out
}

// A ticket must be raised at a priority matching the work, so the draft has to
// carry it. For a grouped ticket that is the highest across its findings: the
// group is one piece of work, and its urgency is set by its worst member.
func TestDraftCarriesHighestPriorityInGroup(t *testing.T) {
	p := newTestPlanner(t, "")
	mk := func(repo, priority string) sink.FindingView {
		return finding(repo, func(f *sink.FindingView) {
			f.Priority = priority
			f.Upgrade.Source = "https://charts.example.com/thing"
		})
	}
	plan, err := p.Plan([]sink.FindingView{
		mk("acme/a", "low"), mk("acme/b", "urgent"), mk("acme/c", "medium"),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("got %d drafts, want 1", len(plan.Drafts))
	}
	if plan.Drafts[0].Priority != "urgent" {
		t.Errorf("priority = %q, want urgent (the worst in the group)", plan.Drafts[0].Priority)
	}
}
