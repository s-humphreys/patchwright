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
		f.Upgrade.Source = "flux-operator"
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
			f.Upgrade.Source = "flux-operator"
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
	d := newTemplateData([]sink.FindingView{mk("a/one"), mk("b/two")})

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
	unassessed := newTemplateData([]sink.FindingView{finding("a/one")})
	if unassessed.ProviderAssessed {
		t.Error("provider_assessed false in findings should stay false")
	}
	assessed := newTemplateData([]sink.FindingView{
		finding("a/one", func(f *sink.FindingView) { f.ProviderAssessed = true; f.Counts["critical"] = 3 }),
	})
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
		"Kiali/istio-monitoring/kiali":                                  "Kiali/istio-monitoring",
		// Everything else is left exactly as it is.
		"ghcr.io/controlplaneio-fluxcd/flux-operator": "ghcr.io/controlplaneio-fluxcd/flux-operator",
		"https://charts.crossplane.io/stable":         "https://charts.crossplane.io/stable",
		"https://a.example.com/x/y/z":                 "https://a.example.com/x/y/z",
		"flux-operator":                               "flux-operator",
		"bases/argo-events/event-bus":                 "bases/argo-events/event-bus",
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
		"Kiali/istio-monitoring":              "kialis",
		"flux-operator":                       "images",
		"https://charts.crossplane.io/stable": "images",
		"bases/argo-events/event-bus":         "images",
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
