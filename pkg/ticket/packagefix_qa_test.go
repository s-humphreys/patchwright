package ticket

import (
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// stillCarrying is the service on its newest base, still scanned, running and
// carrying brotli, but with brotli's packages unnamed this run: the image scan
// that names them failed, so FixableInBuild is false and no package draft claims
// the open ticket.
func stillCarrying(repo string) sink.FindingView {
	f := onNewestBase(repo)
	unnamed := brotli
	unnamed.Packages = nil
	f.Vulns = []sink.VulnView{unnamed}
	f.Scanned, f.ProviderAssessed = true, true
	f.Liveness = &sink.LivenessView{Live: true}
	return f
}

// Prod renders summaries from a template with no package branch, so a package
// ticket's summary names no CVEs. Such a ticket was raised because the image is
// already on its newest base; "already on the latest available version" is
// therefore true from the day it was raised and is no evidence the package moved.
// It must not be closed while the CVE it was raised for is still reported.
func TestQAPackageTicketWithCVELessSummaryIsNotClosedWhileTheCVEIsReported(t *testing.T) {
	first, err := newTestPlanner(t, "").Plan([]sink.FindingView{onNewestBase("acme/scoring", brotli)})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Drafts) != 1 || len(summaryCVEs(first.Drafts[0].Summary)) != 0 {
		t.Fatalf("precondition: one draft with a CVE-less summary, got %+v", first.Drafts)
	}
	ticket := Existing{Key: "PROJ-1", Summary: first.Drafts[0].Summary, Category: "new"}

	cases := map[string]func() ReconcileInput{
		"image scan lapsed this run": func() ReconcileInput {
			next, err := newTestPlanner(t, "").Plan([]sink.FindingView{stillCarrying("acme/scoring")})
			if err != nil {
				t.Fatal(err)
			}
			return ReconcileInput{Drafts: next.Drafts, Skipped: next.Skips,
				Findings: []sink.FindingView{stillCarrying("acme/scoring")}}
		},
		// The likeliest route in prod: the ticket was raised while a newer base was on
		// offer, then a base bump (Renovate) moved the image onto its newest base. The
		// CVE is still in the app layer, but with no ToRef the differential leaves
		// OriginDetermined false, so no package draft claims the ticket.
		"base bumped, package not moved": func() ReconcileInput {
			f := onNewestBase("acme/scoring", brotli)
			f.Vulns[0].OriginDetermined = false
			f.Scanned, f.ProviderAssessed, f.Liveness = true, true, &sink.LivenessView{Live: true}
			next, err := newTestPlanner(t, "").Plan([]sink.FindingView{f})
			if err != nil {
				t.Fatal(err)
			}
			return ReconcileInput{Drafts: next.Drafts, Skipped: next.Skips, Findings: []sink.FindingView{f}}
		},
		"priority threshold now excludes it": func() ReconcileInput {
			f := onNewestBase("acme/scoring", brotli)
			f.Scanned, f.ProviderAssessed, f.Liveness = true, true, &sink.LivenessView{Live: true}
			return ReconcileInput{Findings: []sink.FindingView{f}, Skipped: []Skip{{
				Image: f.Image, Repository: f.Repository, Policy: true,
				Reason: `highest priority in this change is "high", below the minimum ticket priority "urgent"`,
			}}}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			in := mk()
			in.Config = autoCloseCfg()
			in.OpenByImage = map[string][]Existing{"acme/scoring": {ticket}}
			for _, a := range Reconcile(in) {
				if a.Kind == ActionClose || a.Reason == ReasonUpgradeLanded {
					t.Errorf("package ticket closed/called done as %q while %s is still reported: %s",
						a.Reason, brotli.ID, a.Message)
				}
			}
		})
	}
}

// A summary names at most three CVEs and "and N more". Closing once the named
// three are gone treats a partial fix as the whole one.
func TestQAFixLandedDoesNotCloseWhileAnUnnamedCVEOfTheTicketRemains(t *testing.T) {
	mk := func(id string, eps float64) sink.VulnView {
		v := brotli
		v.ID, v.EPSS, v.KEV = id, eps, false
		v.Packages = []sink.PackageView{{Name: "libfoo" + id[len(id)-1:], Ecosystem: "ubuntu", FixedIn: "2.0"}}
		return v
	}
	vs := []sink.VulnView{mk("CVE-2026-90001", 0.99), mk("CVE-2026-90002", 0.98), mk("CVE-2026-90003", 0.97), mk("CVE-2026-90004", 0.6)}
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{onNewestBase("acme/scoring", vs...)})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("want one draft, got %d (skips %+v)", len(plan.Drafts), plan.Skips)
	}
	summary := plan.Drafts[0].Summary
	if strings.Contains(summary, "CVE-2026-90004") || !strings.Contains(summary, "and 1 more") {
		t.Fatalf("precondition: the fourth CVE is not named in %q", summary)
	}

	// The three named are gone; the fourth is still reported, its package unnamed this run.
	left := stillCarrying("acme/scoring")
	left.Vulns[0] = mk("CVE-2026-90004", 0.6)
	left.Vulns[0].Packages = nil
	next, err := bundledPlanner(t).Plan([]sink.FindingView{left})
	if err != nil {
		t.Fatal(err)
	}
	got := Reconcile(ReconcileInput{
		Config: autoCloseCfg(), Drafts: next.Drafts, Skipped: next.Skips, Findings: []sink.FindingView{left},
		OpenByImage: map[string][]Existing{"acme/scoring": {{Key: "PROJ-1", Summary: summary, Category: "new"}}},
	})
	for _, a := range got {
		if a.Kind == ActionClose {
			t.Errorf("closed as %q with CVE-2026-90004 still reported: %s", a.Reason, a.Message)
		}
	}
}

// Retarget must converge: once the ticket carries the package summary, the next
// run leaves it alone, including when EPSS reorders which CVEs lead the summary.
func TestQARetargetConverges(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{onNewestBase("acme/scoring", brotli)})
	if err != nil {
		t.Fatal(err)
	}
	in := ReconcileInput{
		Config: autoCloseCfg(), Drafts: plan.Drafts, Skipped: plan.Skips,
		Findings:    []sink.FindingView{onNewestBase("acme/scoring", brotli)},
		OpenByImage: map[string][]Existing{"acme/scoring": {{Key: "PROJ-1", Summary: "Upgrade scoring to sha-aaa", Category: "new"}}},
	}
	if got := Reconcile(in); len(got) != 1 || got[0].Kind != ActionUpdate {
		t.Fatalf("first run: got %v, want one update", kinds(got))
	}
	in.OpenByImage["acme/scoring"][0].Summary = plan.Drafts[0].Summary
	for run := 2; run <= 3; run++ {
		if got := Reconcile(in); len(got) != 1 || got[0].Kind != ActionSkip {
			t.Fatalf("run %d: got %v, want one skip", run, kinds(got))
		}
	}

	// A new, higher-EPSS app CVE now leads the draft's summary; the ticket's CVE
	// is still part of the change, so nothing is rewritten.
	extra := brotli
	extra.ID, extra.EPSS = "CVE-2026-10009", 0.99
	extra.Packages = []sink.PackageView{{Name: "libother", Ecosystem: "ubuntu", FixedIn: "9"}}
	plan2, err := bundledPlanner(t).Plan([]sink.FindingView{onNewestBase("acme/scoring", brotli, extra)})
	if err != nil {
		t.Fatal(err)
	}
	in.Drafts = plan2.Drafts
	if got := Reconcile(in); len(got) != 1 || got[0].Kind != ActionSkip {
		t.Errorf("reordered CVEs: got %v, want one skip", kinds(got))
	}
}

// A CVE carried by two packages: the ticket has to tell somebody to move both.
func TestQAACVEInTwoPackagesNamesBoth(t *testing.T) {
	two := brotli
	two.Packages = []sink.PackageView{
		{Name: "libbrotli1", Ecosystem: "ubuntu", Installed: "1.1.0-2", FixedIn: "1.1.0-2ubuntu0.1"},
		{Name: "libbrotli-dev", Ecosystem: "ubuntu", Installed: "1.1.0-2", FixedIn: "1.1.0-2ubuntu0.1"},
	}
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{onNewestBase("acme/scoring", two)})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("want one draft, got %d", len(plan.Drafts))
	}
	d := plan.Drafts[0]
	for _, want := range []string{"libbrotli1: 1.1.0-2 -> 1.1.0-2ubuntu0.1", "libbrotli-dev: 1.1.0-2 -> 1.1.0-2ubuntu0.1"} {
		if !strings.Contains(d.Description, want) {
			t.Errorf("description lacks %q", want)
		}
	}
	t.Logf("summary: %s", d.Summary)
}

// One package, two CVEs fixed in two versions: two rows, and no single-version
// promise in the summary.
func TestQAOnePackageTwoFixedVersions(t *testing.T) {
	a, b := brotli, brotli
	b.ID = "CVE-2026-10002"
	b.Packages = []sink.PackageView{{Name: "libbrotli1", Ecosystem: "ubuntu", Installed: "1.1.0-2", FixedIn: "1.1.0-2ubuntu0.2"}}
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{onNewestBase("acme/scoring", a, b)})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("want one draft, got %d", len(plan.Drafts))
	}
	d := plan.Drafts[0]
	t.Logf("summary: %s", d.Summary)
	if strings.Contains(d.Summary, "to 1.1.0-2ubuntu0.1") {
		t.Errorf("summary promises one version where two are needed: %q", d.Summary)
	}
}

// Mixed: base CVE cleared by the move plus an app CVE with a package fix is one
// rebuild ticket with the package beside it, in both grouping modes.
func TestQAMixedFindingIsOneTicketInBothGroupings(t *testing.T) {
	f := rebuildable("acme/scoring", baseCleared, brotli)
	for _, campaign := range []bool{false, true} {
		groups := group([]sink.FindingView{f}, campaign)
		if len(groups) != 1 {
			t.Errorf("campaign=%v: %d groups, want 1", campaign, len(groups))
		}
	}
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{f})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 || plan.Drafts[0].packageOnly {
		t.Fatalf("want one rebuild draft, got %d drafts", len(plan.Drafts))
	}
}

// No ecosystem-correct fix: the scan named the package but gave no FixedIn, so
// whatever the provider's version, no package ticket.
func TestQANoPackageTicketWithoutAPerPackageFix(t *testing.T) {
	v := brotli
	v.FixedVersion = "1.1.0-2ubuntu0.1"
	v.Packages = []sink.PackageView{{Name: "brotli", Ecosystem: "azurelinux"}}
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{onNewestBase("acme/transitioner", v)})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 0 {
		t.Errorf("raised %q with no azurelinux fix known", plan.Drafts[0].Summary)
	}
}

// Pairs with internal/mcp TestQAPlanDoesNotRuleOutARebuildThatMightClear: the
// planner keeps a rebuild ticket when an actionable CVE's origin is unknown.
func TestQAUnknownOriginKeepsTheRebuildTicket(t *testing.T) {
	unknown := sink.VulnView{ID: "CVE-2026-99", Severity: "critical", KEV: true, FixAvailable: true}
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{rebuildable("acme/scoring", brotli, unknown)})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 || plan.Drafts[0].packageOnly {
		t.Fatalf("want one rebuild draft, got %+v", plan.Drafts)
	}
}

// Prod: a rebuild ticket whose rebuild has landed, with an app-layer KEV left. The
// package draft claims it by image and, with no CVEs in either summary, it is
// skipped as "already covers this change": the ticket keeps telling the team to
// rebuild, which is done and fixes nothing, and no package ticket is raised.
func TestQAProdLandedRebuildTicketIsNotSilentlyKept(t *testing.T) {
	f := onNewestBase("acme/scoring", brotli)
	f.Scanned, f.ProviderAssessed, f.Liveness = true, true, &sink.LivenessView{Live: true}
	plan, err := newTestPlanner(t, "").Plan([]sink.FindingView{f})
	if err != nil {
		t.Fatal(err)
	}
	got := Reconcile(ReconcileInput{
		Config: autoCloseCfg(), Drafts: plan.Drafts, Skipped: plan.Skips, Findings: []sink.FindingView{f},
		OpenByImage: map[string][]Existing{"acme/scoring": {{Key: "PROJ-1", Summary: "Upgrade scoring to sha-aaa", Category: "new"}}},
	})
	if len(got) == 1 && got[0].Kind == ActionSkip {
		t.Errorf("landed rebuild ticket kept unchanged as covering the package change: %+v", got[0])
	}
}
