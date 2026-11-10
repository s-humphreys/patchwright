package ticket

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// An exploited CVE in a package the image's own build adds is the owning team's to
// fix, and a ticket asks them to move the package rather than to rebuild on a base
// that leaves it where it is.

// brotli is the case that motivated this: an exploited CVE in a package the
// Dockerfile installs on top of ubuntu. The provider's own fixed version is
// deliberately not the package's, as when it reports one from another ecosystem:
// the ticket has to name the version the scan gave for the package itself.
var brotli = sink.VulnView{
	ID: "CVE-2026-10001", Severity: "high", KEV: true, EPSS: 0.83, FixAvailable: true,
	FixedVersion: "3.0.2-0ubuntu1.99", Origin: "app", OriginDetermined: true,
	Packages: []sink.PackageView{{Name: "libbrotli1", Ecosystem: "ubuntu", Installed: "1.1.0-2", FixedIn: "1.1.0-2ubuntu0.1"}},
}

// baseCleared is an exploited CVE in the base that the newer base removes.
var baseCleared = sink.VulnView{
	ID: "CVE-2026-20002", Severity: "critical", KEV: true, FixAvailable: true,
	Origin: "base", OriginDetermined: true, FixedByUpgrade: true,
}

// rebuildable is a service built on ubuntu with a newer digest on offer.
func rebuildable(repo string, vulns ...sink.VulnView) sink.FindingView {
	return finding(repo, func(f *sink.FindingView) {
		f.Image, f.Tag = "reg.example.com/"+repo+":42", "42"
		f.Priority, f.BuildRepo, f.Owner.Team = "urgent", "acme/models", "scoring"
		f.Upgrade = &sink.UpgradeView{Kind: "base", Name: "docker.io/ubuntu", Current: "sha-aaa", Latest: "sha-bbb",
			Available: true, Resolved: true, Actionable: true}
		f.Vulns = vulns
	})
}

// onNewestBase is the same service with no newer base to move to. The differential
// still scanned the base as built, so Origin is known, but with no candidate to scan
// OriginDetermined is false: the state the pipeline produces, which an earlier
// version of this fixture did not, and so hid that no package ticket was raised.
func onNewestBase(repo string, vulns ...sink.VulnView) sink.FindingView {
	f := rebuildable(repo, vulns...)
	f.Upgrade.Latest, f.Upgrade.Available = f.Upgrade.Current, false
	for i := range f.Vulns {
		f.Vulns[i].OriginDetermined = false
	}
	return f
}

func TestAnAppLayerCVEWithAKnownFixIsTicketedAsAPackageChange(t *testing.T) {
	for name, f := range map[string]sink.FindingView{
		"the base move clears none of it": rebuildable("acme/scoring", brotli),
		"there is no base move":           onNewestBase("acme/scoring", brotli),
	} {
		t.Run(name, func(t *testing.T) {
			plan, err := bundledPlanner(t).Plan([]sink.FindingView{f})
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Drafts) != 1 || len(plan.Skips) != 0 {
				t.Fatalf("want one draft and no skips, got %d drafts, skips %+v", len(plan.Drafts), plan.Skips)
			}
			d := plan.Drafts[0]
			if want := "Upgrade libbrotli1 to 1.1.0-2ubuntu0.1 in scoring (CVE-2026-10001)"; d.Summary != want {
				t.Errorf("summary = %q, want %q", d.Summary, want)
			}
			for _, want := range []string{
				"libbrotli1: 1.1.0-2 -> 1.1.0-2ubuntu0.1, clearing CVE-2026-10001",
				"Upgrade libbrotli1 to 1.1.0-2ubuntu0.1 in your Dockerfile",
				"A base image rebuild will not remove it",
				"in acme/models",
				"exploited in the wild",
			} {
				if !strings.Contains(d.Description, want) {
					t.Errorf("description lacks %q:\n%s", want, d.Description)
				}
			}
			for _, never := range []string{"Rebuild scoring", "sha-bbb", "3.0.2-0ubuntu1.99"} {
				if strings.Contains(d.Description, never) {
					t.Errorf("description says %q, which is not this ticket's change:\n%s", never, d.Description)
				}
			}
			if len(d.Upgrades) != 0 || !d.packageOnly {
				t.Errorf("a package change moves no image: upgrades %+v, packageOnly %v", d.Upgrades, d.packageOnly)
			}
			if d.Priority != "urgent" || d.Route != "all" {
				t.Errorf("priority and route come from the usual machinery: %q, %q", d.Priority, d.Route)
			}
		})
	}
}

// What stays in the queue: a fix nothing can attribute to the package carrying the
// CVE is no fix a ticket can ask for.
func TestAnAppLayerCVEWithNoKnownPackageFixIsStillSkipped(t *testing.T) {
	unnamed := brotli
	unnamed.Packages = nil
	// The provider's fixed version is all there is, and the package beside it has
	// none of its own: the version belongs to some other ecosystem.
	foreign := brotli
	foreign.Packages = []sink.PackageView{{Name: "openssl", Ecosystem: "azurelinux"}}
	partial := brotli
	partial.Packages = append([]sink.PackageView{{Name: "brotli", Ecosystem: "npm", Path: "package-lock.json"}}, brotli.Packages...)
	// Nothing scanned the base, so nothing says the build added it.
	unattributed := brotli
	unattributed.Origin, unattributed.OriginDetermined = "", false

	for name, v := range map[string]sink.VulnView{
		"no package named":           unnamed,
		"fix from another ecosystem": foreign,
		"one carrier has no fix":     partial,
		"no base scan":               unattributed,
	} {
		for kind, f := range map[string]sink.FindingView{
			"rebuild": rebuildable("acme/scoring", v), "newest base": onNewestBase("acme/scoring", v),
		} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				plan, err := bundledPlanner(t).Plan([]sink.FindingView{f})
				if err != nil {
					t.Fatal(err)
				}
				for _, d := range plan.Drafts {
					if d.packageOnly || strings.Contains(d.Summary, "libbrotli1") {
						t.Errorf("a package with no known fix was ticketed: %q", d.Summary)
					}
				}
				if kind == "newest base" && len(plan.Drafts) != 0 {
					t.Errorf("still skipped as before, got %q", plan.Drafts[0].Summary)
				}
			})
		}
	}
}

func TestABaseMoveThatClearsTheActionableCVEKeepsItsRebuildTicket(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{rebuildable("acme/scoring", baseCleared)})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("want one draft, got skips %+v", plan.Skips)
	}
	d := plan.Drafts[0]
	if d.Summary != "Upgrade scoring to sha-bbb" || d.packageOnly {
		t.Errorf("summary = %q (packageOnly %v), want the rebuild ticket unchanged", d.Summary, d.packageOnly)
	}
	if !strings.Contains(d.Description, `That alone clears every CVE under "Done means".`) {
		t.Errorf("a rebuild that clears everything still says so:\n%s", d.Description)
	}
	if strings.Contains(d.Description, "does not touch these") {
		t.Errorf("no package rows on a ticket with no package to move:\n%s", d.Description)
	}
}

// A base move that clears one exploited CVE, and a package the build adds carrying
// another: one ticket, which is the rebuild, and which says the package has to move
// too rather than letting the rebuild's "Done means" be one it cannot meet alone.
func TestAMixedFindingKeepsTheRebuildAndListsThePackageBesideIt(t *testing.T) {
	f := rebuildable("acme/scoring", baseCleared, brotli)
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{f})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("want one draft, got %d (skips %+v)", len(plan.Drafts), plan.Skips)
	}
	d := plan.Drafts[0]
	if d.Summary != "Upgrade scoring to sha-bbb" || d.packageOnly {
		t.Errorf("summary = %q (packageOnly %v), want the rebuild", d.Summary, d.packageOnly)
	}
	for _, want := range []string{
		"CVE-2026-20002", "Nothing extra. The rebuild above removes it.",
		"CVE-2026-10001", "Upgrade libbrotli1 to 1.1.0-2ubuntu0.1 in your Dockerfile",
		"The rebuild does not touch these",
	} {
		if !strings.Contains(d.Description, want) {
			t.Errorf("description lacks %q:\n%s", want, d.Description)
		}
	}
	if strings.Contains(d.Description, "That alone clears") {
		t.Errorf("the rebuild alone does not clear the package's CVE:\n%s", d.Description)
	}

	// A template written against the earlier contract words UrgentCleared as what
	// "the rebuild alone" does, so it counts only the base row.
	data := newTemplateData(ticketGroup{primary: []sink.FindingView{f}}, nil, 0)
	if data.UrgentCleared != 1 || data.UrgentRemaining() != 1 || data.UrgentAllCleared() {
		t.Errorf("cleared %d, remaining %d, all %v; want 1, 1, false",
			data.UrgentCleared, data.UrgentRemaining(), data.UrgentAllCleared())
	}
}

// Grouping follows the route's groupBy as for any change: a ticket per service, or
// one per team and build repository in a campaign.
func TestPackageChangesGroupPerServiceOrPerBuildRepository(t *testing.T) {
	findings := []sink.FindingView{rebuildable("acme/scoring", brotli), rebuildable("acme/pricing", brotli)}
	if got := group(asPackageChanges(findings), false); len(got) != 2 {
		t.Errorf("per service: %d groups, want 2", len(got))
	}
	got := group(asPackageChanges(findings), true)
	if len(got) != 1 || len(got[0].primary) != 2 {
		t.Fatalf("campaign: want one group of both services, got %d", len(got))
	}
	if key := groupKey(got[0].primary[0], true); key != "scoring packages in acme/models" {
		t.Errorf("campaign key = %q", key)
	}
	data := newTemplateData(got[0], nil, 0)
	if data.Upgrade == nil || data.Upgrade.Kind != "package" || data.ImageCount != 2 {
		t.Errorf("one package to one version across both: upgrade %+v, images %d", data.Upgrade, data.ImageCount)
	}
}

func asPackageChanges(fs []sink.FindingView) []sink.FindingView {
	out := make([]sink.FindingView, 0, len(fs))
	for _, f := range fs {
		out = append(out, asPackageChange(f, 0))
	}
	return out
}

// fixed is the service after the package moved: rebuilt, redeployed, still scanned
// and running, and no longer carrying the CVE or anything urgent.
func fixed(repo string) sink.FindingView {
	f := onNewestBase(repo)
	f.Actionable, f.Priority = false, ""
	f.Scanned, f.ProviderAssessed = true, true
	f.Vulns = []sink.VulnView{{ID: "CVE-2020-00001", Severity: "low"}}
	f.Liveness = &sink.LivenessView{Live: true}
	return f
}

func TestReconcileClosesAPackageTicketOnceTheCVEIsGone(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{onNewestBase("acme/scoring", brotli)})
	if err != nil {
		t.Fatal(err)
	}
	summary := plan.Drafts[0].Summary

	for name, tc := range map[string]struct {
		ticket Existing
		want   ActionKind
	}{
		"nobody picked it up": {Existing{Key: "PROJ-1", Summary: summary, Category: "new"}, ActionClose},
		"somebody is on it":   {Existing{Key: "PROJ-1", Summary: summary, Category: "indeterminate", Assigned: true}, ActionNoteDone},
	} {
		t.Run(name, func(t *testing.T) {
			got := Reconcile(ReconcileInput{
				Config:      autoCloseCfg(),
				Findings:    []sink.FindingView{fixed("acme/scoring")},
				OpenByImage: map[string][]Existing{"acme/scoring": {tc.ticket}},
			})
			if len(got) != 1 || got[0].Kind != tc.want || got[0].Reason != ReasonFixLanded {
				t.Fatalf("got %+v, want one %s for %s", got, tc.want, ReasonFixLanded)
			}
			if !strings.Contains(got[0].Message, "CVE-2026-10001 no longer reported on acme/scoring") {
				t.Errorf("message should give the evidence: %q", got[0].Message)
			}
		})
	}
}

// Absence is only evidence where something looked, and an image on its newest base
// is no evidence about a package its build adds.
func TestReconcileDoesNotCloseAPackageTicketWithoutEvidence(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{onNewestBase("acme/scoring", brotli)})
	if err != nil {
		t.Fatal(err)
	}
	open := map[string][]Existing{"acme/scoring": {{Key: "PROJ-1", Summary: plan.Drafts[0].Summary, Category: "new"}}}

	stillThere := fixed("acme/scoring")
	stillThere.Vulns = append(stillThere.Vulns, brotli)
	unscanned := fixed("acme/scoring")
	unscanned.Scanned, unscanned.ProviderAssessed, unscanned.Vulns = false, false, nil
	noLiveness := fixed("acme/scoring")
	noLiveness.Liveness = nil

	for name, f := range map[string]sink.FindingView{
		"the CVE is still reported": stillThere,
		"nothing scanned it":        unscanned,
		"liveness unknown":          noLiveness,
	} {
		t.Run(name, func(t *testing.T) {
			got := Reconcile(ReconcileInput{Config: autoCloseCfg(), Findings: []sink.FindingView{f}, OpenByImage: open})
			for _, a := range got {
				if a.Kind == ActionClose || a.Reason == ReasonFixLanded || a.Reason == ReasonUpgradeLanded {
					t.Errorf("closed or called done without evidence: %+v", a)
				}
			}
		})
	}
}

// A rebuild ticket raised before the package was known, whose rebuild has landed:
// what is left is the package, and the ticket says so.
func TestARebuildTicketWhoseRebuildLandedIsRetargetedAtThePackage(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{onNewestBase("acme/scoring", brotli)})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		ticket Existing
		want   ActionKind
	}{
		"nobody picked it up":   {Existing{Key: "PROJ-1", Summary: "Upgrade scoring to sha-aaa", Category: "new"}, ActionUpdate},
		"somebody is on it":     {Existing{Key: "PROJ-1", Summary: "Upgrade scoring to sha-aaa", Category: "indeterminate"}, ActionNoteStale},
		"already the package's": {Existing{Key: "PROJ-1", Summary: plan.Drafts[0].Summary, Category: "new"}, ActionSkip},
	} {
		t.Run(name, func(t *testing.T) {
			got := Reconcile(ReconcileInput{
				Config: autoCloseCfg(), Drafts: plan.Drafts, Skipped: plan.Skips,
				Findings:    []sink.FindingView{onNewestBase("acme/scoring", brotli)},
				OpenByImage: map[string][]Existing{"acme/scoring": {tc.ticket}},
			})
			if len(got) != 1 || got[0].Kind != tc.want {
				t.Fatalf("got %v, want one %s", kinds(got), tc.want)
			}
			if tc.want == ActionNoteStale && (got[0].Dedupe != "note-retarget:CVE-2026-10001" ||
				!strings.Contains(got[0].Message, "will not remove it")) {
				t.Errorf("note should be deduplicated on the CVEs and say why: %+v", got[0])
			}
		})
	}
}

// A template that leaves the CVEs out of its summary gives nothing to tell a rebuild
// ticket from a package one by, so a package draft over a ticket with another
// summary is said in a comment, posted once, and never rewritten: a rewrite on that
// comparison would follow every change of wording. Silence would leave a landed
// rebuild ticket asking for the rebuild.
func TestALandedRebuildTicketIsNotedWhenTheSummariesNameNoCVEs(t *testing.T) {
	f := onNewestBase("acme/scoring", brotli)
	plan, err := newTestPlanner(t, "").Plan([]sink.FindingView{f})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		summary string
		want    ActionKind
	}{
		"a rebuild ticket":    {"Upgrade scoring to sha-aaa", ActionNoteStale},
		"this package ticket": {plan.Drafts[0].Summary, ActionSkip},
	} {
		t.Run(name, func(t *testing.T) {
			got := Reconcile(ReconcileInput{
				Config: autoCloseCfg(), Drafts: plan.Drafts, Skipped: plan.Skips, Findings: []sink.FindingView{f},
				OpenByImage: map[string][]Existing{"acme/scoring": {{Key: "PROJ-1", Summary: tc.summary, Category: "new"}}},
			})
			if len(got) != 1 || got[0].Kind != tc.want {
				t.Fatalf("got %v, want one %s", kinds(got), tc.want)
			}
			if tc.want == ActionNoteStale && got[0].Dedupe != "note-retarget:"+plan.Drafts[0].Summary {
				t.Errorf("note should be posted once per draft summary: %q", got[0].Dedupe)
			}
		})
	}
}

func TestPackageTicketSurvivesTheConverter(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{rebuildable("acme/scoring", brotli)})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ADFDocument(plan.Drafts[0].Description))
	var doc struct {
		Content []struct {
			Type    string `json:"type"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"content"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, blk := range doc.Content {
		for _, s := range blk.Content {
			if blk.Type == "paragraph" && (strings.HasPrefix(s.Text, "* ") || strings.HasPrefix(s.Text, "**") || strings.HasPrefix(s.Text, "|")) {
				t.Errorf("markup rendered literally in a paragraph: %q", s.Text)
			}
		}
	}
}

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

// A template with no package branch writes a package ticket's summary with no CVEs
// in it. Such a ticket was raised because the image is already on its newest base,
// so "already on the latest available version" is true from the day it was raised
// and no evidence the package moved: it is held while the CVE is still reported.
func TestAPackageTicketIsNotClosedWhileItsCVEIsReported(t *testing.T) {
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
func TestFixLandedWaitsForCVEsTheSummaryDidNotName(t *testing.T) {
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
func TestRetargetingConverges(t *testing.T) {
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
func TestACVEInTwoPackagesNamesBoth(t *testing.T) {
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
	for _, want := range []string{
		"libbrotli1: 1.1.0-2 -> 1.1.0-2ubuntu0.1", "libbrotli-dev: 1.1.0-2 -> 1.1.0-2ubuntu0.1",
		"Upgrade libbrotli1, libbrotli-dev to 1.1.0-2ubuntu0.1 in your Dockerfile",
	} {
		if !strings.Contains(d.Description, want) {
			t.Errorf("description lacks %q", want)
		}
	}
}

// One package, two CVEs fixed in two versions: two rows, and no single-version
// promise in the summary.
func TestOnePackageNeedingTwoVersionsPromisesNeither(t *testing.T) {
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
	if want := "Upgrade libbrotli1 in scoring (CVE-2026-10001, CVE-2026-10002)"; d.Summary != want {
		t.Errorf("summary = %q, want one package and no single version: %q", d.Summary, want)
	}
}

// Mixed: base CVE cleared by the move plus an app CVE with a package fix is one
// rebuild ticket with the package beside it, in both grouping modes.
func TestAMixedFindingIsOneTicketInBothGroupings(t *testing.T) {
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

// Pairs with internal/mcp TestAPlanDoesNotRuleOutARebuildThatMightClear: the
// planner keeps a rebuild ticket when an actionable CVE's origin is unknown.
func TestAnUnmeasuredCVEKeepsTheRebuildTicket(t *testing.T) {
	unknown := sink.VulnView{ID: "CVE-2026-99", Severity: "critical", KEV: true, FixAvailable: true}
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{rebuildable("acme/scoring", brotli, unknown)})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 || plan.Drafts[0].packageOnly {
		t.Fatalf("want one rebuild draft, got %+v", plan.Drafts)
	}
}
