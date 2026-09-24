package ticket

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// A ticket is raised only for a change that clears at least one of the CVEs that
// made its findings actionable, and says only what that change clears.

func bundledPlanner(t *testing.T) *Planner {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "templates", "container-vuln.md.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	return newTestPlanner(t, string(raw))
}

var exploited = sink.VulnView{ID: "CVE-2023-45288", Severity: "high", KEV: true, FixAvailable: true, FixedVersion: "0.23.0"}

// chartFinding is an image whose version the retool chart owns, bumped from
// 6.11.32 to 6.11.33, with the tag the target chart deploys for it.
func chartFinding(repo, tag, targetTag string, vulns ...sink.VulnView) sink.FindingView {
	return finding(repo, func(f *sink.FindingView) {
		f.Image, f.Tag = repo+":"+tag, tag
		f.Vulns = vulns
		f.Upgrade = &sink.UpgradeView{
			Kind: "chart", Name: "retool", Current: "6.11.32", Latest: "6.11.33",
			Available: true, Resolved: true, Actionable: true, Source: "https://charts.retool.com",
			ImageCurrent: tag, ImageLatest: targetTag,
		}
	})
}

// dvop4476 is the case that motivated this: the chart bump moves neither image.
// The backend's tag is pinned in our release values; the device manager's is the
// same in both chart versions, and it carries the only exploited CVE.
func dvop4476() []sink.FindingView {
	backend := chartFinding("tryretool/backend", "4.34.1-stable", "4.34.1-stable")
	backend.Upgrade.ImagePinned = true
	return []sink.FindingView{
		backend,
		chartFinding("ghcr.io/smarter-project/smarter-device-manager", "v1.20.12", "v1.20.12", exploited),
	}
}

func TestAChartBumpThatMovesNoImageRaisesNoTicket(t *testing.T) {
	plan, err := bundledPlanner(t).Plan(dvop4476())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 0 {
		t.Fatalf("a change that clears nothing must not be raised, got %q", plan.Drafts[0].Summary)
	}
	if len(plan.Skips) != 2 {
		t.Fatalf("both images should be reported as skipped, got %+v", plan.Skips)
	}
	for _, s := range plan.Skips {
		if !s.ClearsNothing || s.Policy {
			t.Errorf("skip should be marked clears-nothing, not policy: %+v", s)
		}
		if !strings.Contains(s.Reason, "retool 6.11.32 -> 6.11.33") || !strings.Contains(s.Reason, "does not clear any") {
			t.Errorf("reason should name the change and say it clears nothing: %q", s.Reason)
		}
	}
}

// Measured to leave the actionable CVE behind, even though another image moves:
// the moving image carries nothing actionable, so nothing the ticket would be
// raised for is cleared.
func TestAChangeMeasuredToClearNoneOfTheActionableCVEsRaisesNoTicket(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{
		chartFinding("acme/api", "1.0", "1.1"),
		chartFinding("acme/agent", "2.0", "2.0", exploited),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 0 {
		t.Fatalf("got a draft for a change that leaves the only exploited CVE: %q", plan.Drafts[0].Summary)
	}
}

func TestAnUntouchedTicketForAChangeThatClearsNothingIsClosed(t *testing.T) {
	plan, err := bundledPlanner(t).Plan(dvop4476())
	if err != nil {
		t.Fatal(err)
	}
	got := Reconcile(ReconcileInput{
		Config:   noLongerActionableCfg(),
		Drafts:   plan.Drafts,
		Skipped:  plan.Skips,
		Findings: dvop4476(),
		OpenByImage: map[string][]Existing{
			"tryretool/backend": {{Key: "PROJ-4476", Category: "new"}},
			"ghcr.io/smarter-project/smarter-device-manager": {{Key: "PROJ-4476", Category: "new"}},
		},
	})
	if len(got) != 1 || got[0].Kind != ActionClose {
		t.Fatalf("got %v, want one close", kinds(got))
	}
	a := got[0]
	if !a.NoLongerActionable || !a.Unworked || a.Reason != ReasonUpgradeClearsNothing {
		t.Errorf("close should use the not-actionable transition with the new reason: %+v", a)
	}
	for _, want := range []string{"does not clear any of the vulnerabilities that raised this ticket", "not-worked", "Reopen if this is wrong"} {
		if !strings.Contains(a.Message, want) {
			t.Errorf("comment should say %q: %s", want, a.Message)
		}
	}
}

func TestAWorkedTicketForAChangeThatClearsNothingIsOnlyToldWhy(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  func() Existing
		off  bool
	}{
		{name: "assigned", cfg: func() Existing { return Existing{Key: "PROJ-1", Category: "new", Assigned: true} }},
		{name: "in progress", cfg: func() Existing { return Existing{Key: "PROJ-1", Category: "indeterminate"} }},
		{name: "no not-actionable transition configured", off: true, cfg: func() Existing { return Existing{Key: "PROJ-1", Category: "new"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := bundledPlanner(t).Plan(dvop4476())
			if err != nil {
				t.Fatal(err)
			}
			cfg := noLongerActionableCfg()
			if tc.off {
				cfg.Routes[0].CloseTransitionNoLongerActionable, cfg.Routes[0].ClosePriorityNoLongerActionable = "", ""
			}
			got := Reconcile(ReconcileInput{
				Config: cfg, Skipped: plan.Skips, Findings: dvop4476(),
				OpenByImage: map[string][]Existing{"ghcr.io/smarter-project/smarter-device-manager": {tc.cfg()}},
			})
			if len(got) != 1 || got[0].Kind != ActionNoteDone {
				t.Fatalf("got %v, want one note", kinds(got))
			}
			n := got[0]
			if n.Reason != ReasonUpgradeClearsNothing || n.Dedupe != "note-done:"+ReasonUpgradeClearsNothing {
				t.Errorf("note should carry the reason and dedupe on it: %+v", n)
			}
			if !strings.Contains(n.Message, "does not clear any of the vulnerabilities") || !strings.Contains(n.Message, "Left open deliberately") {
				t.Errorf("note = %s", n.Message)
			}
		})
	}
}

// Not knowing what a change clears is never a reason to withhold the ticket, and
// never a reason to claim anything about it either.
func TestAnUnmeasuredChangeIsRaisedWithoutAClaim(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{
		chartFinding("acme/agent", "2.0", "", exploited),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("an unmeasured change must still be raised, got skips %+v", plan.Skips)
	}
	body := plan.Drafts[0].Description
	for _, never := range []string{"Done means", "CVE-2023-45288 remain", "could not be measured", " of 1", "clears"} {
		if strings.Contains(body, never) {
			t.Errorf("body makes a claim it cannot back (%q):\n%s", never, body)
		}
	}
	if !strings.Contains(body, "running 6.11.33") {
		t.Errorf("acceptance should fall back to the version, which the change can satisfy:\n%s", body)
	}
	if !strings.Contains(body, "tag it deploys could not be read") {
		t.Errorf("the row should say the image's target tag is unknown:\n%s", body)
	}
}

func TestDoneMeansListsOnlyTheCVETheChangeClears(t *testing.T) {
	base := func(f *sink.FindingView) {
		f.Upgrade = &sink.UpgradeView{Kind: "base", Name: "example.io/base", Current: "aaa", Latest: "bbb",
			Available: true, Resolved: true, Actionable: true}
		f.Vulns = []sink.VulnView{
			{ID: "CVE-CLEARED", KEV: true, FixAvailable: true, Origin: "base", OriginDetermined: true, FixedByUpgrade: true},
			{ID: "CVE-KEPT", KEV: true, FixAvailable: true, Origin: "app", OriginDetermined: true},
		}
	}
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{finding("acme/svc", base)})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("clearing one of two is still worth a ticket, got skips %+v", plan.Skips)
	}
	body := plan.Drafts[0].Description
	if !strings.Contains(body, "CVE-CLEARED") {
		t.Errorf("the cleared CVE belongs under Done means:\n%s", body)
	}
	if strings.Contains(body, "CVE-KEPT") {
		t.Errorf("a CVE the change leaves must be omitted entirely:\n%s", body)
	}
	if strings.Contains(body, " of 2") || strings.Contains(body, "not the whole job") {
		t.Errorf("body counts against a CVE it does not list:\n%s", body)
	}
}

// The upgrade rows name each image's own tags, not the chart's version, and leave
// out an image the bump does not move.
func TestTheUpgradeTableShowsImageTagsAndOmitsUnmovedImages(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{
		chartFinding("acme/api", "1.0", "1.1", exploited),
		chartFinding("acme/agent", "2.0", "2.0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("want one draft, got %d (skips %+v)", len(plan.Drafts), plan.Skips)
	}
	d := plan.Drafts[0]
	if d.Summary != "Upgrade retool to 6.11.33" {
		t.Errorf("summary should still name the chart version: %q", d.Summary)
	}
	if !strings.Contains(d.Description, "* acme/api: 1.0 -> 1.1 (set by the retool chart, which moves 6.11.32 -> 6.11.33)") {
		t.Errorf("row should show the image's tags and the chart that moves them:\n%s", d.Description)
	}
	actions := d.Description[strings.Index(d.Description, "**Technical"):strings.Index(d.Description, "**Where it runs")]
	if strings.Contains(actions, "acme/agent") {
		t.Errorf("an image the bump leaves alone must not be listed as moving:\n%s", actions)
	}
	if strings.Contains(actions, "acme/api: 6.11.32") {
		t.Errorf("the chart's version is shown as the image's:\n%s", actions)
	}
	if len(d.Upgrades) != 1 || d.Upgrades[0].Repo != "acme/api" {
		t.Errorf("draft upgrades should hold only the moving image: %+v", d.Upgrades)
	}
}

// Staleness compares the chart version the summary names, not an image tag.
func TestStalenessOfAChartTicketComparesChartVersions(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{chartFinding("acme/api", "1.0", "1.1", exploited)})
	if err != nil {
		t.Fatal(err)
	}
	d := plan.Drafts[0]
	if got := staleTarget(d, Existing{Key: "PROJ-1", Summary: "Upgrade retool to 6.11.33"}); got != "" {
		t.Errorf("a ticket already asking for 6.11.33 is not stale: %s", got)
	}
	if got := staleTarget(d, Existing{Key: "PROJ-1", Summary: "Upgrade retool to 6.11.30"}); !strings.Contains(got, "6.11.33") {
		t.Errorf("a ticket asking for 6.11.30 is stale: %q", got)
	}
}

func TestClearsNone(t *testing.T) {
	critical := sink.VulnView{ID: "CVE-CRIT", Severity: "critical", FixAvailable: true}
	for _, tc := range []struct {
		name  string
		group []sink.FindingView
		want  bool
	}{
		{"every image unmoved", dvop4476(), true},
		{"unmoved with no CVEs at all", []sink.FindingView{chartFinding("a/x", "1", "1")}, true},
		{"target tag unknown", []sink.FindingView{chartFinding("a/x", "1", "", exploited)}, false},
		{"image moves, nothing measured", []sink.FindingView{chartFinding("a/x", "1", "2", exploited)}, false},
		{"falls back to fixable criticals when nothing is urgent",
			[]sink.FindingView{chartFinding("a/x", "1", "1", critical), chartFinding("a/y", "1", "2")}, true},
		{"a moving image with nothing actionable is not measured to clear anything",
			[]sink.FindingView{chartFinding("a/y", "1", "2")}, false},
		{"the same CVE on a moving image might be cleared there",
			[]sink.FindingView{chartFinding("a/x", "1", "1", exploited), chartFinding("a/y", "1", "2", exploited)}, false},
		{"image tag bump is never measured", []sink.FindingView{finding("a/x", func(f *sink.FindingView) {
			f.Vulns = []sink.VulnView{exploited}
		})}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clearsNone(tc.group, 0); got != tc.want {
				t.Errorf("clearsNone = %v, want %v", got, tc.want)
			}
		})
	}
}
