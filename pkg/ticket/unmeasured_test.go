package ticket

import (
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// A base rebuild whose effect on the exploited CVE is measured, unmeasurable, or
// went unmeasured this run because a scan failed.
func rebuild(repo string, v sink.VulnView, baseDiffError string) sink.FindingView {
	return finding(repo, func(f *sink.FindingView) {
		f.Upgrade = &sink.UpgradeView{Kind: "base", Name: "example.io/base", Current: "aaa", Latest: "bbb",
			Available: true, Resolved: true, Actionable: true}
		f.Vulns = []sink.VulnView{v}
		f.BaseDiffError = baseDiffError
	})
}

var (
	clearedCVE  = sink.VulnView{ID: "CVE-1", KEV: true, FixAvailable: true, Origin: "base", OriginDetermined: true, FixedByUpgrade: true}
	keptCVE     = sink.VulnView{ID: "CVE-1", KEV: true, FixAvailable: true, Origin: "base", OriginDetermined: true}
	unknownCVE  = sink.VulnView{ID: "CVE-1", KEV: true, FixAvailable: true}
	scanFailure = "base scan failed: trivy base@sha256:aaa: exit status 1: 404 Not Found"
)

func TestPlanHoldsAChangeThatCouldNotBeMeasuredThisRun(t *testing.T) {
	for _, tc := range []struct {
		name  string
		group []sink.FindingView
		// want is "draft", "unmeasured" or "clears-nothing".
		want string
	}{
		{"unmeasured this run raises nothing",
			[]sink.FindingView{rebuild("acme/svc", unknownCVE, scanFailure)}, "unmeasured"},
		{"unmeasurable by configuration still tickets",
			[]sink.FindingView{rebuild("acme/svc", unknownCVE, "")}, "draft"},
		{"measured to fix nothing is unchanged",
			[]sink.FindingView{rebuild("acme/svc", keptCVE, "")}, "clears-nothing"},
		{"measured to clear stands, whatever failed",
			[]sink.FindingView{rebuild("acme/svc", clearedCVE, scanFailure)}, "draft"},
		// The candidate scan failed but the base scan did not: ownership was measured,
		// the upgrade was not, and the verdict is still unknown.
		{"a failed candidate scan is unmeasured too",
			[]sink.FindingView{rebuild("acme/svc", sink.VulnView{ID: "CVE-1", KEV: true, FixAvailable: true, Origin: "base"},
				"candidate base scan failed: timeout")}, "unmeasured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := bundledPlanner(t).Plan(tc.group)
			if err != nil {
				t.Fatal(err)
			}
			switch tc.want {
			case "draft":
				if len(plan.Drafts) != 1 {
					t.Fatalf("want a draft, got skips %+v", plan.Skips)
				}
			case "unmeasured":
				if len(plan.Drafts) != 0 {
					t.Fatalf("raised %q on a change this run could not measure", plan.Drafts[0].Summary)
				}
				if len(plan.Skips) != 1 || !plan.Skips[0].Unmeasured || plan.Skips[0].ClearsNothing || plan.Skips[0].Policy {
					t.Fatalf("want one unmeasured skip, got %+v", plan.Skips)
				}
				r := plan.Skips[0].Reason
				if !strings.Contains(r, "could not be measured this run") || !strings.Contains(r, "nothing was raised or changed") {
					t.Errorf("reason should say it could not be measured and that nothing was done: %q", r)
				}
				if !strings.Contains(r, tc.group[0].BaseDiffError) {
					t.Errorf("reason should carry why it could not be measured: %q", r)
				}
			case "clears-nothing":
				if len(plan.Drafts) != 0 || len(plan.Skips) != 1 || !plan.Skips[0].ClearsNothing || plan.Skips[0].Unmeasured {
					t.Fatalf("want one clears-nothing skip, got drafts %d skips %+v", len(plan.Drafts), plan.Skips)
				}
			}
		})
	}
}

// Every reconciliation that could act on an open ticket is configured to: closing
// allowed, a not-done transition, an untouched ticket. Each must still hold.
func TestAnOpenTicketForAnUnmeasuredChangeIsOnlyHeld(t *testing.T) {
	findings := []sink.FindingView{rebuild("acme/svc", unknownCVE, scanFailure)}
	plan, err := bundledPlanner(t).Plan(findings)
	if err != nil {
		t.Fatal(err)
	}
	cfg := noLongerActionableCfg()
	on := true
	cfg.Routes[0].AutoClose = &on
	for _, tc := range []struct {
		name   string
		ticket Existing
	}{
		{"untouched", Existing{Key: "PROJ-1", Category: "new", Summary: "Rebuild acme/svc to bbb"}},
		{"being worked", Existing{Key: "PROJ-1", Category: "indeterminate", Assigned: true, Summary: "Rebuild acme/svc to aaa"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Reconcile(ReconcileInput{
				Config: cfg, Drafts: plan.Drafts, Skipped: plan.Skips, Findings: findings,
				OpenByImage: map[string][]Existing{"acme/svc": {tc.ticket}},
			})
			if len(got) != 1 || got[0].Kind != ActionHold {
				t.Fatalf("got %v, want exactly one hold", kinds(got))
			}
			a := got[0]
			if a.TicketKey != "PROJ-1" || a.Reason != ReasonUnmeasured {
				t.Errorf("hold should name the ticket and the reason: %+v", a)
			}
			if a.Message != "" {
				t.Errorf("a hold writes nothing, got a message: %q", a.Message)
			}
			if !strings.Contains(a.Why, "could not be measured this run") || !strings.Contains(a.Why, "acme/svc") {
				t.Errorf("why should say what could not be measured: %q", a.Why)
			}
		})
	}
}

func TestAnUnmeasuredChangeWithNoTicketIsReportedAsHeld(t *testing.T) {
	findings := []sink.FindingView{rebuild("acme/svc", unknownCVE, scanFailure), rebuild("acme/other", unknownCVE, "")}
	plan, err := bundledPlanner(t).Plan(findings)
	if err != nil {
		t.Fatal(err)
	}
	got := Reconcile(ReconcileInput{
		Config: config.JiraConfig{}, Drafts: plan.Drafts, Skipped: plan.Skips, Findings: findings,
		OpenByImage: map[string][]Existing{},
	})
	var creates, holds []Action
	for _, a := range got {
		switch a.Kind {
		case ActionCreate:
			creates = append(creates, a)
		case ActionHold:
			holds = append(holds, a)
		}
	}
	if len(creates) != 1 || creates[0].Draft.Images[0] != "acme/other" {
		t.Fatalf("only the unmeasurable change should be raised, got creates %+v", creates)
	}
	if len(holds) != 1 {
		t.Fatalf("want one hold for the unmeasured change, got %v", kinds(got))
	}
	h := holds[0]
	if h.TicketKey != "" || h.Reason != ReasonUnmeasured || len(h.Images) != 1 || h.Images[0] != "acme/svc" {
		t.Errorf("hold should be ticketless, name the image and the reason: %+v", h)
	}
}

func TestUnmeasured(t *testing.T) {
	for _, tc := range []struct {
		name  string
		group []sink.FindingView
		want  string
	}{
		{"failed this run", []sink.FindingView{rebuild("a/x", unknownCVE, scanFailure)}, scanFailure},
		{"never measurable", []sink.FindingView{rebuild("a/x", unknownCVE, "")}, ""},
		{"measured and kept", []sink.FindingView{rebuild("a/x", keptCVE, "")}, ""},
		{"measured to clear on one image, failed on another",
			[]sink.FindingView{rebuild("a/x", clearedCVE, ""), rebuild("a/y", unknownCVE, scanFailure)}, ""},
		{"kept on one image, failed on another",
			[]sink.FindingView{rebuild("a/x", keptCVE, ""), rebuild("a/y", unknownCVE, scanFailure)}, scanFailure},
		// A failure on an image carrying nothing actionable decides nothing.
		{"failure on an image with nothing actionable",
			[]sink.FindingView{rebuild("a/x", keptCVE, ""), rebuild("a/y", sink.VulnView{ID: "CVE-2", Severity: "low"}, scanFailure)}, ""},
		{"an unmoved chart is measured whatever failed",
			[]sink.FindingView{func() sink.FindingView {
				f := chartFinding("a/x", "1", "1", exploited)
				f.BaseDiffError = scanFailure
				return f
			}()}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := unmeasured(tc.group, 0); got != tc.want {
				t.Errorf("unmeasured = %q, want %q", got, tc.want)
			}
		})
	}
}
