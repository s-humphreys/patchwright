package ticket

import (
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Images whose versions an operator picks at runtime are never ticketed as image
// bumps. With the operator's chart upgrade on offer, that is the ticket; without
// it there is nothing to raise, and an open ticket is not reported as done.

var natsRepos = []struct{ repo, tag string }{
	{"nats", "2.10.29"},
	{"natsio/nats-server-config-reloader", "0.14.0"},
	{"natsio/prometheus-nats-exporter", "0.14.0"},
}

const eventBusReason = "version chosen by the operator that reconciles EventBus/argo-events/cpo; " +
	"which operator that is could not be determined, so its upgrade could not be resolved"

// eventBusFindings are the DVOP-4420 images as remediation now reports them.
func eventBusFindings(upgrade func(tag string) *sink.UpgradeView) []sink.FindingView {
	out := make([]sink.FindingView, 0, len(natsRepos))
	for _, n := range natsRepos {
		out = append(out, finding(n.repo, func(f *sink.FindingView) {
			f.Image, f.Tag = "docker.io/"+n.repo+":"+n.tag, n.tag
			f.Vulns = []sink.VulnView{exploited}
			f.ProviderAssessed = true
			f.Liveness = &sink.LivenessView{Live: true}
			f.Upgrade = upgrade(n.tag)
		}))
	}
	return out
}

// unknownOperator is the production shape: nothing names the operator, so whether
// it has an upgrade is unknown.
func unknownOperator(tag string) *sink.UpgradeView {
	return &sink.UpgradeView{
		Kind: "image", Current: tag, Managed: "operator",
		Source: "EventBus/argo-events/cpo", OperatorChosen: true, Reason: eventBusReason,
	}
}

const latestReason = "version chosen by the operator argo-events; the operator is on its latest version"

// operatorOnLatest is the one shape that establishes there is no upgrade.
func operatorOnLatest(tag string) *sink.UpgradeView {
	return &sink.UpgradeView{
		Kind: "image", Current: tag, Resolved: true, Managed: "operator", Manager: "argo-events",
		Source: "EventBus/argo-events/cpo", OperatorChosen: true, Reason: latestReason,
	}
}

func operatorChartUpgrade(tag string) *sink.UpgradeView {
	return &sink.UpgradeView{
		Kind: "chart", Name: "argo-events", Current: "2.4.15", Latest: "2.4.16",
		Available: true, Resolved: true, Actionable: true, Source: "https://charts.example.test",
		Managed: "operator", Manager: "argo-events", OperatorChosen: true, ImageCurrent: tag,
	}
}

func TestOperatorChosenImagesAreNotTicketed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		upgrade func(string) *sink.UpgradeView
		reason  string
		proven  bool
	}{
		{"operator unknown", unknownOperator, eventBusReason + "; no ticket until the operator's upgrade is known", false},
		{"operator on its latest version", operatorOnLatest, latestReason + "; there is no change to ticket", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := bundledPlanner(t).Plan(eventBusFindings(tc.upgrade))
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Drafts) != 0 {
				t.Fatalf("nothing can be changed, so nothing is raised; got %q", plan.Drafts[0].Summary)
			}
			if len(plan.Skips) != len(natsRepos) {
				t.Fatalf("every image should be reported as skipped: %+v", plan.Skips)
			}
			for _, s := range plan.Skips {
				if s.OperatorChosen != tc.proven || s.Policy || s.ClearsNothing {
					t.Errorf("operator-chosen should be set only when the operator is proven current: %+v", s)
				}
				if s.Reason != tc.reason {
					t.Errorf("reason = %q, want %q", s.Reason, tc.reason)
				}
			}
		})
	}
}

func TestOperatorChartUpgradeIsRaisedWithoutClaimingWhatItClears(t *testing.T) {
	plan, err := bundledPlanner(t).Plan(eventBusFindings(operatorChartUpgrade))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("want one ticket for the operator's chart, got %d (skips %+v)", len(plan.Drafts), plan.Skips)
	}
	d := plan.Drafts[0]
	if d.Summary != "Upgrade argo-events to 2.4.16" {
		t.Errorf("summary = %q", d.Summary)
	}
	if strings.Contains(d.Description, "Done means") {
		t.Errorf("nothing measured what the operator's upgrade clears, so nothing is claimed:\n%s", d.Description)
	}
	want := "* nats: 2.10.29 (chosen at runtime by the operator the argo-events chart installs, which moves 2.4.15 -> 2.4.16"
	if !strings.Contains(d.Description, want) {
		t.Errorf("row should say the operator picks the tag:\n%s", d.Description)
	}
	for _, wrong := range []string{"2.14.7", "set by the argo-events chart", "version owned by"} {
		if strings.Contains(d.Description, wrong) {
			t.Errorf("description says %q:\n%s", wrong, d.Description)
		}
	}
}

// DVOP-4491's shape: each Crossplane function's package is set in its own
// revision, so the change is a direct bump of the package there.
func TestCustomResourceSetImagesAreStillBumped(t *testing.T) {
	fn := func(name, rev, current, latest string) sink.FindingView {
		repo := "crossplane-contrib/" + name
		return finding(repo, func(f *sink.FindingView) {
			f.Image, f.Tag = "xpkg.crossplane.io/"+repo+":"+current, current
			f.Upgrade = &sink.UpgradeView{
				Kind: "image", Name: "xpkg.crossplane.io/" + repo, Current: current, Latest: latest,
				Available: true, Resolved: true, Actionable: true,
				Source: "FunctionRevision/crossplane-system/" + rev,
			}
		})
	}
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{
		fn("function-auto-ready", "function-auto-ready-59868730b9a9", "v0.6.0", "v0.7.0"),
		fn("function-go-templating", "function-go-templating-10dcf7881e85", "v0.11.3", "v0.11.4"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("want one ticket for the functions, got %d (skips %+v)", len(plan.Drafts), plan.Skips)
	}
	d := plan.Drafts[0]
	if d.Summary != "Upgrade crossplane-system functions (2) to their latest versions" {
		t.Errorf("summary = %q", d.Summary)
	}
	if !strings.Contains(d.Description, "* crossplane-contrib/function-auto-ready: v0.6.0 -> v0.7.0, change in FunctionRevision/crossplane-system/function-auto-ready-59868730b9a9") {
		t.Errorf("row should be a direct bump in the revision:\n%s", d.Description)
	}
	if strings.Contains(d.Description, "version owned by") {
		t.Errorf("a package set in the resource is not owned elsewhere:\n%s", d.Description)
	}
}

// The ticket DVOP-4420 already raised, in production: the operator is unknown, so
// nobody can say whether an upgrade exists. The ticket is held, never closed.
func TestAnOpenTicketForImagesOfAnUnknownOperatorIsHeld(t *testing.T) {
	findings := eventBusFindings(unknownOperator)
	plan, err := bundledPlanner(t).Plan(findings)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.JiraConfig{Project: "DVOP", AutoClose: true, CloseTransitionNoLongerActionable: "WON'T BE DONE"}
	got := Reconcile(ReconcileInput{Config: cfg, Findings: findings, Skipped: plan.Skips, OpenByImage: openDVOP4420()})
	if len(got) != 1 || got[0].Kind != ActionHold {
		t.Fatalf("got %+v, want one hold", got)
	}
	for _, want := range []string{"cannot tell", eventBusReason} {
		if !strings.Contains(got[0].Why, want) {
			t.Errorf("hold should say %q: %s", want, got[0].Why)
		}
	}
}

// Once the operator is shown to be on its latest version the ticket's change is
// proven not to exist: closed as not done, or commented on. Never reported done.
func TestAnOpenTicketForImagesOfAnOperatorOnItsLatestVersionIsClosedNotDone(t *testing.T) {
	findings := eventBusFindings(operatorOnLatest)
	plan, err := bundledPlanner(t).Plan(findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  config.JiraConfig
		kind ActionKind
	}{
		{"closes when a not-done transition exists", config.JiraConfig{Project: "DVOP", AutoClose: true,
			CloseTransitionNoLongerActionable: "WON'T BE DONE"}, ActionClose},
		{"comments otherwise", config.JiraConfig{Project: "DVOP", AutoClose: true}, ActionNoteDone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Reconcile(ReconcileInput{
				Config: tc.cfg, Findings: findings, Skipped: plan.Skips, OpenByImage: openDVOP4420(),
			})
			if len(got) != 1 {
				t.Fatalf("got %+v, want one action", got)
			}
			a := got[0]
			if a.Kind != tc.kind || a.Reason != ReasonOperatorChosen {
				t.Fatalf("got %s/%s, want %s/%s: %+v", a.Kind, a.Reason, tc.kind, ReasonOperatorChosen, a)
			}
			if a.Kind == ActionClose && (!a.NoLongerActionable || !a.Unworked) {
				t.Errorf("a close must use the not-done transition: %+v", a)
			}
			for _, want := range []string{"already on its latest version", "nats: " + latestReason, "stay in the queue"} {
				if !strings.Contains(a.Message, want) {
					t.Errorf("comment should say %q:\n%s", want, a.Message)
				}
			}
		})
	}
}

func openDVOP4420() map[string][]Existing {
	open := map[string][]Existing{}
	for _, n := range natsRepos {
		open[n.repo] = []Existing{{Key: "DVOP-4420", Category: "new"}}
	}
	return open
}
