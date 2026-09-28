package ticket

import (
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

const fluxReason = "version chosen by the operator flux-operator; upgrading it " +
	"(ghcr.io/controlplaneio-fluxcd/flux-operator v0.33.0 -> v0.60.0) is the only change that moves this image"

// fluxController is a Flux controller as remediation reports it in production:
// flux-operator picks its version and has a newer release that Helm owns, so the
// controller is a managed upgrade with no target tag of its own.
func fluxController(repo, tag string) sink.FindingView {
	return finding(repo, func(f *sink.FindingView) {
		f.Image, f.Tag = "ghcr.io/"+repo+":"+tag, tag
		f.Upgrade = &sink.UpgradeView{
			Kind: "image", Name: "ghcr.io/" + repo, Current: tag, Available: true, Resolved: true,
			Managed: "operator", Manager: "flux-operator", OperatorChosen: true, Reason: fluxReason,
		}
	})
}

func fluxOperator() sink.FindingView {
	return finding("controlplaneio-fluxcd/flux-operator", func(f *sink.FindingView) {
		f.Image, f.Tag = "ghcr.io/controlplaneio-fluxcd/flux-operator:v0.33.0", "v0.33.0"
		f.Upgrade = &sink.UpgradeView{
			Kind: "image", Name: "ghcr.io/controlplaneio-fluxcd/flux-operator", Current: "v0.33.0", Latest: "v0.60.0",
			Available: true, Resolved: true, Managed: "helm", Manager: "flux-operator-0.33.0",
			Source: "ghcr.io/controlplaneio-fluxcd/flux-operator",
		}
	})
}

// The behaviour main had and the operator-chosen change must keep: the
// controllers ride on the flux-operator ticket as consequences of its upgrade.
func TestFluxControllersFoldIntoTheFluxOperatorTicket(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{
		fluxController("fluxcd/source-controller", "v1.6.0"),
		fluxController("fluxcd/helm-controller", "v1.3.0"),
		fluxOperator(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("want one flux-operator ticket, got %v (skips %+v)", summaries(plan.Drafts), plan.Skips)
	}
	d := plan.Drafts[0]
	// Named from the chart label, as on main: "flux-operator-0.33.0".
	if !strings.HasPrefix(d.Summary, "Upgrade flux-operator") || !strings.HasSuffix(d.Summary, " to v0.60.0") {
		t.Errorf("summary = %q", d.Summary)
	}
	if len(d.Images) != 3 {
		t.Errorf("the ticket should account for all three images: %v", d.Images)
	}
	for _, want := range []string{"not bumped directly", "* fluxcd/source-controller: v1.6.0\n"} {
		if !strings.Contains(d.Description, want) {
			t.Errorf("description should contain %q:\n%s", want, d.Description)
		}
	}
	if strings.Contains(d.Description, "v1.7") {
		t.Errorf("no controller tag may be proposed:\n%s", d.Description)
	}
}

// Without the operator's own finding the controllers still stand as one managed
// change, and the ticket neither promises a version nor leaves a dangling arrow.
func TestFluxControllersWithoutTheirOperatorStillReadHonestly(t *testing.T) {
	plan, err := bundledPlanner(t).Plan([]sink.FindingView{
		fluxController("fluxcd/source-controller", "v1.6.0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("want one draft, got %d (skips %+v)", len(plan.Drafts), plan.Skips)
	}
	d := plan.Drafts[0]
	if strings.HasSuffix(d.Summary, " to ") || strings.Contains(d.Summary, " to  ") {
		t.Errorf("summary promises a version it does not have: %q", d.Summary)
	}
	if strings.Contains(d.Description, "v1.6.0 -> ") && !strings.Contains(d.Description, "v1.6.0 -> v") {
		t.Errorf("row has a dangling arrow:\n%s", d.Description)
	}
	if !strings.Contains(d.Description, "version owned by the operator") {
		t.Errorf("row should say the operator owns the version:\n%s", d.Description)
	}
}
