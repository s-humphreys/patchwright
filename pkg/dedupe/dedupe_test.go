package dedupe

import (
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

func occ(ref string, crit int) model.Occurrence {
	return model.Occurrence{
		Image:  model.ParseImageRef(ref),
		Counts: model.Counts{model.SeverityCritical: crit},
	}
}

func TestByImageCollapsesAndTakesMax(t *testing.T) {
	in := []model.Occurrence{
		occ("acr.io/app:1", 3),
		occ("acr.io/app:1", 5), // same image, higher critical
		occ("acr.io/other:2", 1),
		occ("acr.io/app:1", 2),
	}

	out := ByImage(in)

	if len(out) != 2 {
		t.Fatalf("expected 2 assessed images, got %d", len(out))
	}
	// Order follows first appearance.
	if out[0].Image.Ref != "acr.io/app:1" {
		t.Errorf("expected first image acr.io/app:1, got %q", out[0].Image.Ref)
	}
	if got := out[0].Counts.Get(model.SeverityCritical); got != 5 {
		t.Errorf("expected representative critical 5 (max), got %d", got)
	}
	if len(out[0].Occurrences) != 3 {
		t.Errorf("expected 3 occurrences rolled up, got %d", len(out[0].Occurrences))
	}
}

func TestByImageUnionsVulns(t *testing.T) {
	a := occ("acr.io/app:1", 1)
	a.Vulns = []model.Vulnerability{{ID: "CVE-1"}, {ID: "CVE-2"}}
	b := occ("acr.io/app:1", 1)
	b.Vulns = []model.Vulnerability{{ID: "CVE-2"}, {ID: "CVE-3"}}

	out := ByImage([]model.Occurrence{a, b})
	if len(out) != 1 {
		t.Fatalf("expected 1 image, got %d", len(out))
	}
	if len(out[0].Vulns) != 3 {
		t.Errorf("expected 3 unioned vulns (CVE-1,2,3), got %d", len(out[0].Vulns))
	}
}
