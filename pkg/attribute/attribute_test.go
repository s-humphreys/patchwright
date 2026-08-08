package attribute

import (
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

func newTestAttributor(t *testing.T) *Attributor {
	t.Helper()
	a, err := New([]config.OwnerRule{
		{Name: "cloud", Match: "image.registry == 'mcr.microsoft.com'", Class: "cloud-provider", Team: "aks"},
		{Name: "platform", Match: "dimensions['namespace'] == 'flux-system'", Class: "platform", Team: "platform-engineering"},
		{Name: "by-label", Match: "'team' in labels", Class: "engineering", TeamFrom: "labels['team']"},
		{Name: "default", Match: "true", Class: "engineering", TeamFrom: "dimensions['namespace']"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func occurrence(registry, namespace string, labels map[string]string) model.Occurrence {
	return model.Occurrence{
		Image: model.Image{Registry: registry, Repository: "x", Ref: registry + "/x:1"},
		Resource: model.Resource{
			Dimensions: map[string]string{"namespace": namespace},
			Labels:     labels,
		},
	}
}

func TestAttributeFirstMatchWins(t *testing.T) {
	a := newTestAttributor(t)

	// A cloud-provider image inside a platform namespace must resolve to
	// cloud-provider: the earlier rule wins.
	got, err := a.Attribute(occurrence("mcr.microsoft.com", "flux-system", nil))
	if err != nil {
		t.Fatal(err)
	}
	if got.Class != "cloud-provider" || got.Team != "aks" {
		t.Errorf("got %+v, want cloud-provider/aks", got)
	}
}

func TestAttributeLabelTakesPrecedenceOverNamespace(t *testing.T) {
	a := newTestAttributor(t)
	got, err := a.Attribute(occurrence("acr.io", "orders", map[string]string{"team": "rewards"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Class != "engineering" || got.Team != "rewards" {
		t.Errorf("got %+v, want engineering/rewards (from team label)", got)
	}
}

func TestAttributeFallsBackToNamespace(t *testing.T) {
	a := newTestAttributor(t)
	got, err := a.Attribute(occurrence("acr.io", "billing", nil))
	if err != nil {
		t.Fatal(err)
	}
	if got.Team != "billing" {
		t.Errorf("got team %q, want billing (from namespace)", got.Team)
	}
}

func TestNewRejectsBadExpression(t *testing.T) {
	if _, err := New([]config.OwnerRule{{Name: "bad", Match: "this is not cel ++"}}); err == nil {
		t.Error("expected compile error for invalid expression")
	}
}

func TestNewRejectsNonBoolMatch(t *testing.T) {
	if _, err := New([]config.OwnerRule{{Name: "notbool", Match: "dimensions['namespace']"}}); err == nil {
		t.Error("expected error for match expression that does not return bool")
	}
}
