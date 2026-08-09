package registry

import (
	"context"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

type stubLister struct{ tags map[string][]string }

func (s stubLister) Tags(_ context.Context, repo string) ([]string, error) {
	return s.tags[repo], nil
}

func TestResolverFindsNewerSemverTag(t *testing.T) {
	r := &Resolver{Lister: stubLister{tags: map[string][]string{
		"acme.io/app": {"1.0.0", "1.1.0", "1.2.0", "1.3.0-rc.1", "latest"},
	}}}
	images := []model.AssessedImage{
		{Image: model.ParseImageRef("acme.io/app:1.0.0")},  // -> 1.2.0
		{Image: model.ParseImageRef("acme.io/app:1.2.0")},  // already latest stable
		{Image: model.ParseImageRef("acme.io/app:918319")}, // non-semver -> skipped
	}
	ups, err := r.Upgrades(context.Background(), images)
	if err != nil {
		t.Fatal(err)
	}

	if u := ups["acme.io/app:1.0.0"]; !u.Available || !u.Actionable || u.Latest != "1.2.0" || u.Kind != "image" {
		t.Errorf("1.0.0 should upgrade to 1.2.0 (actionable), got %+v", u)
	}
	if u := ups["acme.io/app:1.2.0"]; u.Available {
		t.Errorf("1.2.0 is latest stable (rc ignored); should not be available, got %+v", u)
	}
	if _, ok := ups["acme.io/app:918319"]; ok {
		t.Error("non-semver tag should be skipped, not reported")
	}
}

func TestResolverMarksManagedImagesNotActionable(t *testing.T) {
	r := &Resolver{
		Lister: stubLister{tags: map[string][]string{"acme.io/app": {"1.0.0", "1.2.0"}}},
		Contexts: func(_ context.Context) (map[string]enrich.DeployContext, error) {
			return map[string]enrich.DeployContext{
				"acme.io/app:1.0.0": {Mechanism: "operator", Actionable: false},
			}, nil
		},
	}
	ups, err := r.Upgrades(context.Background(), []model.AssessedImage{
		{Image: model.ParseImageRef("acme.io/app:1.0.0")},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := ups["acme.io/app:1.0.0"]
	if !u.Available {
		t.Errorf("a newer tag exists, should be Available: %+v", u)
	}
	if u.Actionable {
		t.Errorf("operator-managed image should NOT be directly actionable: %+v", u)
	}
	if u.Managed != "operator" {
		t.Errorf("expected Managed=operator, got %q", u.Managed)
	}
}

func TestResolverActionableWithSourceFromContext(t *testing.T) {
	// An operator image whose tag is set in the CR spec: actionable, and the
	// change target is the CR.
	r := &Resolver{
		Lister: stubLister{tags: map[string][]string{"acme.io/app": {"1.0.0", "1.2.0"}}},
		Contexts: func(_ context.Context) (map[string]enrich.DeployContext, error) {
			return map[string]enrich.DeployContext{
				"acme.io/app:1.0.0": {Mechanism: "operator", Actionable: true, Source: "Api/apps/my-api"},
			}, nil
		},
	}
	ups, err := r.Upgrades(context.Background(), []model.AssessedImage{
		{Image: model.ParseImageRef("acme.io/app:1.0.0")},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := ups["acme.io/app:1.0.0"]
	if !u.Actionable || u.Source != "Api/apps/my-api" {
		t.Errorf("CR-set image should be actionable with the CR as source, got %+v", u)
	}
}

func TestResolverIncludesPrereleaseWhenCurrentIsPrerelease(t *testing.T) {
	r := &Resolver{Lister: stubLister{tags: map[string][]string{
		"acme.io/app": {"1.2.0", "1.3.0-rc.1", "1.3.0-rc.2"},
	}}}
	images := []model.AssessedImage{{Image: model.ParseImageRef("acme.io/app:1.3.0-rc.1")}}
	ups, err := r.Upgrades(context.Background(), images)
	if err != nil {
		t.Fatal(err)
	}
	if u := ups["acme.io/app:1.3.0-rc.1"]; !u.Available || u.Latest != "1.3.0-rc.2" {
		t.Errorf("a pre-release current should see newer pre-releases, got %+v", u)
	}
}
