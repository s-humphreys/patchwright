package registry

import (
	"context"
	"testing"

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

	if u := ups["acme.io/app:1.0.0"]; !u.Available || u.Latest != "1.2.0" || u.Kind != "image" {
		t.Errorf("1.0.0 should upgrade to 1.2.0, got %+v", u)
	}
	if u := ups["acme.io/app:1.2.0"]; u.Available {
		t.Errorf("1.2.0 is latest stable (rc ignored); should not be available, got %+v", u)
	}
	if _, ok := ups["acme.io/app:918319"]; ok {
		t.Error("non-semver tag should be skipped, not reported")
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
