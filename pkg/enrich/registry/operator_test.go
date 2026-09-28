package registry

import (
	"context"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

type listerFunc func(context.Context, string) ([]string, error)

func (f listerFunc) Tags(ctx context.Context, repo string) ([]string, error) { return f(ctx, repo) }

// DVOP-4420: the newest NATS tags were proposed for an image Argo Events picks
// from its own supported-versions list. An operator-chosen image never gets a
// registry tag; without a way to find the operator it has no upgrade at all, and
// the reason says whose choice it is.
func TestResolverProposesNoTagForOperatorChosenImages(t *testing.T) {
	listed := false
	r := &Resolver{
		Lister: listerFunc(func(context.Context, string) ([]string, error) {
			listed = true
			return []string{"2.10.29", "2.14.7"}, nil
		}),
		Contexts: func(_ context.Context) (map[string]enrich.DeployContext, error) {
			return map[string]enrich.DeployContext{
				"docker.io/nats:2.10.29": {Mechanism: "operator", Source: "EventBus/argo-events/cpo"},
			}, nil
		},
	}
	ups, err := r.Upgrades(context.Background(), []model.AssessedImage{
		{Image: model.ParseImageRef("nats:2.10.29")},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := ups["docker.io/nats:2.10.29"]
	if u.Available || u.Latest != "" || u.Actionable {
		t.Errorf("no registry tag may be proposed for an operator-chosen image, got %+v", u)
	}
	if u.Resolved || !u.OperatorChosen || u.Managed != "operator" {
		t.Errorf("want an unresolved, operator-chosen answer, got %+v", u)
	}
	if want := "version chosen by the operator that reconciles EventBus/argo-events/cpo"; !strings.HasPrefix(u.Reason, want) {
		t.Errorf("reason = %q, want it to start %q", u.Reason, want)
	}
	if listed {
		t.Error("the registry was listed for an image whose tags are not the answer")
	}
}

// When the operator's own image is known, the answer carries it so the operator's
// upgrade can be attached once every source has answered.
func TestResolverPointsOperatorChosenImagesAtTheirOperator(t *testing.T) {
	r := &Resolver{
		Lister: stubLister{},
		Contexts: func(_ context.Context) (map[string]enrich.DeployContext, error) {
			return map[string]enrich.DeployContext{
				"docker.io/nats:2.10.29": {
					Mechanism: "operator", Source: "EventBus/argo-events/cpo",
					Manager: "argo-events", ManagerImage: "quay.io/argoproj/argo-events:v1.9.11",
				},
			}, nil
		},
	}
	ups, err := r.Upgrades(context.Background(), []model.AssessedImage{
		{Image: model.ParseImageRef("nats:2.10.29")},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := ups["docker.io/nats:2.10.29"]
	if u.OperatorImage != "quay.io/argoproj/argo-events:v1.9.11" || u.Manager != "argo-events" || u.Reason != "" {
		t.Errorf("got %+v", u)
	}
}

// An image whose tag the custom resource sets is still bumped there.
func TestResolverStillBumpsImagesSetInTheCustomResource(t *testing.T) {
	r := &Resolver{
		Lister: stubLister{tags: map[string][]string{
			"xpkg.crossplane.io/crossplane-contrib/function-auto-ready": {"v0.6.0", "v0.7.0"},
		}},
		Contexts: func(_ context.Context) (map[string]enrich.DeployContext, error) {
			return map[string]enrich.DeployContext{
				"xpkg.crossplane.io/crossplane-contrib/function-auto-ready:v0.6.0": {
					Mechanism: "operator", Actionable: true,
					Source: "FunctionRevision/crossplane-system/function-auto-ready-59868730b9a9",
				},
			}, nil
		},
	}
	ups, err := r.Upgrades(context.Background(), []model.AssessedImage{
		{Image: model.ParseImageRef("xpkg.crossplane.io/crossplane-contrib/function-auto-ready:v0.6.0")},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := ups["xpkg.crossplane.io/crossplane-contrib/function-auto-ready:v0.6.0"]
	if !u.Available || !u.Actionable || u.Latest != "v0.7.0" || u.OperatorChosen || u.Managed != "" {
		t.Errorf("want a direct bump of the package the revision names, got %+v", u)
	}
}
