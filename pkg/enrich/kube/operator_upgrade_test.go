package kube

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/enrich/registry"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// These tests run the remediation path the way an assessment does: the cluster's
// deployment contexts and Flux chart upgrades, then the registry tag source, all
// merged by the remediation enricher. Only the registry and the chart repository
// are stubbed.

type staticSource map[string]model.Upgrade

func (s staticSource) Upgrades(context.Context, []model.AssessedImage) (map[string]model.Upgrade, error) {
	return s, nil
}

type tagLister map[string][]string

func (t tagLister) Tags(_ context.Context, repo string) ([]string, error) { return t[repo], nil }

// newestTags is what the registry offered in DVOP-4420: tags no Argo Events
// release supports.
var newestTags = tagLister{
	"docker.io/nats": {"2.10.29", "2.14.7"},
	"docker.io/natsio/nats-server-config-reloader": {"0.14.0", "0.24.0"},
	"docker.io/natsio/prometheus-nats-exporter":    {"0.14.0", "0.20.2"},
	"docker.io/acme/app":                           {"1.0.0", "1.2.0"},
	"ghcr.io/controlplaneio-fluxcd/source-ctrl":    {"v1.6.0", "v1.7.0"},
}

// helmInstalled is an operator Deployment installed by a Flux HelmRelease.
func helmInstalled(ns, name, image string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: map[string]string{
			"helm.toolkit.fluxcd.io/name":      name,
			"helm.toolkit.fluxcd.io/namespace": ns,
		}},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Image: image}},
		}}},
	}
}

func remediationDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			kustomizationGVR:  "KustomizationList",
			gitRepositoryGVR:  "GitRepositoryList",
			ociRepositoryGVR:  "OCIRepositoryList",
			helmReleaseGVR:    "HelmReleaseList",
			helmRepositoryGVR: "HelmRepositoryList",
		}, objs...)
}

// remediate runs the assessment's remediation sources over the cluster and
// returns each image's upgrade.
func remediate(t *testing.T, typed kubernetes.Interface, dyn *dynamicfake.FakeDynamicClient, fetch crFetcher, chart model.Upgrade, refs ...string) map[string]*model.Upgrade {
	t.Helper()
	ctx := context.Background()
	contexts := map[string]enrich.DeployContext{}
	if err := clusterImageDeployments(ctx, typed, dyn, fetch, contexts); err != nil {
		t.Fatal(err)
	}
	charts := map[string]model.Upgrade{}
	if err := clusterUpgrades(ctx, typed, dyn, stubChecker{up: chart}, charts); err != nil {
		t.Fatal(err)
	}
	reg := &registry.Resolver{
		Lister: newestTags,
		Contexts: func(context.Context) (map[string]enrich.DeployContext, error) {
			return contexts, nil
		},
	}
	images := make([]model.AssessedImage, 0, len(refs))
	for _, r := range refs {
		images = append(images, model.AssessedImage{Image: model.ParseImageRef(r)})
	}
	if err := enrich.NewRemediationEnricher(staticSource(charts), reg).EnrichImages(ctx, images); err != nil {
		t.Fatal(err)
	}
	out := map[string]*model.Upgrade{}
	for _, img := range images {
		out[img.Image.Ref] = img.Upgrade
	}
	return out
}

var natsImages = []string{
	"nats:2.10.29",
	"natsio/nats-server-config-reloader:0.14.0",
	"natsio/prometheus-nats-exporter:0.14.0",
}

// DVOP-4420 as it happened: nothing names the operator, so there is no upgrade to
// propose for the NATS images, and the reason says whose choice their version is.
func TestOperatorChosenImagesGetNoRegistryUpgrade(t *testing.T) {
	typed := kubefake.NewSimpleClientset(eventBusStatefulSet())
	ups := remediate(t, typed, remediationDyn(), fixedFetcher(eventBus(nil)), model.Upgrade{}, natsImages...)
	for _, ref := range natsImages {
		u := ups[ref]
		if u == nil {
			t.Fatalf("%s: no remediation answer", ref)
		}
		if u.Available || u.Latest != "" {
			t.Errorf("%s: proposed %q; the operator chooses this version", ref, u.Latest)
		}
		if !u.Resolved || !u.OperatorChosen {
			t.Errorf("%s: want a resolved, operator-chosen answer, got %+v", ref, u)
		}
		if !strings.Contains(u.Reason, "version chosen by the operator that reconciles EventBus/argo-events/cpo") {
			t.Errorf("%s: reason = %q", ref, u.Reason)
		}
	}
}

// The same EventBus when its operator is named and installed from a chart with a
// newer release: the proposal is the operator's chart, and nothing claims to know
// which NATS tag that deploys.
func TestOperatorChosenImagesGetTheOperatorsChartUpgrade(t *testing.T) {
	typed := kubefake.NewSimpleClientset(
		eventBusStatefulSet(),
		helmInstalled("argo-events", "argo-events", "quay.io/argoproj/argo-events:v1.9.11"),
	)
	dyn := remediationDyn(helmRelease("argo-events", "argo-events", "argo-events", "2.4.15", "charts", nil), helmRepository("argo-events", "charts", "https://charts.example.test"))
	cr := eventBus(map[string]interface{}{"app.kubernetes.io/part-of": "argo-events"})
	chart := model.Upgrade{Kind: "chart", Name: "argo-events", Current: "2.4.15", Latest: "2.4.16",
		Source: "https://charts.example.test", Available: true, Actionable: true, Resolved: true}

	ups := remediate(t, typed, dyn, fixedFetcher(cr), chart, natsImages...)
	for _, ref := range natsImages {
		u := ups[ref]
		if u == nil {
			t.Fatalf("%s: no remediation answer", ref)
		}
		if u.Kind != "chart" || u.Name != "argo-events" || u.Current != "2.4.15" || u.Latest != "2.4.16" {
			t.Errorf("%s: want the operator's chart bump, got %+v", ref, u)
		}
		if !u.Available || !u.Actionable || !u.OperatorChosen || u.Managed != "operator" || u.Manager != "argo-events" {
			t.Errorf("%s: got %+v", ref, u)
		}
		if u.ImageCurrent != model.ParseImageRef(ref).Tag || u.ImageLatest != "" {
			t.Errorf("%s: the tag the operator will pick is unknown, got %q -> %q", ref, u.ImageCurrent, u.ImageLatest)
		}
	}
}

// An operator already on its newest chart leaves nothing to propose.
func TestOperatorOnItsLatestVersionLeavesNoUpgrade(t *testing.T) {
	typed := kubefake.NewSimpleClientset(
		eventBusStatefulSet(),
		helmInstalled("argo-events", "argo-events", "quay.io/argoproj/argo-events:v1.9.11"),
	)
	dyn := remediationDyn(helmRelease("argo-events", "argo-events", "argo-events", "2.4.16", "charts", nil), helmRepository("argo-events", "charts", "https://charts.example.test"))
	cr := eventBus(map[string]interface{}{"app.kubernetes.io/part-of": "argo-events"})
	chart := model.Upgrade{Kind: "chart", Name: "argo-events", Current: "2.4.16", Resolved: true}

	u := remediate(t, typed, dyn, fixedFetcher(cr), chart, "nats:2.10.29")["nats:2.10.29"]
	if u == nil || u.Available {
		t.Fatalf("want no upgrade, got %+v", u)
	}
	if want := "version chosen by the operator argo-events; the operator is on its latest version"; u.Reason != want {
		t.Errorf("reason = %q, want %q", u.Reason, want)
	}
}

// The label-based case: flux-operator names itself on the controllers it runs.
func TestManagedByLabelImagesGetTheOperatorsChartUpgrade(t *testing.T) {
	ctrl := deployment("flux-system", "source-controller",
		map[string]string{"app.kubernetes.io/managed-by": "flux-operator"}, nil,
		"ghcr.io/controlplaneio-fluxcd/source-ctrl:v1.6.0")
	typed := kubefake.NewSimpleClientset(ctrl,
		helmInstalled("flux-system", "flux-operator", "ghcr.io/controlplaneio-fluxcd/flux-operator:v0.20.0"))
	dyn := remediationDyn(helmRelease("flux-system", "flux-operator", "flux-operator", "0.20.0", "charts", nil), helmRepository("flux-system", "charts", "https://charts.example.test"))
	chart := model.Upgrade{Kind: "chart", Name: "flux-operator", Current: "0.20.0", Latest: "0.21.0",
		Available: true, Actionable: true, Resolved: true}

	u := remediate(t, typed, dyn, fixedFetcher(nil), chart,
		"ghcr.io/controlplaneio-fluxcd/source-ctrl:v1.6.0")["ghcr.io/controlplaneio-fluxcd/source-ctrl:v1.6.0"]
	if u == nil || u.Kind != "chart" || u.Name != "flux-operator" || u.Latest != "0.21.0" {
		t.Fatalf("want the flux-operator chart bump, got %+v", u)
	}
	if u.Manager != "flux-operator" || !u.OperatorChosen || u.ImageLatest != "" {
		t.Errorf("got %+v", u)
	}
}

// An image the custom resource sets is still a bump of that resource.
func TestImageSetInTheCustomResourceIsStillBumpedThere(t *testing.T) {
	api := deployment("apps", "api", nil,
		[]metav1.OwnerReference{controllerRef("example.com/v1", "Api", "my-api")}, "acme/app:1.0.0")
	cr := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"labels": map[string]interface{}{"app.kubernetes.io/part-of": "api-operator"}},
		"spec":     map[string]interface{}{"image": "acme/app:1.0.0"},
	}}
	u := remediate(t, kubefake.NewSimpleClientset(api), remediationDyn(), fixedFetcher(cr), model.Upgrade{},
		"acme/app:1.0.0")["acme/app:1.0.0"]
	if u == nil || !u.Available || !u.Actionable || u.Latest != "1.2.0" || u.OperatorChosen {
		t.Fatalf("want a direct bump to 1.2.0, got %+v", u)
	}
	if u.Source != "Api/apps/my-api" {
		t.Errorf("source = %q, want the custom resource", u.Source)
	}
}
