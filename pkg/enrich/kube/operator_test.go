package kube

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

func controllerRef(apiVersion, kind, name string) metav1.OwnerReference {
	yes := true
	return metav1.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, Controller: &yes}
}

// eventBusStatefulSet is the NATS StatefulSet Argo Events creates for an EventBus,
// as observed in production: owned by the EventBus, and carrying the Flux
// Kustomize labels the controller copied from it.
func eventBusStatefulSet() *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "argo-events", Name: "eventbus-cpo-js",
			Labels: map[string]string{
				"controller":                            "eventbus-controller",
				"eventbus-name":                         "cpo",
				"owner-name":                            "cpo",
				"kustomize.toolkit.fluxcd.io/name":      "argo-events-event-bus",
				"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
			},
			OwnerReferences: []metav1.OwnerReference{controllerRef("argoproj.io/v1alpha1", "EventBus", "cpo")},
		},
		Spec: appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Image: "nats:2.10.29"},
				{Image: "natsio/nats-server-config-reloader:0.14.0"},
				{Image: "natsio/prometheus-nats-exporter:0.14.0"},
			},
		}}},
	}
}

// eventBus is the EventBus as flux-infra declares it: a NATS version, never an
// image reference. The controller maps the version to images from its own config.
func eventBus(labels map[string]interface{}) *unstructured.Unstructured {
	md := map[string]interface{}{"namespace": "argo-events", "name": "cpo"}
	if labels != nil {
		md["labels"] = labels
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "argoproj.io/v1alpha1", "kind": "EventBus",
		"metadata": md,
		"spec": map[string]interface{}{"jetstream": map[string]interface{}{
			"version": "2.10.29", "replicas": int64(3),
		}},
	}}
}

func fluxKustomizeDyn() *dynamicfake.FakeDynamicClient {
	kust := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
		"metadata": map[string]interface{}{"namespace": "flux-system", "name": "argo-events-event-bus"},
		"spec": map[string]interface{}{
			"path":      "./bases/argo-events/event-bus",
			"sourceRef": map[string]interface{}{"kind": "GitRepository", "name": "flux-infra"},
		},
	}}
	git := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository",
		"metadata": map[string]interface{}{"namespace": "flux-system", "name": "flux-infra"},
		"spec":     map[string]interface{}{"url": "https://example.test/flux-infra"},
	}}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			kustomizationGVR: "KustomizationList",
			gitRepositoryGVR: "GitRepositoryList",
			ociRepositoryGVR: "OCIRepositoryList",
		}, kust, git)
}

func fixedFetcher(cr *unstructured.Unstructured) crFetcher {
	return func(context.Context, string, string, string, string) (*unstructured.Unstructured, error) {
		return cr, nil
	}
}

// DVOP-4420: the inherited Kustomize labels made the NATS images look like a
// directly deployed manifest in flux-infra, so the newest registry tags were
// proposed as a bump there. The owner decides: the operator chose these images.
func TestOperatorOwnedWorkloadIgnoresInheritedKustomizeLabels(t *testing.T) {
	typed := kubefake.NewSimpleClientset(eventBusStatefulSet())
	out := map[string]enrich.DeployContext{}
	if err := clusterImageDeployments(context.Background(), typed, fluxKustomizeDyn(), fixedFetcher(eventBus(nil)), nil, out); err != nil {
		t.Fatal(err)
	}
	for _, img := range []string{"nats:2.10.29", "natsio/nats-server-config-reloader:0.14.0", "natsio/prometheus-nats-exporter:0.14.0"} {
		dc, ok := out[model.ParseImageRef(img).NameTag()]
		if !ok {
			t.Fatalf("%s: no context", img)
		}
		if dc.Mechanism != "operator" || dc.Actionable {
			t.Errorf("%s: got %+v, want a non-actionable operator context", img, dc)
		}
		if dc.Source != "EventBus/argo-events/cpo" || dc.SourcePath != "" {
			t.Errorf("%s: the change target must be the owning EventBus, not the repo that applied it: %+v", img, dc)
		}
	}
}

// A non-controller owner is a garbage-collection link, not a statement about
// who created the workload, so it does not outrank the labels.
func TestNonControllerOwnerDoesNotOutrankLabels(t *testing.T) {
	sts := eventBusStatefulSet()
	sts.OwnerReferences[0].Controller = nil
	typed := kubefake.NewSimpleClientset(sts)
	out := map[string]enrich.DeployContext{}
	if err := clusterImageDeployments(context.Background(), typed, fluxKustomizeDyn(), fixedFetcher(eventBus(nil)), nil, out); err != nil {
		t.Fatal(err)
	}
	if dc := out[model.ParseImageRef("nats:2.10.29").NameTag()]; dc.Mechanism != "kustomize" {
		t.Errorf("got %+v, want the Kustomize classification", dc)
	}
}

// DVOP-4491: a Crossplane function's Deployment is owned by a cluster-scoped
// FunctionRevision whose spec carries the image. Fetched under the Deployment's
// namespace it was a 404, so the image read as operator-derived. Read at cluster
// scope, it is set in the spec, and bumping the package is the change.
func TestClusterScopedOwnerIsReadAtClusterScope(t *testing.T) {
	const image = "xpkg.crossplane.io/crossplane-contrib/function-auto-ready:v0.6.0"
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "crossplane-system", Name: "function-auto-ready-59868730b9a9",
			OwnerReferences: []metav1.OwnerReference{
				controllerRef("pkg.crossplane.io/v1", "FunctionRevision", "function-auto-ready-59868730b9a9"),
			},
		},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Image: image}},
		}}},
	}
	revision := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "pkg.crossplane.io/v1", "kind": "FunctionRevision",
		"metadata": map[string]interface{}{
			"name":   "function-auto-ready-59868730b9a9",
			"labels": map[string]interface{}{"pkg.crossplane.io/package": "function-auto-ready"},
			"ownerReferences": []interface{}{map[string]interface{}{
				"apiVersion": "pkg.crossplane.io/v1", "kind": "Function", "name": "function-auto-ready",
				"uid": "aae180c9-d215-46df-9694-d1a361b73774", "controller": true,
			}},
		},
		"spec": map[string]interface{}{
			"desiredState": "Active", "image": image, "revision": int64(4),
		},
	}}
	revisionGVR := schema.GroupVersionResource{Group: "pkg.crossplane.io", Version: "v1", Resource: "functionrevisions"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			kustomizationGVR: "KustomizationList",
			gitRepositoryGVR: "GitRepositoryList",
			ociRepositoryGVR: "OCIRepositoryList",
			revisionGVR:      "FunctionRevisionList",
		}, revision)

	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(schema.GroupVersionKind{Group: "pkg.crossplane.io", Version: "v1", Kind: "FunctionRevision"}, meta.RESTScopeRoot)
	fetch := mappedCRFetcher(func() (meta.RESTMapper, error) { return mapper, nil }, dyn)

	out := map[string]enrich.DeployContext{}
	if err := clusterImageDeployments(context.Background(), kubefake.NewSimpleClientset(dep), dyn, fetch, nil, out); err != nil {
		t.Fatal(err)
	}
	dc := out[image]
	if dc.Mechanism != "operator" || !dc.Actionable {
		t.Errorf("got %+v, want an actionable operator context: the image is the revision's spec.image", dc)
	}
	// The revision is generated; the Function's spec.package is what a person edits.
	if dc.Source != "Function/crossplane-system/function-auto-ready" {
		t.Errorf("source = %q, want the Function that owns the revision", dc.Source)
	}
}
