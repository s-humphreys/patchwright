package kube

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/upgrade"
)

type stubChecker struct{ up model.Upgrade }

func (s stubChecker) Check(context.Context, upgrade.ChartRef) (model.Upgrade, error) {
	return s.up, nil
}

// TestClusterUpgrades exercises the full Flux path against fake clients: a
// Helm-managed Deployment -> its HelmRelease -> its HelmRepository -> the (stub)
// chart check -> an upgrade attached to the image.
func TestClusterUpgrades(t *testing.T) {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "app",
			Labels: map[string]string{
				"helm.toolkit.fluxcd.io/name":      "app",
				"helm.toolkit.fluxcd.io/namespace": "apps",
			},
		},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Image: "acme.example.com/app:1.0.0"}},
		}}},
	}
	typed := kubefake.NewSimpleClientset(dep)

	hr := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease",
		"metadata": map[string]interface{}{"namespace": "apps", "name": "app"},
		"spec": map[string]interface{}{"chart": map[string]interface{}{"spec": map[string]interface{}{
			"chart": "app", "version": "1.0.0",
			"sourceRef": map[string]interface{}{"kind": "HelmRepository", "name": "repo"},
		}}},
	}}
	repo := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "HelmRepository",
		"metadata": map[string]interface{}{"namespace": "apps", "name": "repo"},
		"spec":     map[string]interface{}{"url": "https://charts.example.com"},
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			helmReleaseGVR:    "HelmReleaseList",
			helmRepositoryGVR: "HelmRepositoryList",
		}, hr, repo)

	checker := stubChecker{up: model.Upgrade{Kind: "chart", Name: "app", Current: "1.0.0", Latest: "1.2.0", Available: true}}
	result := map[string]model.Upgrade{}
	if err := clusterUpgrades(context.Background(), typed, dyn, checker, result); err != nil {
		t.Fatal(err)
	}

	up, ok := result["acme.example.com/app:1.0.0"]
	if !ok {
		t.Fatalf("expected an upgrade for the image, got none (%v)", result)
	}
	if !up.Available || up.Latest != "1.2.0" {
		t.Errorf("unexpected upgrade: %+v", up)
	}
}

func TestParseHelmRelease(t *testing.T) {
	hr := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"namespace": "apps", "name": "podinfo"},
		"spec": map[string]interface{}{
			"chart": map[string]interface{}{
				"spec": map[string]interface{}{
					"chart":     "podinfo",
					"version":   "6.5.0", // requested; overridden by status history below
					"sourceRef": map[string]interface{}{"kind": "HelmRepository", "name": "podinfo-repo"},
				},
			},
		},
		"status": map[string]interface{}{
			"history": []interface{}{map[string]interface{}{"chartVersion": "6.6.0"}},
		},
	}}

	key, info := parseHelmRelease(hr)
	if key != "apps/podinfo" {
		t.Errorf("key: got %q, want apps/podinfo", key)
	}
	if info.chart != "podinfo" {
		t.Errorf("chart: got %q", info.chart)
	}
	if info.version != "6.6.0" {
		t.Errorf("version should come from status history: got %q, want 6.6.0", info.version)
	}
	// sourceRef namespace defaults to the HelmRelease namespace.
	if info.repoKey != "apps/podinfo-repo" {
		t.Errorf("repoKey: got %q, want apps/podinfo-repo", info.repoKey)
	}
}

func TestParseHelmReleaseFallsBackToSpecVersion(t *testing.T) {
	hr := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"namespace": "apps", "name": "x"},
		"spec": map[string]interface{}{"chart": map[string]interface{}{"spec": map[string]interface{}{
			"chart": "x", "version": "1.2.3",
			"sourceRef": map[string]interface{}{"name": "repo", "namespace": "flux-system"},
		}}},
	}}
	_, info := parseHelmRelease(hr)
	if info.version != "1.2.3" {
		t.Errorf("version should fall back to spec.chart.spec.version, got %q", info.version)
	}
	if info.repoKey != "flux-system/repo" {
		t.Errorf("repoKey should use explicit sourceRef namespace, got %q", info.repoKey)
	}
}

func TestParseHelmRepository(t *testing.T) {
	repo := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"namespace": "apps", "name": "podinfo-repo"},
		"spec":     map[string]interface{}{"url": "https://stefanprodan.github.io/podinfo"},
	}}
	key, url := parseHelmRepository(repo)
	if key != "apps/podinfo-repo" || url != "https://stefanprodan.github.io/podinfo" {
		t.Errorf("got key=%q url=%q", key, url)
	}
}
