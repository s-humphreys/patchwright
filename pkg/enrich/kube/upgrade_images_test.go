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
)

func helmRelease(ns, name, chart, version, repo string, values map[string]interface{}) *unstructured.Unstructured {
	spec := map[string]interface{}{"chart": map[string]interface{}{"spec": map[string]interface{}{
		"chart": chart, "version": version,
		"sourceRef": map[string]interface{}{"kind": "HelmRepository", "name": repo},
	}}}
	if values != nil {
		spec["values"] = values
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "helm.toolkit.fluxcd.io/v2", "kind": "HelmRelease",
		"metadata": map[string]interface{}{"namespace": ns, "name": name},
		"spec":     spec,
	}}
}

func helmRepository(ns, name, url string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "HelmRepository",
		"metadata": map[string]interface{}{"namespace": ns, "name": name},
		"spec":     map[string]interface{}{"url": url},
	}}
}

func fluxDynamic(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			helmReleaseGVR:    "HelmReleaseList",
			helmRepositoryGVR: "HelmRepositoryList",
		}, objs...)
}

func fluxLabels(ns, name string) map[string]string {
	return map[string]string{"helm.toolkit.fluxcd.io/name": name, "helm.toolkit.fluxcd.io/namespace": ns}
}

// A chart bump says, per image, which tag the target chart would deploy: the
// retool case, where one image's tag is pinned in the release and the other's is
// the same in both chart versions, so the bump moves neither.
func TestClusterUpgradesResolvesEachImagesTargetTag(t *testing.T) {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "retool", Name: "backend", Labels: fluxLabels("retool", "retool")},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Image: "tryretool/backend:4.34.1-stable"}},
		}}},
	}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "retool", Name: "device-plugin", Labels: fluxLabels("retool", "retool")},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Image: "ghcr.io/smarter-project/smarter-device-manager:v1.20.12"},
				{Image: "acme.example.com/sidecar:1.0"},
			},
		}}},
	}
	dyn := fluxDynamic(
		helmRelease("retool", "retool", "retool", "6.11.32", "retool", map[string]interface{}{
			"image": map[string]interface{}{"repository": "tryretool/backend", "tag": "4.34.1-stable"},
		}),
		helmRepository("retool", "retool", "https://charts.retool.com"),
	)

	var asked string
	checker := stubChecker{
		up: model.Upgrade{Kind: "chart", Name: "retool", Current: "6.11.32", Latest: "6.11.33", Available: true, Resolved: true},
		values: map[string]any{
			"image": map[string]any{"repository": "tryretool/backend", "tag": ""},
			"devicePlugin": map[string]any{"image": map[string]any{
				"repository": "ghcr.io/smarter-project/smarter-device-manager", "tag": "v1.20.12",
			}},
		},
		asked: &asked,
	}
	result := map[string]model.Upgrade{}
	if err := clusterUpgrades(context.Background(), kubefake.NewSimpleClientset(dep, ds), dyn, checker, result); err != nil {
		t.Fatal(err)
	}
	if asked != "6.11.33" {
		t.Errorf("values should be read for the target version, got %q", asked)
	}
	for _, tc := range []struct {
		image, current, latest string
		pinned                 bool
	}{
		{"docker.io/tryretool/backend:4.34.1-stable", "4.34.1-stable", "4.34.1-stable", true},
		{"ghcr.io/smarter-project/smarter-device-manager:v1.20.12", "v1.20.12", "v1.20.12", false},
		// Not in the chart's values: unknown, never assumed unchanged.
		{"acme.example.com/sidecar:1.0", "1.0", "", false},
	} {
		up, ok := result[tc.image]
		if !ok {
			t.Fatalf("no upgrade for %s (%v)", tc.image, result)
		}
		if up.Current != "6.11.32" || up.Latest != "6.11.33" {
			t.Errorf("%s: chart versions should be unchanged: %+v", tc.image, up)
		}
		if up.ImageCurrent != tc.current || up.ImageLatest != tc.latest || up.ImagePinned != tc.pinned {
			t.Errorf("%s: image %q -> %q pinned=%v, want %q -> %q pinned=%v", tc.image,
				up.ImageCurrent, up.ImageLatest, up.ImagePinned, tc.current, tc.latest, tc.pinned)
		}
	}
}

// Target chart unreadable: the chart upgrade stands, and each image's target is
// unknown rather than guessed. A tag pinned in the release still answers.
func TestClusterUpgradesWithoutChartValues(t *testing.T) {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "app", Labels: fluxLabels("apps", "app")},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Image: "acme.example.com/app:1.0.0"}, {Image: "acme.example.com/pinned:3.0"}},
		}}},
	}
	dyn := fluxDynamic(
		helmRelease("apps", "app", "app", "1.0.0", "repo", map[string]interface{}{"pinned": map[string]interface{}{
			"image": map[string]interface{}{"registry": "acme.example.com", "repository": "pinned", "tag": "3.0"},
		}}),
		helmRepository("apps", "repo", "https://charts.example.com"),
	)

	checker := stubChecker{up: model.Upgrade{Kind: "chart", Name: "app", Current: "1.0.0", Latest: "1.2.0", Available: true}}
	result := map[string]model.Upgrade{}
	if err := clusterUpgrades(context.Background(), kubefake.NewSimpleClientset(dep), dyn, checker, result); err != nil {
		t.Fatal(err)
	}
	if up := result["acme.example.com/app:1.0.0"]; !up.Available || up.ImageCurrent != "1.0.0" || up.ImageLatest != "" {
		t.Errorf("unreadable chart should leave the target unknown: %+v", up)
	}
	if up := result["acme.example.com/pinned:3.0"]; up.ImageLatest != "3.0" || !up.ImagePinned {
		t.Errorf("a tag pinned in the release is known without the chart: %+v", up)
	}
}
