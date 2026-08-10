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

	"github.com/s-humphreys/patchwright/pkg/enrich"
)

func TestOwnerGroupIsCustom(t *testing.T) {
	cases := map[string]bool{
		"apps/v1":                   false,
		"batch/v1":                  false,
		"v1":                        false, // core
		"tailscale.com/v1alpha1":    true,
		"helm.toolkit.fluxcd.io/v2": true,
	}
	for apiVersion, want := range cases {
		if got := ownerGroupIsCustom(apiVersion); got != want {
			t.Errorf("ownerGroupIsCustom(%q) = %v, want %v", apiVersion, got, want)
		}
	}
}

func TestImageInSpec(t *testing.T) {
	cr := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{
			"image":    "acme.io/app:1.0.0",
			"replicas": int64(2),
			"nested":   map[string]interface{}{"sidecar": map[string]interface{}{"image": "acme.io/side:2.0.0"}},
		},
	}}
	if !imageInSpec(cr, "acme.io/app:1.0.0") {
		t.Error("top-level spec.image should be found")
	}
	if !imageInSpec(cr, "acme.io/side:2.0.0") {
		t.Error("nested image should be found")
	}
	if imageInSpec(cr, "acme.io/other:9") {
		t.Error("absent image should not be found")
	}
}

func deployment(ns, name string, labels map[string]string, owners []metav1.OwnerReference, image string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels, OwnerReferences: owners},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Image: image}},
		}}},
	}
}

func TestClusterImageDeployments(t *testing.T) {
	typed := kubefake.NewSimpleClientset(
		// plain manifest
		deployment("apps", "plain", nil, nil, "acme.io/plain:1.0.0"),
		// Flux Kustomize
		deployment("apps", "kust", map[string]string{
			"kustomize.toolkit.fluxcd.io/name":      "apps",
			"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
		}, nil, "acme.io/kust:1.0.0"),
		// operator, image set in CR spec -> actionable
		deployment("apps", "api", nil, []metav1.OwnerReference{
			{APIVersion: "example.com/v1", Kind: "Api", Name: "my-api"},
		}, "acme.io/api:1.0.0"),
		// operator, image NOT in CR spec -> derived, not actionable
		deployment("apps", "proxy", nil, []metav1.OwnerReference{
			{APIVersion: "example.com/v1", Kind: "Proxy", Name: "my-proxy"},
		}, "acme.io/proxy:1.0.0"),
		// label-based controller ownership (no ownerRefs), e.g. flux-operator
		deployment("apps", "ctrl", map[string]string{"app.kubernetes.io/managed-by": "flux-operator"}, nil, "acme.io/ctrl:1.0.0"),
		// operator-owned via a CR whose own labels name the operator, as a real
		// Kiali CR does (app.kubernetes.io/part-of=kiali-operator).
		deployment("apps", "dash", map[string]string{"app.kubernetes.io/name": "dash"}, []metav1.OwnerReference{
			{APIVersion: "example.com/v1", Kind: "Dash", Name: "my-dash"},
		}, "acme.io/dash:1.0.0"),
	)

	kust := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
		"metadata": map[string]interface{}{"namespace": "flux-system", "name": "apps"},
		"spec": map[string]interface{}{
			"path":      "./apps",
			"sourceRef": map[string]interface{}{"kind": "GitRepository", "name": "repo"},
		},
	}}
	git := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository",
		"metadata": map[string]interface{}{"namespace": "flux-system", "name": "repo"},
		"spec":     map[string]interface{}{"url": "https://github.com/acme/infra"},
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{
			kustomizationGVR: "KustomizationList",
			gitRepositoryGVR: "GitRepositoryList",
			ociRepositoryGVR: "OCIRepositoryList",
		}, kust, git)

	// Stub CR fetcher: the Api CR has the image in its spec; the Proxy CR doesn't.
	fetch := func(_ context.Context, apiVersion, kind, ns, name string) (*unstructured.Unstructured, error) {
		spec := map[string]interface{}{"replicas": int64(1)}
		if kind == "Api" {
			spec["image"] = "acme.io/api:1.0.0"
		}
		meta := map[string]interface{}{}
		if kind == "Dash" {
			meta["labels"] = map[string]interface{}{"app.kubernetes.io/part-of": "dash-operator"}
		}
		return &unstructured.Unstructured{Object: map[string]interface{}{
			"metadata": meta, "spec": spec,
		}}, nil
	}

	out := map[string]enrich.DeployContext{}
	if err := clusterImageDeployments(context.Background(), typed, dyn, fetch, out); err != nil {
		t.Fatal(err)
	}

	check := func(nametag, mech string, actionable bool, source, sourcePath, manager string) {
		dc, ok := out[nametag]
		if !ok {
			t.Fatalf("%s: no context", nametag)
		}
		if dc.Mechanism != mech || dc.Actionable != actionable ||
			(source != "" && dc.Source != source) || dc.SourcePath != sourcePath ||
			dc.Manager != manager {
			t.Errorf("%s: got %+v, want mechanism=%s actionable=%v source=%s path=%s manager=%s",
				nametag, dc, mech, actionable, source, sourcePath, manager)
		}
	}
	check("acme.io/plain:1.0.0", "manifest", true, "", "", "")
	// The Kustomization's repo and path are reported SEPARATELY. Joining them
	// with kustomize's "//" notation yields a string that looks like a URL and is
	// not one, which matters wherever a change target gets rendered as a link.
	check("acme.io/kust:1.0.0", "kustomize", true, "https://github.com/acme/infra", "apps", "")
	check("acme.io/api:1.0.0", "operator", true, "Api/apps/my-api", "", "") // image in CR spec
	check("acme.io/proxy:1.0.0", "operator", false, "", "", "")             // derived
	// A controller named by a label is a Manager, not a change location: the
	// version cannot be edited in place, so the remediation is to upgrade it.
	check("acme.io/ctrl:1.0.0", "operator", false, "", "", "flux-operator")
	// And a CR that labels itself with its operator names that operator, rather
	// than the Kind being guessed into a name.
	check("acme.io/dash:1.0.0", "operator", false, "Dash/apps/my-dash", "", "dash-operator")
}
