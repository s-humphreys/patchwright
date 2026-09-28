package kube

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

// DVOP-4556 in production: the EventBus carries only the Flux labels of the
// Kustomization that applied it, so nothing on it names Argo Events. Its CRD was
// installed by the argo-events Kustomization, which also installed exactly one
// workload: the controller-manager, on the latest argo-events release.

const argoEventsImage = "quay.io/argoproj/argo-events:v1.9.11"

func argoEventsKustomization() map[string]string {
	return map[string]string{
		"kustomize.toolkit.fluxcd.io/name":      "argo-events",
		"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
	}
}

// eventBusFromFlux is the EventBus as applied in production: Flux labels only.
func eventBusFromFlux() *unstructured.Unstructured {
	return eventBus(map[string]interface{}{
		"kustomize.toolkit.fluxcd.io/name":      "argo-events-event-bus",
		"kustomize.toolkit.fluxcd.io/namespace": "flux-system",
	})
}

func eventBusCRD(labels, annotations map[string]string) *unstructured.Unstructured {
	crd := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
		"metadata": map[string]interface{}{"name": "eventbus.argoproj.io"},
	}}
	crd.SetLabels(labels)
	crd.SetAnnotations(annotations)
	return crd
}

func argoController(name string, labels, annotations map[string]string, containers ...corev1.Container) *appsv1.Deployment {
	if len(containers) == 0 {
		containers = []corev1.Container{{Name: "controller-manager", Image: argoEventsImage}}
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "argo-events", Name: name, Labels: labels, Annotations: annotations},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: containers,
		}}},
	}
}

// eventBusCRDs reads CRDs through the REST mapper the way a live cluster does.
// The Argo Events plural is "eventbus", not the guessed "eventbuses", so a wrong
// name would miss the CRD.
func eventBusCRDs(dyn *dynamicfake.FakeDynamicClient) crdFetcher {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.AddSpecific(schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "EventBus"},
		schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "eventbus"},
		schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "eventbus"},
		meta.RESTScopeNamespace)
	return mappedCRDFetcher(func() (meta.RESTMapper, error) { return mapper, nil }, dyn)
}

// argoTags is the registry with argo-events v1.9.11 as its newest release.
func argoTags() tagLister {
	tags := tagLister{"quay.io/argoproj/argo-events": {"v1.9.10", "v1.9.11"}}
	for repo, t := range newestTags {
		tags[repo] = t
	}
	return tags
}

func argoRefs() []string { return append(append([]string{}, natsImages...), argoEventsImage) }

func TestOperatorNamedFromTheInstallOfItsCRDIsProvenCurrent(t *testing.T) {
	typed := kubefake.NewSimpleClientset(eventBusStatefulSet(),
		argoController("controller-manager", argoEventsKustomization(), nil))
	dyn := remediationDyn(eventBusCRD(argoEventsKustomization(), nil))

	ups := remediateWith(t, typed, dyn, fixedFetcher(eventBusFromFlux()), eventBusCRDs(dyn), argoTags(),
		model.Upgrade{}, argoRefs()...)

	op := ups[argoEventsImage]
	if op == nil || !op.Resolved || op.Available {
		t.Fatalf("argo-events: want a resolved lookup with nothing newer, got %+v", op)
	}
	for _, ref := range natsImages {
		u := ups[ref]
		if u == nil {
			t.Fatalf("%s: no remediation answer", ref)
		}
		if !u.Resolved || u.Available || u.Latest != "" || !u.OperatorChosen {
			t.Errorf("%s: want proven to have no upgrade, got %+v", ref, u)
		}
		if u.Manager != "argo-events" || u.Source != "EventBus/argo-events/cpo" {
			t.Errorf("%s: operator should be named from its image, got manager=%q source=%q", ref, u.Manager, u.Source)
		}
		if want := "version chosen by the operator argo-events; the operator is on its latest version"; u.Reason != want {
			t.Errorf("%s: reason = %q, want %q", ref, u.Reason, want)
		}
	}

	// And the ticket raised for these images, untouched, is closed as not done.
	findings := make([]sink.FindingView, 0, len(natsImages))
	for _, ref := range natsImages {
		findings = append(findings, sink.ToFindingView(model.Finding{
			Image:              model.ParseImageRef(ref),
			Vulns:              []model.Vulnerability{{ID: "CVE-2023-45288", Severity: "high", KEV: true, FixAvailable: true, FixedVersion: "0.23.0"}},
			Occurrences:        []model.Occurrence{{Assessed: true}},
			Reconciled:         true,
			Live:               true,
			Actionable:         true,
			Priority:           "high",
			Upgrade:            ups[ref],
			RemediationChecked: true,
		}))
	}
	planner, err := ticket.NewPlanner(config.JiraConfig{
		DefaultTemplate: filepath.Join("..", "..", "..", "config", "templates", "container-vuln.md.tmpl"),
		Routes:          []config.TicketRoute{{Name: "all", When: "true", Board: 1, Project: "DVOP", ImageField: "customfield_1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(findings)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drafts) != 0 {
		t.Fatalf("nothing can be changed, so nothing is raised; got %q", plan.Drafts[0].Summary)
	}
	open := map[string][]ticket.Existing{}
	for _, f := range findings {
		open[f.Repository] = []ticket.Existing{{Key: "DVOP-4556", Category: "new"}}
	}
	got := ticket.Reconcile(ticket.ReconcileInput{
		Config:   config.JiraConfig{Project: "DVOP", AutoClose: true, CloseTransitionNoLongerActionable: "WON'T BE DONE"},
		Findings: findings, Skipped: plan.Skips, OpenByImage: open,
	})
	if len(got) != 1 || got[0].Kind != ticket.ActionClose || got[0].Reason != ticket.ReasonOperatorChosen {
		t.Fatalf("want DVOP-4556 closed as %s, got %+v", ticket.ReasonOperatorChosen, got)
	}
	if !got[0].Unworked || !got[0].NoLongerActionable {
		t.Errorf("a close must use the not-done transition: %+v", got[0])
	}
}

// An operator named from its CRD's install is only proven current by a registry
// that answered. A failed lookup is not "no newer release".
func TestOperatorNamedFromItsCRDInstallWithAnUnresolvedLookupStaysUnknown(t *testing.T) {
	typed := kubefake.NewSimpleClientset(eventBusStatefulSet(),
		argoController("controller-manager", argoEventsKustomization(), nil))
	dyn := remediationDyn(eventBusCRD(argoEventsKustomization(), nil))

	u := remediateWith(t, typed, dyn, fixedFetcher(eventBusFromFlux()), eventBusCRDs(dyn), failingLister{},
		model.Upgrade{}, argoRefs()...)["nats:2.10.29"]
	if u == nil || u.Resolved || u.Available || u.Manager != "argo-events" {
		t.Fatalf("want a named operator whose upgrade is unresolved, got %+v", u)
	}
	if want := "version chosen by the operator argo-events; the operator's own upgrade could not be resolved"; u.Reason != want {
		t.Errorf("reason = %q, want %q", u.Reason, want)
	}
}

type failingLister struct{}

func (failingLister) Tags(context.Context, string) ([]string, error) {
	return nil, apierrors.NewServiceUnavailable("registry down")
}

// The cases that must stay unknown: nothing singles out one operator, or the CRD
// cannot be read. Each leaves the NATS images where production has them today.
func TestOperatorNotSingledOutByItsCRDInstallStaysUnknown(t *testing.T) {
	helmAnnotations := map[string]string{
		"meta.helm.sh/release-name":      "argo-events",
		"meta.helm.sh/release-namespace": "argo-events",
	}
	for _, tc := range []struct {
		name      string
		crd       *unstructured.Unstructured
		workloads []runtime.Object
		forbidden bool
	}{
		{
			name: "two workloads from the same install",
			crd:  eventBusCRD(argoEventsKustomization(), nil),
			workloads: []runtime.Object{
				argoController("controller-manager", argoEventsKustomization(), nil),
				argoController("events-webhook", argoEventsKustomization(), nil),
			},
		},
		{
			name:      "CRD records no install",
			crd:       eventBusCRD(nil, nil),
			workloads: []runtime.Object{argoController("controller-manager", argoEventsKustomization(), nil)},
		},
		{
			name:      "CRD read forbidden",
			crd:       eventBusCRD(argoEventsKustomization(), nil),
			workloads: []runtime.Object{argoController("controller-manager", argoEventsKustomization(), nil)},
			forbidden: true,
		},
		{
			name: "operator runs two containers of its own",
			crd:  eventBusCRD(nil, helmAnnotations),
			workloads: []runtime.Object{argoController("controller-manager", nil, helmAnnotations,
				corev1.Container{Name: "controller-manager", Image: argoEventsImage},
				corev1.Container{Name: "metrics", Image: "natsio/prometheus-nats-exporter:0.14.0"})},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			typed := kubefake.NewSimpleClientset(append([]runtime.Object{eventBusStatefulSet()}, tc.workloads...)...)
			dyn := remediationDyn(tc.crd)
			if tc.forbidden {
				dyn.PrependReactor("get", "customresourcedefinitions", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions"}, "eventbus.argoproj.io", nil)
				})
			}
			u := remediateWith(t, typed, dyn, fixedFetcher(eventBusFromFlux()), eventBusCRDs(dyn), argoTags(),
				model.Upgrade{}, argoRefs()...)["nats:2.10.29"]
			if u == nil || u.Resolved || u.Available || u.Manager != "" || !u.OperatorChosen {
				t.Fatalf("want an unnamed operator and an unresolved answer, got %+v", u)
			}
			if !strings.Contains(u.Reason, "which operator that is could not be determined") {
				t.Errorf("reason = %q", u.Reason)
			}
		})
	}
}

// Helm-installed operators: the CRD and the controller carry Helm's release
// annotations, and a sidecar beside the controller does not make it ambiguous.
func TestOperatorNamedFromAHelmReleaseOfItsCRD(t *testing.T) {
	helmAnnotations := map[string]string{
		"meta.helm.sh/release-name":      "argo-events",
		"meta.helm.sh/release-namespace": "argo-events",
	}
	typed := kubefake.NewSimpleClientset(eventBusStatefulSet(),
		argoController("controller-manager", map[string]string{"app.kubernetes.io/managed-by": "Helm"}, helmAnnotations,
			corev1.Container{Name: "controller-manager", Image: argoEventsImage},
			corev1.Container{Name: "istio-proxy", Image: "docker.io/istio/proxyv2:1.24.0"}))
	dyn := remediationDyn(eventBusCRD(nil, helmAnnotations))

	u := remediateWith(t, typed, dyn, fixedFetcher(eventBusFromFlux()), eventBusCRDs(dyn), argoTags(),
		model.Upgrade{}, argoRefs()...)["nats:2.10.29"]
	if u == nil || !u.Resolved || u.Available || u.Manager != "argo-events" {
		t.Fatalf("want the Helm-installed operator named and proven current, got %+v", u)
	}
}

// A custom resource that names its operator is believed over the CRD's install,
// which is only consulted when the resource says nothing.
func TestOperatorNamedByItsCustomResourceOutranksItsCRDInstall(t *testing.T) {
	typed := kubefake.NewSimpleClientset(eventBusStatefulSet(),
		argoController("controller-manager", argoEventsKustomization(), nil))
	dyn := remediationDyn(eventBusCRD(argoEventsKustomization(), nil))
	var crdReads int
	crds := eventBusCRDs(dyn)
	counted := func(ctx context.Context, apiVersion, kind string) (*unstructured.Unstructured, error) {
		crdReads++
		return crds(ctx, apiVersion, kind)
	}
	cr := eventBus(map[string]interface{}{"app.kubernetes.io/part-of": "events-operator"})

	u := remediateWith(t, typed, dyn, fixedFetcher(cr), counted, argoTags(), model.Upgrade{}, argoRefs()...)["nats:2.10.29"]
	if u == nil || u.Manager != "events-operator" {
		t.Fatalf("want the operator the custom resource names, got %+v", u)
	}
	if crdReads != 0 {
		t.Errorf("the CRD was read %d times; a named operator needs no lookup", crdReads)
	}
}
