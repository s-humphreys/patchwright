package kube

import (
	"context"
	"testing"

	"errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func pod(ns, name, image string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Image: image}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func svc(ns, name string, typ corev1.ServiceType, selector, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: annotations},
		Spec:       corev1.ServiceSpec{Type: typ, Selector: selector},
	}
}

func httpRouteHosts(ns, name, service string, hosts ...string) *unstructured.Unstructured {
	r := httpRoute(ns, name, service, "gw", "public-gateway")
	spec := r.Object["spec"].(map[string]any)
	hh := make([]any, 0, len(hosts))
	for _, h := range hosts {
		hh = append(hh, h)
	}
	spec["hostnames"] = hh
	return r
}

func httpRoute(ns, name, service, gatewayNS, gateway string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"parentRefs": []any{map[string]any{"name": gateway, "namespace": gatewayNS}},
			"rules": []any{map[string]any{
				"backendRefs": []any{map[string]any{"kind": "Service", "name": service}},
			}},
		},
	}}
}

func dynFor(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	s := runtime.NewScheme()
	gvr := map[schema.GroupVersionResource]string{httpRouteGVR: "HTTPRouteList"}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(s, gvr, objs...)
}

func exposureOf(t *testing.T, s *Source, typed *kubefake.Clientset, dyn *dynamicfake.FakeDynamicClient) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	if err := s.clusterExposure(context.Background(), "test", typed, dyn, out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestALoadBalancerServiceExposesItsPods(t *testing.T) {
	typed := kubefake.NewSimpleClientset(
		svc("web", "front", corev1.ServiceTypeLoadBalancer, map[string]string{"app": "web"}, nil),
		pod("web", "web-1", "acme.io/web:1", map[string]string{"app": "web"}),
		pod("web", "worker-1", "acme.io/worker:1", map[string]string{"app": "worker"}),
	)
	got := exposureOf(t, &Source{}, typed, dynFor())
	if !got["acme.io/web:1"] {
		t.Error("a pod behind a LoadBalancer is reachable from outside")
	}
	// Recorded as false rather than omitted: seen and not exposed is an answer.
	if exposed, ok := got["acme.io/worker:1"]; !ok || exposed {
		t.Errorf("worker = %v (present %v), want an explicit false", exposed, ok)
	}
}

func TestAnInternalLoadBalancerIsNotInternetExposure(t *testing.T) {
	// Counting an internal LB as public would put half a cluster in the urgent
	// tier on the strength of a service type.
	typed := kubefake.NewSimpleClientset(
		svc("web", "front", corev1.ServiceTypeLoadBalancer, map[string]string{"app": "web"},
			map[string]string{azureInternalLB: "true"}),
		pod("web", "web-1", "acme.io/web:1", map[string]string{"app": "web"}),
	)
	if exposureOf(t, &Source{}, typed, dynFor())["acme.io/web:1"] {
		t.Error("an internal load balancer is not internet exposure")
	}
}

func TestAnHTTPRouteExposesItsBackend(t *testing.T) {
	typed := kubefake.NewSimpleClientset(
		svc("web", "api", corev1.ServiceTypeClusterIP, map[string]string{"app": "api"}, nil),
		pod("web", "api-1", "acme.io/api:1", map[string]string{"app": "api"}),
	)
	dyn := dynFor(httpRoute("web", "api", "api", "gw", "public-gateway"))
	if !exposureOf(t, &Source{}, typed, dyn)["acme.io/api:1"] {
		t.Error("a service behind an HTTPRoute is reachable from outside")
	}
}

func TestAnHTTPRouteOnlyOnAnInternalGatewayIsNotExposure(t *testing.T) {
	typed := kubefake.NewSimpleClientset(
		svc("web", "api", corev1.ServiceTypeClusterIP, map[string]string{"app": "api"}, nil),
		pod("web", "api-1", "acme.io/api:1", map[string]string{"app": "api"}),
	)
	dyn := dynFor(httpRoute("web", "api", "api", "gw", "private-gateway"))
	s := &Source{InternalGateways: []string{"gw/private-gateway"}}
	if exposureOf(t, s, typed, dyn)["acme.io/api:1"] {
		t.Error("a route whose only parent is internal is not exposure")
	}
}

func TestOnePublicParentMakesARoutePublic(t *testing.T) {
	// A route attached to both a private and a public gateway is reachable.
	// Requiring every parent to be public would hide it.
	r := httpRoute("web", "api", "api", "gw", "private-gateway")
	spec := r.Object["spec"].(map[string]any)
	spec["parentRefs"] = []any{
		map[string]any{"name": "private-gateway", "namespace": "gw"},
		map[string]any{"name": "public-gateway", "namespace": "gw"},
	}
	typed := kubefake.NewSimpleClientset(
		svc("web", "api", corev1.ServiceTypeClusterIP, map[string]string{"app": "api"}, nil),
		pod("web", "api-1", "acme.io/api:1", map[string]string{"app": "api"}),
	)
	s := &Source{InternalGateways: []string{"gw/private-gateway"}}
	if !exposureOf(t, s, typed, dynFor(r))["acme.io/api:1"] {
		t.Error("one public parent should make the route public")
	}
}

func TestExposedAnywhereWins(t *testing.T) {
	// The same image behind an ingress in one namespace and nothing in another is
	// reachable. The finding is about the image.
	typed := kubefake.NewSimpleClientset(
		svc("public", "api", corev1.ServiceTypeLoadBalancer, map[string]string{"app": "api"}, nil),
		pod("public", "api-1", "acme.io/api:1", map[string]string{"app": "api"}),
		pod("private", "api-2", "acme.io/api:1", map[string]string{"app": "api"}),
	)
	if !exposureOf(t, &Source{}, typed, dynFor())["acme.io/api:1"] {
		t.Error("exposed in one namespace means the image is exposed")
	}
}

func TestAServiceWithNoSelectorExposesNothing(t *testing.T) {
	// An ExternalName or manually-endpointed service selects no pods, and matching
	// every pod in the namespace would mark the whole namespace public.
	typed := kubefake.NewSimpleClientset(
		svc("web", "external", corev1.ServiceTypeLoadBalancer, nil, nil),
		pod("web", "api-1", "acme.io/api:1", map[string]string{"app": "api"}),
	)
	if exposureOf(t, &Source{}, typed, dynFor())["acme.io/api:1"] {
		t.Error("a selectorless service must not expose the namespace")
	}
}

func TestAMissingGatewayAPIIsToldApartFromARefusal(t *testing.T) {
	// A cluster with no Gateway API installed is normal and must not fail the
	// assessment; a cluster that refused the request must. The fake dynamic client
	// panics on an unregistered resource rather than returning what a real API
	// server returns, so this checks the classifier against the real strings.
	missing := []string{
		`the server could not find the requested resource`,
		`no matches for kind "HTTPRoute" in version "gateway.networking.k8s.io/v1"`,
	}
	for _, m := range missing {
		if !isMissingResource(errors.New(m)) {
			t.Errorf("should be treated as absent: %q", m)
		}
	}
	refusals := []string{
		`httproutes.gateway.networking.k8s.io is forbidden: User cannot list resource`,
		`Get "https://cluster/apis": dial tcp: i/o timeout`,
	}
	for _, r := range refusals {
		if isMissingResource(errors.New(r)) {
			t.Errorf("a refusal must not be swallowed as absence: %q", r)
		}
	}
}

func TestHostnamesDecideExposureWhenTheOperatorNamesThem(t *testing.T) {
	// The case this exists for. A gateway is not necessarily internet-facing: a
	// proxy can sit in front of it that Kubernetes knows nothing about. On this
	// estate a service answers on BOTH "<svc>.pro.example.com", which is internal,
	// and "api-<svc>.example.com", which is not, so the hostname is the only thing
	// in the cluster that separates them.
	typed := kubefake.NewSimpleClientset(
		svc("web", "api", corev1.ServiceTypeClusterIP, map[string]string{"app": "api"}, nil),
		pod("web", "api-1", "acme.io/api:1", map[string]string{"app": "api"}),
		svc("web", "internal", corev1.ServiceTypeClusterIP, map[string]string{"app": "internal"}, nil),
		pod("web", "internal-1", "acme.io/internal:1", map[string]string{"app": "internal"}),
	)
	dyn := dynFor(
		httpRouteHosts("web", "public", "api", "api-thing.example.com", "thing.pro.example.com"),
		httpRouteHosts("web", "private", "internal", "other.pro.example.com"),
	)
	s := &Source{
		PublicHostnames:   []string{"example.com"},
		InternalHostnames: []string{"pro.example.com"},
	}
	got := exposureOf(t, s, typed, dyn)
	if !got["acme.io/api:1"] {
		t.Error("a route answering on a public hostname is internet-facing")
	}
	if got["acme.io/internal:1"] {
		t.Error("a route only on an internal subdomain is not")
	}
}

func TestTheMostSpecificHostnameSuffixWins(t *testing.T) {
	// Without this a single public domain drags every internal subdomain in with
	// it, which on a real estate is most of the routes.
	public := []string{"example.com"}
	internal := []string{"pro.example.com"}
	cases := map[string]bool{
		"api-thing.example.com":      true,
		"thing.pro.example.com":      false,
		"deep.thing.pro.example.com": false,
		"example.com":                true,
		"thing.elsewhere.com":        false,
	}
	for host, want := range cases {
		if got := hostnameIsPublic(host, public, internal); got != want {
			t.Errorf("hostnameIsPublic(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestAContradictoryHostnameRuleDoesNotEscalate(t *testing.T) {
	// Naming the same suffix public and internal is a mistake. The safe reading of
	// a contradiction about exposure is the one that does not put somebody in the
	// urgent tier.
	if hostnameIsPublic("a.example.com", []string{"example.com"}, []string{"example.com"}) {
		t.Error("a suffix in both lists should not resolve to public")
	}
}

func TestWithoutHostnamesConfiguredTheGatewayStillDecides(t *testing.T) {
	// Coarse and over-reporting, but it is what an estate that has not stated its
	// domains gets, and over-reporting is the safe direction.
	typed := kubefake.NewSimpleClientset(
		svc("web", "api", corev1.ServiceTypeClusterIP, map[string]string{"app": "api"}, nil),
		pod("web", "api-1", "acme.io/api:1", map[string]string{"app": "api"}),
	)
	dyn := dynFor(httpRouteHosts("web", "api", "api", "anything.internal.local"))
	if !exposureOf(t, &Source{}, typed, dyn)["acme.io/api:1"] {
		t.Error("with no public hostnames declared, a routed service counts as exposed")
	}
}

func TestARouteWithNoHostnameIsNotEvidence(t *testing.T) {
	typed := kubefake.NewSimpleClientset(
		svc("web", "api", corev1.ServiceTypeClusterIP, map[string]string{"app": "api"}, nil),
		pod("web", "api-1", "acme.io/api:1", map[string]string{"app": "api"}),
	)
	s := &Source{PublicHostnames: []string{"example.com"}}
	if exposureOf(t, s, typed, dynFor(httpRoute("web", "api", "api", "gw", "gw")))["acme.io/api:1"] {
		t.Error("a route with no hostname is not evidence of a public address")
	}
}
