package kube

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// Whether a workload is reachable from the internet, measured rather than assumed.
//
// The scan provider reports a public_accessible field, and on this estate it is
// false for every row - so every finding read as "internal", which is an assertion
// and not an absence. That matters more than it sounds: an urgency tier defined as
// "high exploitation probability AND internet-facing" can never fire if nothing is
// ever internet-facing, so the rule looks configured and does nothing.
//
// The clusters already being read for liveness know the answer. A workload is
// reachable if something in front of it is: a LoadBalancer Service, an Ingress, or
// a Gateway API HTTPRoute.

var httpRouteGVR = schema.GroupVersionResource{
	Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes",
}

// azureInternalLB marks a LoadBalancer that only has a private address. An
// internal load balancer is not internet exposure, and counting it as such would
// put half a cluster in the urgent tier on the strength of a service type.
const azureInternalLB = "service.beta.kubernetes.io/azure-load-balancer-internal"

// ExposedImages reports, per running image, whether anything in front of it makes
// it reachable from outside the cluster.
//
// An image is present in the result only when a cluster was actually read for it.
// Absent means "not established", which the caller keeps distinct from "internal":
// an image nothing here saw running cannot be pronounced unreachable.
func (s *Source) ExposedImages(ctx context.Context) (map[string]bool, error) {
	configs, err := s.restConfigs()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for label, cfg := range configs {
		typed, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
		dyn, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
		if err := s.clusterExposure(ctx, label, typed, dyn, out); err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
	}
	return out, nil
}

// serviceKey identifies a Service within a cluster.
type serviceKey struct{ namespace, name string }

func (s *Source) clusterExposure(ctx context.Context, cluster string,
	typed kubernetes.Interface, dyn dynamic.Interface, out map[string]bool) error {

	services, err := typed.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list services: %w", err)
	}
	pods, err := typed.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}

	exposed := map[serviceKey]bool{}
	for i := range services.Items {
		svc := &services.Items[i]
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
			continue
		}
		if strings.EqualFold(svc.Annotations[azureInternalLB], "true") {
			continue
		}
		exposed[serviceKey{svc.Namespace, svc.Name}] = true
	}

	// Ingresses. A failure here is reported rather than skipped: a cluster whose
	// ingresses could not be read would report everything behind them as internal,
	// which is the false negative this whole thing exists to remove.
	ings, err := typed.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list ingresses: %w", err)
	}
	for i := range ings.Items {
		ing := &ings.Items[i]
		if s.internalIngressClass(ing) {
			continue
		}
		for _, svc := range ingressServices(ing) {
			exposed[serviceKey{ing.Namespace, svc}] = true
		}
	}

	// HTTPRoutes, when the CRD is installed. Absence is normal - plenty of clusters
	// run no Gateway API at all - so a "no matches for kind" is not an error, while
	// any other failure is.
	routes, err := dyn.Resource(httpRouteGVR).Namespace(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	switch {
	case err == nil:
		for i := range routes.Items {
			r := &routes.Items[i]
			if s.internalGateway(r) {
				continue
			}
			for _, svc := range routeServices(r) {
				exposed[serviceKey{r.GetNamespace(), svc}] = true
			}
		}
	case isMissingResource(err):
		slog.DebugContext(ctx, "no Gateway API in this cluster", "cluster", cluster)
	default:
		return fmt.Errorf("list httproutes: %w", err)
	}

	// Match pods to the services in front of them. Every running image gets an
	// answer, so "seen and not exposed" is recorded as false rather than left out.
	selectors := make(map[serviceKey]labels.Selector, len(exposed))
	for i := range services.Items {
		svc := &services.Items[i]
		key := serviceKey{svc.Namespace, svc.Name}
		if !exposed[key] || len(svc.Spec.Selector) == 0 {
			continue
		}
		selectors[key] = labels.SelectorFromSet(svc.Spec.Selector)
	}

	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase != corev1.PodRunning && p.Status.Phase != corev1.PodPending {
			continue
		}
		public := false
		for key, sel := range selectors {
			if key.namespace == p.Namespace && sel.Matches(labels.Set(p.Labels)) {
				public = true
				break
			}
		}
		for _, c := range append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
			ref := model.ParseImageRef(c.Image).NameTag()
			// Exposed anywhere wins. The same image behind an ingress in one
			// namespace and nothing in another is reachable, and the finding is
			// about the image.
			if public || !out[ref] {
				out[ref] = out[ref] || public
			}
		}
	}
	return nil
}

// internalIngressClass reports whether this ingress is served by a controller the
// operator has declared internal-only.
func (s *Source) internalIngressClass(ing *networkingv1.Ingress) bool {
	if len(s.InternalIngressClasses) == 0 {
		return false
	}
	class := ""
	if ing.Spec.IngressClassName != nil {
		class = *ing.Spec.IngressClassName
	}
	if class == "" {
		class = ing.Annotations["kubernetes.io/ingress.class"]
	}
	for _, c := range s.InternalIngressClasses {
		if strings.EqualFold(strings.TrimSpace(c), class) {
			return true
		}
	}
	return false
}

// internalGateway reports whether every parent of this route is a gateway the
// operator has declared internal-only.
func (s *Source) internalGateway(r *unstructured.Unstructured) bool {
	if len(s.InternalGateways) == 0 {
		return false
	}
	parents, found, err := unstructured.NestedSlice(r.Object, "spec", "parentRefs")
	if err != nil || !found || len(parents) == 0 {
		return false
	}
	for _, p := range parents {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		ns, _ := m["namespace"].(string)
		if ns == "" {
			ns = r.GetNamespace()
		}
		if !s.gatewayIsInternal(ns, name) {
			// One public parent is enough to make the route public.
			return false
		}
	}
	return true
}

func (s *Source) gatewayIsInternal(namespace, name string) bool {
	for _, g := range s.InternalGateways {
		g = strings.TrimSpace(g)
		if g == name || g == namespace+"/"+name {
			return true
		}
	}
	return false
}

// ingressServices names the backend services an ingress routes to.
func ingressServices(ing *networkingv1.Ingress) []string {
	var out []string
	if b := ing.Spec.DefaultBackend; b != nil && b.Service != nil {
		out = append(out, b.Service.Name)
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil {
				out = append(out, path.Backend.Service.Name)
			}
		}
	}
	return out
}

// routeServices names the backend services an HTTPRoute sends traffic to.
//
// Only Service backends. A route pointing at something else entirely is not
// evidence about any image here, and guessing at it would manufacture exposure.
func routeServices(r *unstructured.Unstructured) []string {
	rules, found, err := unstructured.NestedSlice(r.Object, "spec", "rules")
	if err != nil || !found {
		return nil
	}
	var out []string
	for _, rule := range rules {
		m, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		refs, ok := m["backendRefs"].([]any)
		if !ok {
			continue
		}
		for _, ref := range refs {
			rm, ok := ref.(map[string]any)
			if !ok {
				continue
			}
			if kind, _ := rm["kind"].(string); kind != "" && kind != "Service" {
				continue
			}
			if name, _ := rm["name"].(string); name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}

// isMissingResource reports an API that does not serve this kind at all, as
// distinct from one that refused to.
func isMissingResource(err error) bool {
	s := err.Error()
	return strings.Contains(s, "could not find the requested resource") ||
		strings.Contains(s, "no matches for kind") ||
		strings.Contains(s, "the server could not find the requested resource")
}
