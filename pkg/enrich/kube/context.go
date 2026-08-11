package kube

import (
	"context"
	"fmt"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

var (
	kustomizationGVR  = schema.GroupVersionResource{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}
	gitRepositoryGVR  = schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}
	ociRepositoryGVR  = schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1beta2", Resource: "ocirepositories"}
	helmToolkitLabels = []string{"helm.toolkit.fluxcd.io/name", "helm.sh/chart"}
)

// crFetcher fetches a custom resource by its owner reference. It is an interface
// so the operator CR-spec detection can be tested without a live cluster.
type crFetcher func(ctx context.Context, apiVersion, kind, namespace, name string) (*unstructured.Unstructured, error)

// ImageDeployments reports the deployment context per image NameTag: how the
// image is deployed, whether an image-tag bump is directly actionable, and
// where the change would land. Directly-deployed (manifest/Kustomize) and
// operator-set-in-spec images are actionable; chart-managed and operator-derived
// images are not.
func (s *Source) ImageDeployments(ctx context.Context) (map[string]enrich.DeployContext, error) {
	configs, err := s.restConfigs()
	if err != nil {
		return nil, err
	}
	out := map[string]enrich.DeployContext{}
	for label, cfg := range configs {
		typed, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
		dyn, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
		fetch := newDynamicCRFetcher(cfg, dyn)
		if err := clusterImageDeployments(ctx, typed, dyn, fetch, out); err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
	}
	return out, nil
}

// newDynamicCRFetcher builds a crFetcher that resolves an ownerReference's Kind
// to a resource via the discovery REST mapper (built lazily, once) and reads it
// dynamically. If the mapper can't be built or the CR can't be read, callers
// treat the operator image as non-actionable.
func newDynamicCRFetcher(cfg *rest.Config, dyn dynamic.Interface) crFetcher {
	var (
		once   sync.Once
		mapper meta.RESTMapper
		mapErr error
	)
	initMapper := func() {
		dc, err := discovery.NewDiscoveryClientForConfig(cfg)
		if err != nil {
			mapErr = err
			return
		}
		gr, err := restmapper.GetAPIGroupResources(dc)
		if err != nil {
			mapErr = err
			return
		}
		mapper = restmapper.NewDiscoveryRESTMapper(gr)
	}
	return func(ctx context.Context, apiVersion, kind, namespace, name string) (*unstructured.Unstructured, error) {
		once.Do(initMapper)
		if mapErr != nil {
			return nil, mapErr
		}
		gv, err := schema.ParseGroupVersion(apiVersion)
		if err != nil {
			return nil, err
		}
		mapping, err := mapper.RESTMapping(schema.GroupKind{Group: gv.Group, Kind: kind}, gv.Version)
		if err != nil {
			return nil, err
		}
		return dyn.Resource(mapping.Resource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	}
}

func clusterImageDeployments(ctx context.Context, typed kubernetes.Interface, dyn dynamic.Interface, fetch crFetcher, out map[string]enrich.DeployContext) error {
	kustSources := kustomizationSources(ctx, dyn)
	crCache := map[string]*unstructured.Unstructured{}

	handle := func(meta metav1.ObjectMeta, spec corev1.PodSpec) {
		dc, ok := workloadContext(ctx, meta, kustSources, fetch, crCache)
		if !ok {
			return
		}
		for _, c := range podContainers(spec) {
			key := model.ParseImageRef(c.Image).NameTag()
			dcImg := dc
			// For operator workloads, actionability depends on the specific
			// image appearing in the CR spec.
			if dc.Mechanism == "operator" {
				dcImg = operatorContextForImage(dc, c.Image, crCache, meta)
			}
			if existing, seen := out[key]; !seen || preferContext(dcImg, existing) {
				out[key] = dcImg
			}
		}
	}

	deploys, err := typed.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list deployments: %w", err)
	}
	for i := range deploys.Items {
		handle(deploys.Items[i].ObjectMeta, deploys.Items[i].Spec.Template.Spec)
	}
	sts, err := typed.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list statefulsets: %w", err)
	}
	for i := range sts.Items {
		handle(sts.Items[i].ObjectMeta, sts.Items[i].Spec.Template.Spec)
	}
	ds, err := typed.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list daemonsets: %w", err)
	}
	for i := range ds.Items {
		handle(ds.Items[i].ObjectMeta, ds.Items[i].Spec.Template.Spec)
	}
	return nil
}

// workloadContext classifies a workload's deployment mechanism and, for
// non-operator cases, its actionability/source. The operator case is refined
// per-image by operatorContextForImage.
func workloadContext(ctx context.Context, meta metav1.ObjectMeta, kustSources map[string]kustSource, fetch crFetcher, crCache map[string]*unstructured.Unstructured) (enrich.DeployContext, bool) {
	for _, l := range helmToolkitLabels {
		if meta.Labels[l] != "" {
			return enrich.DeployContext{Mechanism: "helm", Actionable: false}, true
		}
	}
	if name := meta.Labels["kustomize.toolkit.fluxcd.io/name"]; name != "" {
		ns := meta.Labels["kustomize.toolkit.fluxcd.io/namespace"]
		if ns == "" {
			ns = meta.Namespace
		}
		src := kustSources[ns+"/"+name]
		return enrich.DeployContext{
			Mechanism: "kustomize", Actionable: true,
			Source: src.URL, SourcePath: src.Path,
		}, true
	}
	for _, ref := range meta.OwnerReferences {
		if !ownerGroupIsCustom(ref.APIVersion) {
			continue
		}
		// Cache the CR for per-image spec inspection.
		key := crCacheKey(ref.APIVersion, ref.Kind, meta.Namespace, ref.Name)
		if _, ok := crCache[key]; !ok {
			cr, err := fetch(ctx, ref.APIVersion, ref.Kind, meta.Namespace, ref.Name)
			if err == nil {
				crCache[key] = cr
			} else {
				crCache[key] = nil
			}
		}
		return enrich.DeployContext{
			Mechanism: "operator", Actionable: false,
			Source:  crRef(ref.Kind, meta.Namespace, ref.Name),
			Manager: managerFromCR(crCache[key], meta.Labels),
		}, true
	}
	// Label-based controller ownership: some operators (e.g. flux-operator)
	// manage workloads via app.kubernetes.io/managed-by with no ownerReferences.
	// A direct image bump would be reverted, so treat these as controller-owned.
	if by := meta.Labels["app.kubernetes.io/managed-by"]; by != "" {
		switch strings.ToLower(by) {
		case "helm":
			return enrich.DeployContext{Mechanism: "helm", Actionable: false}, true
		case "kubectl", "kustomize":
			// applied directly — treat as manifest below.
		default:
			// The label names WHAT owns the version, not where to change it, so it
			// is a Manager rather than a Source.
			return enrich.DeployContext{Mechanism: "operator", Actionable: false, Manager: by}, true
		}
	}
	return enrich.DeployContext{Mechanism: "manifest", Actionable: true}, true
}

// managerFromCR names the operator that owns a custom resource, from the CR's own
// standard Kubernetes labels.
//
// A CR does not say "my controller is X", but the operator that ships it labels
// it: a Kiali CR created by the kiali-operator chart carries
// app.kubernetes.io/part-of=kiali-operator. Reading that is the difference
// between pointing a ticket at the component to upgrade and guessing a name from
// the CR's Kind, which would be a fabrication.
//
// workloadLabels are the managed workload's own labels, used only to reject a
// name identical to the workload itself: "kiali is managed by kiali" is no use.
func managerFromCR(cr *unstructured.Unstructured, workloadLabels map[string]string) string {
	if cr == nil {
		return ""
	}
	labels := cr.GetLabels()
	self := workloadLabels["app.kubernetes.io/name"]
	// part-of before name: for an operator's own resources it names the operator,
	// where name may be the instance.
	for _, key := range []string{"app.kubernetes.io/part-of", "app.kubernetes.io/name"} {
		if v := labels[key]; v != "" && v != self {
			return v
		}
	}
	return ""
}

// operatorContextForImage refines an operator workload's context for a specific
// image: if the image is set in the owning CR's spec, the bump is actionable
// (change the CR); otherwise it's derived and not actionable.
func operatorContextForImage(base enrich.DeployContext, image string, crCache map[string]*unstructured.Unstructured, meta metav1.ObjectMeta) enrich.DeployContext {
	for _, ref := range meta.OwnerReferences {
		if !ownerGroupIsCustom(ref.APIVersion) {
			continue
		}
		cr := crCache[crCacheKey(ref.APIVersion, ref.Kind, meta.Namespace, ref.Name)]
		if cr != nil && imageInSpec(cr, image) {
			base.Actionable = true
		}
		return base
	}
	return base
}

// preferContext decides whether candidate should replace existing when the same
// image runs in multiple workloads: prefer an actionable context, then one that
// names a source.
func preferContext(candidate, existing enrich.DeployContext) bool {
	if candidate.Actionable != existing.Actionable {
		return candidate.Actionable
	}
	return existing.Source == "" && candidate.Source != ""
}

// kustSource is a Flux Kustomization's change target: the repository and the
// directory within it, kept apart so a consumer can render a working link.
type kustSource struct {
	URL  string
	Path string
}

// kustomizationSources maps "<ns>/<name>" of each Flux Kustomization to its
// source repository (GitRepository or OCIRepository) and path. Best-effort:
// clusters without Flux Kustomize contribute nothing.
func kustomizationSources(ctx context.Context, dyn dynamic.Interface) map[string]kustSource {
	git := listSourceURLs(ctx, dyn, gitRepositoryGVR)
	oci := listSourceURLs(ctx, dyn, ociRepositoryGVR)

	list, err := dyn.Resource(kustomizationGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return map[string]kustSource{}
	}
	out := map[string]kustSource{}
	for i := range list.Items {
		k := &list.Items[i]
		ns, name := k.GetNamespace(), k.GetName()
		srcName, _, _ := unstructured.NestedString(k.Object, "spec", "sourceRef", "name")
		srcNS, _, _ := unstructured.NestedString(k.Object, "spec", "sourceRef", "namespace")
		srcKind, _, _ := unstructured.NestedString(k.Object, "spec", "sourceRef", "kind")
		if srcNS == "" {
			srcNS = ns
		}
		srcKey := srcNS + "/" + srcName
		url := git[srcKey]
		if srcKind == "OCIRepository" {
			url = oci[srcKey]
		}
		if url == "" {
			continue
		}
		// Record the Kustomization's path within the repo, so remediation points
		// at the right directory rather than just the repo root. Deliberately NOT
		// joined into the URL with kustomize's "//" notation: the result looks
		// like a link and is not one.
		src := kustSource{URL: strings.TrimRight(url, "/")}
		if path, _, _ := unstructured.NestedString(k.Object, "spec", "path"); path != "" {
			src.Path = strings.TrimPrefix(strings.TrimPrefix(path, "./"), "/")
		}
		out[ns+"/"+name] = src
	}
	return out
}

func listSourceURLs(ctx context.Context, dyn dynamic.Interface, gvr schema.GroupVersionResource) map[string]string {
	list, err := dyn.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(list.Items))
	for i := range list.Items {
		u := &list.Items[i]
		url, _, _ := unstructured.NestedString(u.Object, "spec", "url")
		out[u.GetNamespace()+"/"+u.GetName()] = url
	}
	return out
}

// imageInSpec reports whether image appears anywhere in the custom resource's
// spec (a string leaf equal to the image ref), i.e. the tag is user-set.
func imageInSpec(cr *unstructured.Unstructured, image string) bool {
	spec, ok, _ := unstructured.NestedMap(cr.Object, "spec")
	if !ok {
		return false
	}
	return containsStringValue(spec, image)
}

func containsStringValue(v interface{}, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case map[string]interface{}:
		for _, e := range t {
			if containsStringValue(e, want) {
				return true
			}
		}
	case []interface{}:
		for _, e := range t {
			if containsStringValue(e, want) {
				return true
			}
		}
	}
	return false
}

func crRef(kind, namespace, name string) string {
	return kind + "/" + namespace + "/" + name
}

func crCacheKey(apiVersion, kind, namespace, name string) string {
	return apiVersion + "/" + kind + "/" + namespace + "/" + name
}

// ownerGroupIsCustom reports whether an ownerReference apiVersion belongs to a
// custom resource group (a dotted group like "tailscale.com") rather than a
// built-in Kubernetes group (core, apps, batch).
func ownerGroupIsCustom(apiVersion string) bool {
	group := apiVersion
	if i := strings.Index(apiVersion, "/"); i != -1 {
		group = apiVersion[:i]
	} else {
		group = "" // core group ("v1")
	}
	switch group {
	case "", "apps", "batch":
		return false
	default:
		return strings.Contains(group, ".")
	}
}
