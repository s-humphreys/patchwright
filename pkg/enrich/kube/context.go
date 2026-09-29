package kube

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
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
	crdGVR            = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
)

// crFetcher fetches a custom resource by its owner reference. It is an interface
// so the operator CR-spec detection can be tested without a live cluster.
type crFetcher func(ctx context.Context, apiVersion, kind, namespace, name string) (*unstructured.Unstructured, error)

// crdFetcher fetches the CustomResourceDefinition of a custom resource's group and
// kind, so the install that created it can name its operator.
type crdFetcher func(ctx context.Context, apiVersion, kind string) (*unstructured.Unstructured, error)

// ImageDeployments reports the deployment context per image NameTag: how the
// image is deployed, whether an image-tag bump is directly actionable, and
// where the change would land. Directly-deployed (manifest/Kustomize) and
// operator-set-in-spec images are actionable; chart-managed and operator-derived
// images are not.
//
// A cluster that cannot be read is left out, so its images carry no deployment
// context this run.
func (s *Source) ImageDeployments(ctx context.Context) (map[string]enrich.DeployContext, error) {
	clusters, err := s.clusters()
	if err != nil {
		return nil, err
	}
	out := map[string]enrich.DeployContext{}
	_, err = s.readClusters(ctx, model.StageDeployContext, clusters, func(c cluster) error {
		// Into a copy, kept only when the whole cluster reads. Not a map of its own:
		// a cluster's read refines what earlier clusters recorded for the same image.
		next := maps.Clone(out)
		fetch, crds := newDynamicFetchers(c.cfg, c.dyn)
		if err := clusterImageDeployments(ctx, c.typed, c.dyn, fetch, crds, next); err != nil {
			return err
		}
		out = next
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// newDynamicFetchers builds a crFetcher that resolves an ownerReference's Kind
// to a resource via the discovery REST mapper (built lazily, once, and shared)
// and reads it dynamically, and a crdFetcher that reads the same Kind's
// definition. If the mapper can't be built or the CR can't be read, callers
// treat the operator image as non-actionable.
func newDynamicFetchers(cfg *rest.Config, dyn dynamic.Interface) (crFetcher, crdFetcher) {
	var (
		once   sync.Once
		mapper meta.RESTMapper
		mapErr error
	)
	newMapper := func() (meta.RESTMapper, error) {
		once.Do(func() {
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
		})
		return mapper, mapErr
	}
	return mappedCRFetcher(newMapper, dyn), mappedCRDFetcher(newMapper, dyn)
}

// restMapping resolves a custom resource's apiVersion and Kind to its resource.
func restMapping(newMapper func() (meta.RESTMapper, error), apiVersion, kind string) (*meta.RESTMapping, error) {
	mapper, err := newMapper()
	if err != nil {
		return nil, err
	}
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil, err
	}
	return mapper.RESTMapping(schema.GroupKind{Group: gv.Group, Kind: kind}, gv.Version)
}

// mappedCRFetcher is the crFetcher of newDynamicFetchers with the mapper
// supplied, so scope handling can be tested without a discovery endpoint.
func mappedCRFetcher(newMapper func() (meta.RESTMapper, error), dyn dynamic.Interface) crFetcher {
	return func(ctx context.Context, apiVersion, kind, namespace, name string) (*unstructured.Unstructured, error) {
		mapping, err := restMapping(newMapper, apiVersion, kind)
		if err != nil {
			return nil, err
		}
		// A namespaced workload can be owned by a cluster-scoped object (every
		// Crossplane FunctionRevision and ProviderRevision is one). Asking for it
		// under the workload's namespace is a 404, which used to read as "image not
		// in the spec" and turned every Crossplane package into a derived image.
		if mapping.Scope.Name() == meta.RESTScopeNameRoot {
			return dyn.Resource(mapping.Resource).Get(ctx, name, metav1.GetOptions{})
		}
		return dyn.Resource(mapping.Resource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	}
}

// mappedCRDFetcher is the crdFetcher of newDynamicFetchers with the mapper
// supplied. A CRD is named "<plural>.<group>", and only the mapper knows the plural.
func mappedCRDFetcher(newMapper func() (meta.RESTMapper, error), dyn dynamic.Interface) crdFetcher {
	return func(ctx context.Context, apiVersion, kind string) (*unstructured.Unstructured, error) {
		mapping, err := restMapping(newMapper, apiVersion, kind)
		if err != nil {
			return nil, err
		}
		name := mapping.Resource.Resource + "." + mapping.Resource.Group
		return dyn.Resource(crdGVR).Get(ctx, name, metav1.GetOptions{})
	}
}

func clusterImageDeployments(ctx context.Context, typed kubernetes.Interface, dyn dynamic.Interface, fetch crFetcher, crds crdFetcher, out map[string]enrich.DeployContext) error {
	kustSources := kustomizationSources(ctx, dyn)
	crCache := map[string]*unstructured.Unstructured{}
	// Every image running in this cluster by the last segment of its repository,
	// which is how an operator's name is matched to its own image.
	byName := map[string]string{}
	touched := map[string]bool{}
	// The custom resource owning each operator-chosen image, and the workloads each
	// install created, for naming an operator from the install of its CRD.
	owners := map[string]metav1.OwnerReference{}
	installs := map[string][]installedWorkload{}

	handle := func(meta metav1.ObjectMeta, spec corev1.PodSpec) {
		dc, ok := workloadContext(ctx, meta, kustSources, fetch, crCache)
		if !ok {
			return
		}
		recordInstall(installs, meta, spec)
		for _, c := range podContainers(spec) {
			img := model.ParseImageRef(c.Image)
			key := img.NameTag()
			name := img.Repository[strings.LastIndex(img.Repository, "/")+1:]
			if existing, seen := byName[name]; !seen || key < existing {
				byName[name] = key
			}
			touched[key] = true
			dcImg := dc
			// For operator workloads, actionability depends on the specific
			// image appearing in the CR spec.
			if dc.Mechanism == "operator" {
				dcImg = operatorContextForImage(dc, c.Image, crCache, meta)
			}
			if existing, seen := out[key]; !seen || preferContext(dcImg, existing) {
				out[key] = dcImg
				if ref, ok := customOwner(meta); ok && dcImg.Mechanism == "operator" {
					owners[key] = ref
				} else {
					delete(owners, key)
				}
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

	// A custom resource that does not name its operator is still defined by a CRD,
	// and whatever installed that CRD usually installed the operator beside it.
	// Only a readable owner qualifies: with the owner unread, whether it sets the
	// image is unknown, and naming an operator would let its upgrade speak for it.
	byInstall := map[string]installedWorkload{}
	for key := range touched {
		dc := out[key]
		if dc.Mechanism != "operator" || dc.Actionable || dc.Manager != "" || dc.OwnerUnread {
			continue
		}
		ref, ok := owners[key]
		if !ok {
			continue
		}
		gk := ref.APIVersion + "/" + ref.Kind
		op, ok := byInstall[gk]
		if !ok {
			op = operatorFromCRDInstall(ctx, crds, ref, installs)
			byInstall[gk] = op
		}
		if op.image == "" || op.image == key {
			continue
		}
		dc.Manager, dc.ManagerImage = op.manager, op.image
		out[key] = dc
	}

	// An operator-derived image changes only when its operator is upgraded, so
	// point it at the operator's own image for that upgrade to be found. Matched
	// by name the same way the ticket planner folds managed images into their
	// manager's ticket: a named operator whose image is not running here is left
	// unmatched rather than guessed at.
	for key := range touched {
		dc := out[key]
		if dc.Mechanism != "operator" || dc.Actionable || dc.Manager == "" || dc.ManagerImage != "" {
			continue
		}
		if img, ok := byName[dc.Manager]; ok && img != key {
			dc.ManagerImage = img
			out[key] = dc
		}
	}
	return nil
}

// installedWorkload is a workload an install created: its image, when that is
// one container once known sidecars are set aside, and the name to give it as
// an operator.
type installedWorkload struct {
	manager string
	image   string
}

// sidecarContainers are containers injected beside a workload's own process, which
// never name the operator the workload runs.
var sidecarContainers = map[string]bool{
	"istio-proxy":     true,
	"linkerd-proxy":   true,
	"kube-rbac-proxy": true,
}

// installIdentities names the installs an object records it came from, in order of
// precedence: a Flux Kustomization, a Flux HelmRelease, a Helm release. Each needs
// both its name and namespace, since a name alone matches unrelated installs.
func installIdentities(labels, annotations map[string]string) []string {
	var ids []string
	for _, p := range []struct {
		kind           string
		from           map[string]string
		nameKey, nsKey string
	}{
		{"kustomization", labels, "kustomize.toolkit.fluxcd.io/name", "kustomize.toolkit.fluxcd.io/namespace"},
		{"helmrelease", labels, "helm.toolkit.fluxcd.io/name", "helm.toolkit.fluxcd.io/namespace"},
		{"helm", annotations, "meta.helm.sh/release-name", "meta.helm.sh/release-namespace"},
	} {
		if name, ns := p.from[p.nameKey], p.from[p.nsKey]; name != "" && ns != "" {
			ids = append(ids, p.kind+":"+ns+"/"+name)
		}
	}
	return ids
}

// recordInstall files a workload under every install it records. A workload an
// operator created is left out: it carries whatever labels the operator copied
// from its custom resource, and it is never the operator itself.
func recordInstall(installs map[string][]installedWorkload, meta metav1.ObjectMeta, spec corev1.PodSpec) {
	if ref, ok := customOwner(meta); ok && ref.Controller != nil && *ref.Controller {
		return
	}
	var own []string
	for _, c := range spec.Containers {
		if !sidecarContainers[c.Name] {
			own = append(own, c.Image)
		}
	}
	// Named by its image's repository, the name the ticket planner folds managed
	// images under; the workload's own name is often generic ("controller-manager").
	w := installedWorkload{manager: meta.Name}
	if len(own) == 1 {
		img := model.ParseImageRef(own[0])
		w.image = img.NameTag()
		if name := img.Repository[strings.LastIndex(img.Repository, "/")+1:]; name != "" {
			w.manager = name
		}
	}
	for _, id := range installIdentities(meta.Labels, meta.Annotations) {
		installs[id] = append(installs[id], w)
	}
}

// operatorFromCRDInstall names the operator of a custom resource from the install
// that created its CRD: the one workload that install also created. None, several,
// or one whose image is ambiguous is no answer, because a guessed operator would
// let an unrelated component's version close a ticket. Nothing here fails the
// assessment; an unreadable CRD leaves the operator unknown, as before.
func operatorFromCRDInstall(ctx context.Context, crds crdFetcher, ref metav1.OwnerReference, installs map[string][]installedWorkload) installedWorkload {
	if crds == nil {
		return installedWorkload{}
	}
	crd, err := crds(ctx, ref.APIVersion, ref.Kind)
	if err != nil {
		slog.DebugContext(ctx, "could not read the custom resource definition; its operator stays unnamed",
			"apiVersion", ref.APIVersion, "kind", ref.Kind, "error", err)
		return installedWorkload{}
	}
	ids := installIdentities(crd.GetLabels(), crd.GetAnnotations())
	if len(ids) == 0 {
		slog.DebugContext(ctx, "custom resource definition records no install; its operator stays unnamed",
			"crd", crd.GetName())
		return installedWorkload{}
	}
	// The first identity by precedence: a HelmRelease's objects carry both Flux's
	// labels and Helm's annotations, and either names the same install.
	candidates := installs[ids[0]]
	if len(candidates) != 1 || candidates[0].image == "" {
		slog.DebugContext(ctx, "install of the custom resource definition does not single out an operator",
			"crd", crd.GetName(), "install", ids[0], "workloads", len(candidates))
		return installedWorkload{}
	}
	return candidates[0]
}

// workloadContext classifies a workload's deployment mechanism and, for
// non-operator cases, its actionability/source. The operator case is refined
// per-image by operatorContextForImage.
func workloadContext(ctx context.Context, meta metav1.ObjectMeta, kustSources map[string]kustSource, fetch crFetcher, crCache map[string]*unstructured.Unstructured) (enrich.DeployContext, bool) {
	owner, owned := customOwner(meta)
	// A controller-owned workload is classified by its owner before its labels.
	// Operators copy their custom resource's labels onto what they create (Argo
	// Events stamps the EventBus's Flux Kustomize labels on its NATS StatefulSet),
	// and those labels name whoever applied the custom resource, not what chose
	// the images. Reading them first sent registry tags no operator release
	// supports to the repository holding the custom resource.
	if owned && owner.Controller != nil && *owner.Controller {
		return operatorContext(ctx, meta, owner, fetch, crCache), true
	}
	for _, l := range helmToolkitLabels {
		if meta.Labels[l] != "" {
			return helmContext(meta.Labels), true
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
	if owned {
		return operatorContext(ctx, meta, owner, fetch, crCache), true
	}
	// Label-based controller ownership: some operators (e.g. flux-operator)
	// manage workloads via app.kubernetes.io/managed-by with no ownerReferences.
	// A direct image bump would be reverted, so treat these as controller-owned.
	if by := meta.Labels["app.kubernetes.io/managed-by"]; by != "" {
		switch strings.ToLower(by) {
		case "helm":
			return helmContext(meta.Labels), true
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

// operatorContext is the context of a workload owned by a custom resource,
// caching the resource for per-image spec inspection.
func operatorContext(ctx context.Context, meta metav1.ObjectMeta, ref metav1.OwnerReference, fetch crFetcher, crCache map[string]*unstructured.Unstructured) enrich.DeployContext {
	key := crCacheKey(ref.APIVersion, ref.Kind, meta.Namespace, ref.Name)
	if _, ok := crCache[key]; !ok {
		cr, err := fetch(ctx, ref.APIVersion, ref.Kind, meta.Namespace, ref.Name)
		if err == nil {
			crCache[key] = cr
		} else {
			crCache[key] = nil
		}
	}
	cr := crCache[key]
	dc := enrich.DeployContext{
		Mechanism: "operator", Actionable: false,
		Source:      crRef(ref.Kind, meta.Namespace, ref.Name),
		Manager:     managerFromCR(cr, meta.Labels),
		OwnerUnread: cr == nil,
	}
	// A resource that is itself controller-owned was generated from its owner, and
	// the owner is what a person edits: a Crossplane FunctionRevision is stamped out
	// of the Function whose spec.package names the image.
	if cr != nil {
		if parent, ok := customOwner(metav1.ObjectMeta{OwnerReferences: cr.GetOwnerReferences()}); ok &&
			parent.Controller != nil && *parent.Controller {
			dc.Source = crRef(parent.Kind, meta.Namespace, parent.Name)
		}
	}
	return dc
}

// customOwner returns the workload's owner in a custom resource group: its
// controller when that is one, else the first such owner.
func customOwner(meta metav1.ObjectMeta) (metav1.OwnerReference, bool) {
	var first *metav1.OwnerReference
	for i, ref := range meta.OwnerReferences {
		if !ownerGroupIsCustom(ref.APIVersion) {
			continue
		}
		if ref.Controller != nil && *ref.Controller {
			return ref, true
		}
		if first == nil {
			first = &meta.OwnerReferences[i]
		}
	}
	if first == nil {
		return metav1.OwnerReference{}, false
	}
	return *first, true
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
	ref, ok := customOwner(meta)
	if !ok {
		return base
	}
	cr := crCache[crCacheKey(ref.APIVersion, ref.Kind, meta.Namespace, ref.Name)]
	if cr != nil && imageInSpec(cr, image) {
		base.Actionable = true
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

// helmContext names the Helm release and chart that own a workload's version.
//
// Helm's own labels carry both, and they are the only place to find them when the
// release was not created by a Flux HelmRelease — bootstrapped components (the Flux
// operator itself, anything installed by Terraform or the CLI) have no HelmRelease
// object to read. Without this the report can only say "helm", which tells someone
// the image tag is not the place to change it but not where is.
func helmContext(labels map[string]string) enrich.DeployContext {
	dc := enrich.DeployContext{Mechanism: "helm", Actionable: false}
	// helm.sh/chart is "<chart>-<version>", which names the chart to bump and the
	// version it is on. Flux's own label names the HelmRelease instead.
	if chart := labels["helm.sh/chart"]; chart != "" {
		dc.Manager = chart
	} else if hr := labels["helm.toolkit.fluxcd.io/name"]; hr != "" {
		dc.Manager = hr
	}
	if release := labels["app.kubernetes.io/instance"]; release != "" {
		dc.Source = release
	}
	return dc
}
