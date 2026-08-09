package kube

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/upgrade"
)

// Compile-time assertion that the kube source can report upgrades.
var _ enrich.UpgradeSource = (*Source)(nil)

var (
	helmReleaseGVR    = schema.GroupVersionResource{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"}
	helmRepositoryGVR = schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "helmrepositories"}
)

// chartChecker is the Helm-repo lookup, an interface so tests can stub it.
type chartChecker interface {
	Check(ctx context.Context, ref upgrade.ChartRef) (model.Upgrade, error)
}

// Upgrades runs the configured UpgradeResolvers across every cluster and merges
// the per-image upgrades they report. The first resolver to report an upgrade
// for an image wins. Defaults to the Flux HelmRelease resolver.
func (s *Source) Upgrades(ctx context.Context) (map[string]model.Upgrade, error) {
	resolvers := s.resolvers
	if len(resolvers) == 0 {
		resolvers = defaultResolvers()
	}
	configs, err := s.restConfigs()
	if err != nil {
		return nil, err
	}

	result := map[string]model.Upgrade{}
	for label, cfg := range configs {
		typed, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
		dyn, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
		for _, r := range resolvers {
			ups, err := r.Resolve(ctx, typed, dyn)
			if err != nil {
				return nil, fmt.Errorf("cluster %q: resolver %q: %w", label, r.Name(), err)
			}
			for image, up := range ups {
				if _, exists := result[image]; !exists {
					result[image] = up
				}
			}
		}
	}
	return result, nil
}

func clusterUpgrades(ctx context.Context, typed kubernetes.Interface, dyn dynamic.Interface, checker chartChecker, result map[string]model.Upgrade) error {
	// Which images belong to which HelmRelease (via the labels Flux stamps on
	// the workloads it creates).
	imageToRelease, err := helmWorkloadImages(ctx, typed)
	if err != nil {
		return err
	}
	if len(imageToRelease) == 0 {
		return nil // nothing Flux-managed here
	}

	releases, err := listHelmReleases(ctx, dyn)
	if err != nil {
		// Flux (or its CRDs) not present — tolerate.
		slog.DebugContext(ctx, "could not list flux helmreleases; skipping upgrade detection", "error", err)
		return nil
	}
	repos, err := listHelmRepositories(ctx, dyn)
	if err != nil {
		slog.DebugContext(ctx, "could not list flux helmrepositories", "error", err)
		repos = map[string]string{}
	}

	cache := map[string]model.Upgrade{}
	for image, releaseKey := range imageToRelease {
		rel, ok := releases[releaseKey]
		if !ok {
			continue
		}
		if up, done := cache[releaseKey]; done {
			result[image] = up
			continue
		}
		repoURL := repos[rel.repoKey]
		if repoURL == "" || rel.chart == "" || rel.version == "" {
			continue
		}
		up, err := checker.Check(ctx, upgrade.ChartRef{RepoURL: repoURL, Name: rel.chart, Version: rel.version})
		if err != nil {
			slog.WarnContext(ctx, "helm chart upgrade check failed", "chart", rel.chart, "repo", repoURL, "error", err)
			continue
		}
		cache[releaseKey] = up
		result[image] = up
	}
	return nil
}

// helmWorkloadImages maps image NameTag -> "<hrNamespace>/<hrName>" using the
// helm.toolkit.fluxcd.io labels Flux stamps on the workloads it manages.
func helmWorkloadImages(ctx context.Context, client kubernetes.Interface) (map[string]string, error) {
	out := map[string]string{}
	add := func(meta metav1.ObjectMeta, spec corev1.PodSpec) {
		name := meta.Labels["helm.toolkit.fluxcd.io/name"]
		if name == "" {
			return
		}
		ns := meta.Labels["helm.toolkit.fluxcd.io/namespace"]
		if ns == "" {
			ns = meta.Namespace
		}
		key := ns + "/" + name
		for _, c := range podContainers(spec) {
			out[model.ParseImageRef(c.Image).NameTag()] = key
		}
	}

	deploys, err := client.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	for i := range deploys.Items {
		add(deploys.Items[i].ObjectMeta, deploys.Items[i].Spec.Template.Spec)
	}
	sts, err := client.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list statefulsets: %w", err)
	}
	for i := range sts.Items {
		add(sts.Items[i].ObjectMeta, sts.Items[i].Spec.Template.Spec)
	}
	ds, err := client.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list daemonsets: %w", err)
	}
	for i := range ds.Items {
		add(ds.Items[i].ObjectMeta, ds.Items[i].Spec.Template.Spec)
	}
	return out, nil
}

func podContainers(spec corev1.PodSpec) []corev1.Container {
	return append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...)
}

type releaseInfo struct {
	chart   string
	version string
	repoKey string // "<sourceNamespace>/<sourceName>"
}

func listHelmReleases(ctx context.Context, dyn dynamic.Interface) (map[string]releaseInfo, error) {
	list, err := dyn.Resource(helmReleaseGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make(map[string]releaseInfo, len(list.Items))
	for i := range list.Items {
		key, info := parseHelmRelease(&list.Items[i])
		out[key] = info
	}
	return out, nil
}

func listHelmRepositories(ctx context.Context, dyn dynamic.Interface) (map[string]string, error) {
	list, err := dyn.Resource(helmRepositoryGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(list.Items))
	for i := range list.Items {
		key, url := parseHelmRepository(&list.Items[i])
		out[key] = url
	}
	return out, nil
}

// parseHelmRelease extracts (key, chart/version/source) from a Flux HelmRelease.
// The deployed version is taken from status history when available, falling back
// to the requested spec version.
func parseHelmRelease(u *unstructured.Unstructured) (key string, info releaseInfo) {
	ns, name := u.GetNamespace(), u.GetName()
	key = ns + "/" + name

	info.chart, _, _ = unstructured.NestedString(u.Object, "spec", "chart", "spec", "chart")

	if history, ok, _ := unstructured.NestedSlice(u.Object, "status", "history"); ok && len(history) > 0 {
		if h, ok := history[0].(map[string]interface{}); ok {
			if v, ok, _ := unstructured.NestedString(h, "chartVersion"); ok {
				info.version = v
			}
		}
	}
	if info.version == "" {
		info.version, _, _ = unstructured.NestedString(u.Object, "spec", "chart", "spec", "version")
	}

	sourceName, _, _ := unstructured.NestedString(u.Object, "spec", "chart", "spec", "sourceRef", "name")
	sourceNS, _, _ := unstructured.NestedString(u.Object, "spec", "chart", "spec", "sourceRef", "namespace")
	if sourceNS == "" {
		sourceNS = ns
	}
	if sourceName != "" {
		info.repoKey = sourceNS + "/" + sourceName
	}
	return key, info
}

// parseHelmRepository extracts (key, url) from a Flux HelmRepository.
func parseHelmRepository(u *unstructured.Unstructured) (key, url string) {
	key = u.GetNamespace() + "/" + u.GetName()
	url, _, _ = unstructured.NestedString(u.Object, "spec", "url")
	return key, url
}
