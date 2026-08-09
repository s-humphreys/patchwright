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
// for an image wins. Defaults to the Flux HelmRelease resolver. It enumerates
// from the cluster, so the images argument is unused.
func (s *Source) Upgrades(ctx context.Context, _ []model.AssessedImage) (map[string]model.Upgrade, error) {
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

	// Resolve each referenced HelmRelease once, logging why any is skipped so
	// the "no upgrade shown" case is diagnosable at debug level.
	needed := map[string]struct{}{}
	for _, releaseKey := range imageToRelease {
		needed[releaseKey] = struct{}{}
	}
	resolved := make(map[string]model.Upgrade, len(needed))
	for releaseKey := range needed {
		rel, ok := releases[releaseKey]
		if !ok {
			slog.DebugContext(ctx, "workload references an unknown HelmRelease", "release", releaseKey)
			continue
		}
		repoURL := repos[rel.repoKey]
		if repoURL == "" {
			slog.DebugContext(ctx, "HelmRelease source repository not found", "release", releaseKey, "repo", rel.repoKey)
			continue
		}
		if rel.chart == "" || rel.version == "" {
			slog.DebugContext(ctx, "HelmRelease missing chart or version", "release", releaseKey, "chart", rel.chart, "version", rel.version)
			continue
		}
		up, err := checker.Check(ctx, upgrade.ChartRef{RepoURL: repoURL, Name: rel.chart, Version: rel.version})
		if err != nil {
			slog.WarnContext(ctx, "helm chart upgrade check failed", "release", releaseKey, "chart", rel.chart, "repo", repoURL, "error", err)
			continue
		}
		resolved[releaseKey] = up
	}
	for image, releaseKey := range imageToRelease {
		if up, ok := resolved[releaseKey]; ok {
			result[image] = up
		}
	}
	slog.DebugContext(ctx, "resolved helm upgrades", "helmreleases", len(needed), "resolved", len(resolved))
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
			nt := model.ParseImageRef(c.Image).NameTag()
			// An image can appear in several HelmReleases (shared base images).
			// Pick deterministically (smallest release key) so attribution is
			// stable regardless of list order.
			if existing, ok := out[nt]; !ok || key < existing {
				out[nt] = key
			}
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
