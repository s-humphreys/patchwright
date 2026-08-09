package kube

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// ManagedImages reports, per image NameTag, the controller that owns its
// version — "helm" for Flux/Helm-labelled workloads, "operator" for workloads
// owned by a custom resource. Such images are not directly upgradeable by
// bumping a manifest tag (the controller would revert it); the remediation is
// to upgrade the chart/operator instead. Images not present are directly
// deployed (plain manifest / Kustomize) and may take an image-tag upgrade.
func (s *Source) ManagedImages(ctx context.Context) (map[string]string, error) {
	configs, err := s.restConfigs()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for label, cfg := range configs {
		typed, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
		if err := collectManagedImages(ctx, typed, out); err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
	}
	return out, nil
}

func collectManagedImages(ctx context.Context, client kubernetes.Interface, out map[string]string) error {
	classify := func(meta metav1.ObjectMeta, spec corev1.PodSpec) {
		mech := workloadMechanism(meta)
		if mech == "" {
			return // directly deployed — leave upgradeable
		}
		for _, c := range podContainers(spec) {
			key := model.ParseImageRef(c.Image).NameTag()
			// helm takes precedence over operator if both somehow apply.
			if cur, ok := out[key]; !ok || (cur != "helm" && mech == "helm") {
				out[key] = mech
			}
		}
	}

	deploys, err := client.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list deployments: %w", err)
	}
	for i := range deploys.Items {
		classify(deploys.Items[i].ObjectMeta, deploys.Items[i].Spec.Template.Spec)
	}
	sts, err := client.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list statefulsets: %w", err)
	}
	for i := range sts.Items {
		classify(sts.Items[i].ObjectMeta, sts.Items[i].Spec.Template.Spec)
	}
	ds, err := client.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list daemonsets: %w", err)
	}
	for i := range ds.Items {
		classify(ds.Items[i].ObjectMeta, ds.Items[i].Spec.Template.Spec)
	}
	return nil
}

// workloadMechanism classifies who controls a workload's version: "helm" when
// it carries the Flux/Helm labels, "operator" when it is owned by a custom
// resource, or "" when it is directly deployed (manifest / Kustomize).
func workloadMechanism(meta metav1.ObjectMeta) string {
	if meta.Labels["helm.toolkit.fluxcd.io/name"] != "" || meta.Labels["helm.sh/chart"] != "" {
		return "helm"
	}
	for _, ref := range meta.OwnerReferences {
		if ownerGroupIsCustom(ref.APIVersion) {
			return "operator"
		}
	}
	return ""
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
