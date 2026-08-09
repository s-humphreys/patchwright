package kube

import (
	"context"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/upgrade"
)

// UpgradeResolver inspects one cluster and reports the available upgrade per
// image (keyed by model.Image.NameTag) for a particular deployment system. It
// is the common base interface for remediation-path detection: the Flux
// HelmRelease resolver implements it today; Argo, direct Helm releases, and
// Flux Git/OCI sources are future implementations of the same contract.
type UpgradeResolver interface {
	Name() string
	Resolve(ctx context.Context, typed kubernetes.Interface, dyn dynamic.Interface) (map[string]model.Upgrade, error)
}

// defaultResolvers is the set of resolvers used when a Source has none set.
func defaultResolvers() []UpgradeResolver {
	return []UpgradeResolver{
		fluxHelmResolver{checker: upgrade.NewHelmChecker()},
	}
}

// fluxHelmResolver detects newer Helm chart versions for workloads deployed by
// Flux HelmReleases.
type fluxHelmResolver struct {
	checker chartChecker
}

func (fluxHelmResolver) Name() string { return "flux-helm" }

func (r fluxHelmResolver) Resolve(ctx context.Context, typed kubernetes.Interface, dyn dynamic.Interface) (map[string]model.Upgrade, error) {
	result := map[string]model.Upgrade{}
	if err := clusterUpgrades(ctx, typed, dyn, r.checker, result); err != nil {
		return nil, err
	}
	return result, nil
}
