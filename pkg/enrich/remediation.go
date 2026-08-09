package enrich

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// UpgradeSource reports the newer version available for how each image is
// deployed, keyed by image "registry/repository:tag" (model.Image.NameTag).
// Implementations cover a remediation path — the Flux HelmRelease chart source
// (cluster-derived) and the registry image-tag source (image-derived) today,
// with Flux Git/OCI sources to follow. The images being assessed are passed in
// so image-derived sources know what to look up; cluster-derived sources may
// ignore them.
type UpgradeSource interface {
	Upgrades(ctx context.Context, images []model.AssessedImage) (map[string]model.Upgrade, error)
}

// DeployContext describes how an image is deployed, so a registry image-tag
// upgrade can be judged actionable and pointed at the right place to change.
type DeployContext struct {
	// Mechanism is how the workload is deployed: helm, operator, kustomize, or
	// manifest.
	Mechanism string
	// Actionable reports whether the image tag can be bumped directly at this
	// level — true for manifest/Kustomize images and for operator images whose
	// tag is a field in the owning custom resource; false for chart-managed or
	// operator-derived images (bump the chart/operator instead).
	Actionable bool
	// Source is where the change lands: a git repository URL (Kustomize), the
	// owning custom resource ref (operator, e.g. "Api/ns/name"), or empty.
	Source string
}

// DeploymentContextSource reports the deployment context per image NameTag, so
// the registry upgrade source can set actionability and the change target.
type DeploymentContextSource interface {
	ImageDeployments(ctx context.Context) (map[string]DeployContext, error)
}

// RemediationEnricher annotates each image with an available upgrade — the
// concrete remediation path (e.g. "bump chart 1.2 -> 1.5", or a newer image
// tag). It runs its sources in order and, per image, the first source to report
// an upgrade wins (so deployment-aware sources should be listed before the
// registry fallback). Image-level enricher (runs after dedupe).
type RemediationEnricher struct {
	Sources []UpgradeSource
}

// NewRemediationEnricher builds a RemediationEnricher from ordered sources.
func NewRemediationEnricher(sources ...UpgradeSource) RemediationEnricher {
	return RemediationEnricher{Sources: sources}
}

// EnrichImages sets Upgrade on each image an upgrade was found for.
func (r RemediationEnricher) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	merged := map[string]model.Upgrade{}
	for _, src := range r.Sources {
		ups, err := src.Upgrades(ctx, images)
		if err != nil {
			return fmt.Errorf("upgrade source: %w", err)
		}
		for image, up := range ups {
			if _, exists := merged[image]; !exists {
				merged[image] = up
			}
		}
	}

	matched, available := 0, 0
	for i := range images {
		up, ok := merged[images[i].Image.NameTag()]
		if !ok {
			continue
		}
		u := up
		images[i].Upgrade = &u
		matched++
		if u.Available {
			available++
		}
	}
	slog.DebugContext(ctx, "detected deployment upgrades", "matched", matched, "upgradable", available)
	return nil
}
