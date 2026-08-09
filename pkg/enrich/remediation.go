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
