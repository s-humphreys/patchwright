package enrich

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// UpgradeSource reports the newer version available for how each image is
// deployed, keyed by image "registry/repository:tag" (model.Image.NameTag). It
// backs remediation detection and is implemented by the client-go kube source
// (reads Flux HelmReleases and checks their chart repositories).
type UpgradeSource interface {
	Upgrades(ctx context.Context) (map[string]model.Upgrade, error)
}

// RemediationEnricher annotates each image with an available upgrade — the
// concrete remediation path (e.g. "bump chart 1.2 -> 1.5"). It is an image-level
// enricher (runs after dedupe).
type RemediationEnricher struct {
	Source UpgradeSource
}

// NewRemediationEnricher builds a RemediationEnricher from a source.
func NewRemediationEnricher(src UpgradeSource) RemediationEnricher {
	return RemediationEnricher{Source: src}
}

// EnrichImages sets Upgrade on each image that maps to a known deployment.
func (r RemediationEnricher) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	upgrades, err := r.Source.Upgrades(ctx)
	if err != nil {
		return fmt.Errorf("upgrade source: %w", err)
	}
	matched, available := 0, 0
	for i := range images {
		u, ok := upgrades[images[i].Image.NameTag()]
		if !ok {
			continue
		}
		up := u
		images[i].Upgrade = &up
		matched++
		if up.Available {
			available++
		}
	}
	slog.DebugContext(ctx, "detected deployment upgrades",
		"deployments", len(upgrades), "matched", matched, "upgradable", available)
	return nil
}
