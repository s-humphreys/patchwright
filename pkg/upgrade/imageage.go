package upgrade

import (
	"context"
	"log/slog"
	"sync"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// How long since the image was built.
//
// Most of a queue is not neglect. An image drifts because nothing has rebuilt it,
// and the base it was built on has moved on since - so the finding is usually less
// "you ignored this" than "this has not shipped since March". Those are different
// conversations, and only one of them is worth having with a team.
//
// It also explains the shape of a queue at a glance. An image built last week with
// four hundred CVEs is a base image problem; the same count on an image built a year
// ago is a release cadence problem, and no severity count tells them apart.
//
// Scoped to first-party images. A vendor's build date is the vendor's business, and
// reading it would mean a config blob per third-party image for a fact nobody here
// can act on. First-party images are already read for their base labels, so this
// costs no additional registry calls - it reads the same cached config.

// ImageAgeEnricher records when each first-party image was built.
type ImageAgeEnricher struct {
	Cfg       config.RemediationConfig
	Inspector ImageInspector
	// Concurrency bounds simultaneous reads. Shared with nothing: the inspector's
	// cache means most of these return without touching a registry.
	Concurrency int
}

// EnrichImages sets ImageBuilt on every first-party image that records one.
//
// Never fatal. An unreadable image loses its build date and keeps everything else,
// which is the right trade for a field that explains a finding rather than deciding
// it.
func (e *ImageAgeEnricher) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	if e == nil || e.Inspector == nil {
		return nil
	}
	n := e.Concurrency
	if n <= 0 {
		n = 8
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	var mu sync.Mutex
	dated, failed := 0, 0

	for i := range images {
		img := &images[i]
		if !e.Cfg.IsFirstParty(img.Image.Registry) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			cfg, err := e.Inspector.Config(ctx, img.Image.NameTag())
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				return
			}
			if cfg.Built.IsZero() {
				return
			}
			img.ImageBuilt = cfg.Built
			dated++
		}()
	}
	wg.Wait()

	slog.InfoContext(ctx, "image build dates read", "dated", dated, "unreadable", failed)
	return nil
}
