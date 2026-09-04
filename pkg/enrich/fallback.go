package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/s-humphreys/patchwright/internal/metrics"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// FallbackScanner scans the images the scan provider never assessed, so a
// coverage gap is answered with something rather than with nothing.
//
// It is a second, independently configured VulnSource rather than a mode of
// ImageScanner, because on a real estate the primary vuln source IS the scan
// provider (Rapid7 supplies both). Asking it again about an image it has no data
// for returns the same nothing. The fallback only helps when it is something
// else, pulling the image itself.
//
// What it deliberately does not do:
//
//   - It does not touch images the provider assessed. Those already have counts,
//     from a source the rest of the report is drawn from, and rescanning them
//     would blend two severity taxonomies across rows nobody asked about.
//   - It does not touch images Skip rules out. The skip list is the same policy
//     the primary scanner obeys (cloud-provider-owned images, registries with no
//     credentials); a fallback that ignored it would scan exactly the images
//     somebody decided were not worth scanning.
//
// Together those bound the work to the residual gap, which on the estate this was
// built for is six images out of 649 rather than the whole fleet.
type FallbackScanner struct {
	Source      VulnSource
	Concurrency int // scans in flight; defaults to the source's own advice
	// Skip is the primary scanner's skip policy, applied unchanged. See above.
	Skip func(model.AssessedImage) bool
}

// NewFallbackScanner builds a fallback scanner at whatever concurrency the source
// says is safe for it, matching NewImageScanner.
func NewFallbackScanner(src VulnSource) FallbackScanner {
	conc := defaultScanConcurrency
	if p, ok := src.(Paralleliser); ok {
		if n := p.ScanConcurrency(); n > 0 {
			conc = n
		}
	}
	return FallbackScanner{Source: src, Concurrency: conc}
}

// EnrichImages scans every unassessed, unskipped image and fills in what the
// provider could not supply: per-CVE detail, and severity counts derived from it.
//
// Failures are recorded per image and never fail the run — including the case
// where every scan fails, which the primary scanner treats as systemic. Here it
// usually is not: the images reaching this point are the ones the provider could
// not pull either, so them all failing is the expected shape of a bad credential
// rather than a broken install, and it must not take the assessment down with it.
func (s FallbackScanner) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	conc := s.Concurrency
	if conc < 1 {
		conc = 1
	}

	var targets []int
	for i := range images {
		if images[i].ProviderAssessed() {
			continue
		}
		if s.Skip != nil && s.Skip(images[i]) {
			metrics.FallbackScan("skipped")
			continue
		}
		targets = append(targets, i)
	}
	slog.InfoContext(ctx, "scanning provider-unassessed images with the fallback source",
		"source", s.Source.Name(), "to_scan", len(targets), "of_images", len(images))
	if len(targets) == 0 {
		return nil
	}

	if p, ok := s.Source.(Preparer); ok {
		if err := p.Prepare(ctx); err != nil {
			// Recorded on every target rather than returned. A DB download that
			// failed is a reason none of these images got covered, and it belongs
			// on the findings where somebody will see it.
			reason := fmt.Sprintf("fallback source %q: prepare: %v", s.Source.Name(), err)
			for _, i := range targets {
				images[i].FallbackSource = s.Source.Name()
				images[i].FallbackError = reason
				metrics.FallbackScan("failed")
			}
			slog.WarnContext(ctx, "fallback source could not prepare; unassessed images stay uncovered",
				"source", s.Source.Name(), "images", len(targets), "error", err)
			return nil
		}
	}

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	covered := 0

loop:
	for _, i := range targets {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break loop
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()

			images[i].FallbackSource = s.Source.Name()
			vulns, err := s.Source.Scan(ctx, images[i].Image)
			if err != nil {
				metrics.FallbackScan("failed")
				images[i].FallbackError = err.Error()
				slog.WarnContext(ctx, "fallback scan failed (image stays uncovered)",
					"image", images[i].Image.Ref, "error", err)
				return
			}
			metrics.FallbackScan("ok")
			images[i].FallbackScanned = true
			images[i].Vulns = mergeVulns(images[i].Vulns, vulns)
			// Counts, not just Vulns: the report's severity columns read Counts, and
			// leaving them empty would render a scan that succeeded as "?".
			// CountsSource is what stops that number being mistaken for the
			// provider's.
			images[i].Counts = model.CountsFromVulns(images[i].Vulns)
			images[i].CountsSource = s.Source.Name()
			mu.Lock()
			covered++
			mu.Unlock()
			slog.DebugContext(ctx, "fallback scanned image",
				"image", images[i].Image.Ref, "vulns", len(images[i].Vulns))
		}(i)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return err
	}
	slog.InfoContext(ctx, "fallback scanning complete",
		"covered", covered, "uncovered", len(targets)-covered)
	return nil
}
