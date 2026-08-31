package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/s-humphreys/patchwright/internal/metrics"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// VulnSource returns per-CVE detail for a single image, including fix
// availability — the signal that separates "there is a patch to apply" from
// "a critical with no upstream fix". Backed by scanners such as Trivy or Grype.
type VulnSource interface {
	Name() string
	Scan(ctx context.Context, image model.Image) ([]model.Vulnerability, error)
}

// VulnFactory constructs a VulnSource from Options.
type VulnFactory func(opts Options) (VulnSource, error)

var vulnRegistry = map[string]VulnFactory{}

// RegisterVulnSource makes a vuln source available by name (called from init).
func RegisterVulnSource(name string, f VulnFactory) {
	if _, exists := vulnRegistry[name]; exists {
		panic(fmt.Sprintf("enrich: vuln source %q already registered", name))
	}
	vulnRegistry[name] = f
}

// NewVulnSource constructs a registered vuln source by name.
func NewVulnSource(name string, opts Options) (VulnSource, error) {
	f, ok := vulnRegistry[name]
	if !ok {
		return nil, fmt.Errorf("unknown vuln source %q (available: %v)", name, VulnSourceNames())
	}
	return f(opts)
}

// VulnSourceNames returns the sorted registered vuln source names.
func VulnSourceNames() []string {
	names := make([]string, 0, len(vulnRegistry))
	for name := range vulnRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ImageScanner scans each assessed image once (images are already unique after
// dedupe) and populates its per-CVE Vulns. Scanning is the expensive part, so
// it runs with bounded concurrency.
type ImageScanner struct {
	Source      VulnSource
	Concurrency int // scans in flight; defaults to 4
	// Skip, when set, reports images that should not be scanned (e.g. images
	// owned entirely by a class that can't be remediated). Skipped images are
	// left unscanned without being counted as failures.
	Skip func(model.AssessedImage) bool
}

// NewImageScanner builds an ImageScanner from a source, at whatever concurrency that
// source says is safe for it.
//
// One default for every source was wrong, and measurably so. Four at a time suits
// Trivy, where each "scan" pulls an image and works through its filesystem - more of
// those compete for disk and memory, and on one estate a shared disk cache deadlocked
// under concurrency. It badly suits an API source, where a scan is a single HTTP
// request: 768 images at four in flight took 2m19s of a ten-minute assessment, mostly
// waiting.
func NewImageScanner(src VulnSource) ImageScanner {
	conc := defaultScanConcurrency
	if p, ok := src.(Paralleliser); ok {
		if n := p.ScanConcurrency(); n > 0 {
			conc = n
		}
	}
	return ImageScanner{Source: src, Concurrency: conc}
}

// defaultScanConcurrency is what a source that says nothing gets: the cautious value,
// because a source that has not thought about it is more likely to be pulling images
// than making requests.
const defaultScanConcurrency = 4

// Paralleliser is an optional VulnSource capability stating how many scans of it may
// run at once. A source knows what it is doing per image; the scanner does not.
type Paralleliser interface {
	ScanConcurrency() int
}

// Preparer is an optional VulnSource capability for one-time setup before the
// concurrent scan loop — e.g. warming a shared cache or database so the workers
// don't race to populate it.
type Preparer interface {
	Prepare(ctx context.Context) error
}

// EnrichImages scans every image concurrently and merges the results into each
// image's Vulns (deduped by CVE id). Per-image failures are tolerated — the
// image is marked with its ScanError and the run continues — so one image
// patchwright can't pull (e.g. a private registry with no credentials) does not
// fail the whole assessment. It only returns an error when *every* image failed
// (a systemic problem, e.g. the trivy binary is missing) or the context is done.
func (s ImageScanner) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	conc := s.Concurrency
	if conc < 1 {
		conc = 1
	}

	// Count what will actually be scanned so we can no-op (and skip the
	// potentially expensive Prepare) when everything is filtered out.
	skipped := 0
	if s.Skip != nil {
		for i := range images {
			if s.Skip(images[i]) {
				skipped++
			}
		}
	}
	toScan := len(images) - skipped
	for i := 0; i < skipped; i++ {
		// Skips are counted too: "nothing failed" reads very differently when most
		// of the estate was never a candidate.
		metrics.ImageScan("skipped")
	}
	slog.InfoContext(ctx, "scanning images for vulnerabilities",
		"source", s.Source.Name(), "to_scan", toScan, "skipped", skipped, "concurrency", conc)
	if toScan == 0 {
		return nil
	}

	// One-time setup (e.g. warm the vuln DB) before workers start, so they
	// don't race to populate a shared cache.
	if p, ok := s.Source.(Preparer); ok {
		if err := p.Prepare(ctx); err != nil {
			return fmt.Errorf("vuln source %q: prepare: %w", s.Source.Name(), err)
		}
	}

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	failures := 0

loop:
	for i := range images {
		if s.Skip != nil && s.Skip(images[i]) {
			continue // already counted in skipped
		}
		// Acquire a slot, but stop promptly if the context is cancelled even
		// while concurrency is saturated (a plain send could block forever).
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break loop
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			// Each goroutine owns images[i], so those writes need no lock; only
			// the shared counters do. Keep logging (potential I/O) out of the
			// critical section so it doesn't serialize concurrent scans.
			vulns, err := s.Source.Scan(ctx, images[i].Image)
			if err != nil {
				// Counted, not labelled by image: a per-image label would be one
				// series per image in the estate, and the finding itself already
				// carries the reason.
				metrics.ImageScan("failed")
				images[i].ScanError = err.Error()
				mu.Lock()
				failures++
				if firstErr == nil {
					firstErr = fmt.Errorf("vuln source %q: scan %s: %w", s.Source.Name(), images[i].Image.Ref, err)
				}
				mu.Unlock()
				slog.WarnContext(ctx, "image scan failed (reported unscanned)", "image", images[i].Image.Ref, "error", err)
				return
			}
			metrics.ImageScan("ok")
			images[i].Scanned = true
			images[i].Vulns = mergeVulns(images[i].Vulns, vulns)
			slog.DebugContext(ctx, "scanned image", "image", images[i].Image.Ref, "vulns", len(images[i].Vulns))
		}(i)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return err
	}
	// Every attempted scan failing usually means a systemic issue (missing
	// binary, bad config) rather than a handful of unreachable images.
	if failures == toScan {
		return fmt.Errorf("all %d image scans failed: %w", failures, firstErr)
	}
	slog.InfoContext(ctx, "image scanning complete",
		"scanned", toScan-failures, "failed", failures, "skipped", skipped)
	return nil
}

// mergeVulns unions vulnerabilities by CVE id, preferring an entry that carries
// fix information over one that doesn't.
func mergeVulns(existing, scanned []model.Vulnerability) []model.Vulnerability {
	byID := make(map[string]model.Vulnerability)
	var order []string
	add := func(v model.Vulnerability) {
		if cur, ok := byID[v.ID]; ok {
			if !cur.FixAvailable && v.FixAvailable {
				byID[v.ID] = v
			}
			return
		}
		byID[v.ID] = v
		order = append(order, v.ID)
	}
	for _, v := range existing {
		add(v)
	}
	for _, v := range scanned {
		add(v)
	}
	out := make([]model.Vulnerability, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out
}
