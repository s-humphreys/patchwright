package enrich

import (
	"context"
	"fmt"
	"sort"
	"sync"

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
}

// NewImageScanner builds an ImageScanner from a source.
func NewImageScanner(src VulnSource) ImageScanner {
	return ImageScanner{Source: src, Concurrency: 4}
}

// EnrichImages scans every image concurrently and merges the results into each
// image's Vulns (deduped by CVE id). It fails on the first scan error so
// liveness/fix data is never silently partial.
func (s ImageScanner) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	conc := s.Concurrency
	if conc < 1 {
		conc = 1
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for i := range images {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			vulns, err := s.Source.Scan(ctx, images[i].Image)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("vuln source %q: scan %s: %w", s.Source.Name(), images[i].Image.Ref, err)
				}
				return
			}
			images[i].Vulns = mergeVulns(images[i].Vulns, vulns)
		}(i)
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
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
