package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// CVE ageing.
//
// Every other view in patchwright is a snapshot: it can say an image has three
// criticals, not that one of them has been there since June. That makes an SLA
// inexpressible and "oldest first" unavailable, which is how a queue with no
// deadline becomes a queue nobody works through.
//
// The data comes from the scan provider, which already tracks when it first saw
// each CVE, so nothing needs storing locally. A state file would be the obvious
// alternative and a bad one: it would start empty, so every finding would look new
// on the first run and ages would only become true months later.

// AgeSource reports when a set of CVEs was first observed.
type AgeSource interface {
	Name() string
	// FirstSeen returns first-observed times by CVE id. Ids it knows nothing about
	// are omitted rather than zeroed, so "unknown" survives the round trip.
	FirstSeen(ctx context.Context, cveIDs []string) (map[string]time.Time, error)
}

// AgeFactory constructs an AgeSource from Options.
type AgeFactory func(opts Options) (AgeSource, error)

var ageRegistry = map[string]AgeFactory{}

// RegisterAgeSource makes an age source available by name.
func RegisterAgeSource(name string, f AgeFactory) {
	if _, exists := ageRegistry[name]; exists {
		panic(fmt.Sprintf("enrich: age source %q already registered", name))
	}
	ageRegistry[name] = f
}

// NewAgeSource constructs a registered age source by name.
func NewAgeSource(name string, opts Options) (AgeSource, error) {
	f, ok := ageRegistry[name]
	if !ok {
		return nil, fmt.Errorf("unknown age source %q (available: %v)", name, AgeSourceNames())
	}
	return f(opts)
}

// AgeSourceNames returns the sorted registered age source names.
func AgeSourceNames() []string {
	names := make([]string, 0, len(ageRegistry))
	for name := range ageRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// AgeEnricher stamps first-seen times onto already-scanned vulnerabilities. It runs
// after image scanning, gathers every CVE id once, and writes the times back.
type AgeEnricher struct {
	Source AgeSource
}

// NewAgeEnricher builds an AgeEnricher from a source.
func NewAgeEnricher(src AgeSource) AgeEnricher { return AgeEnricher{Source: src} }

// EnrichImages looks up first-seen times for every CVE present and applies them in
// place. A no-op when nothing has per-CVE detail, which is the case without a vuln
// source.
func (e AgeEnricher) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	idset := map[string]struct{}{}
	for i := range images {
		for _, v := range images[i].Vulns {
			if v.ID != "" {
				idset[v.ID] = struct{}{}
			}
		}
	}
	if len(idset) == 0 {
		// Nothing to age. Said at debug rather than silently, because "no ages" and
		// "no CVEs to age" look identical in the output.
		slog.DebugContext(ctx, "no per-CVE detail to age", "source", e.Source.Name())
		return nil
	}

	ids := make([]string, 0, len(idset))
	for id := range idset {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	seen, err := e.Source.FirstSeen(ctx, ids)
	if err != nil {
		return fmt.Errorf("age source %q: %w", e.Source.Name(), err)
	}

	var stamped int
	for i := range images {
		for j := range images[i].Vulns {
			if t, ok := seen[images[i].Vulns[j].ID]; ok && !t.IsZero() {
				images[i].Vulns[j].FirstSeen = t
				stamped++
			}
		}
	}
	// Reported as a fraction: the provider knows nothing about CVEs it did not find
	// itself, so partial coverage is normal and worth seeing rather than assuming.
	slog.InfoContext(ctx, "cve ages gathered",
		"source", e.Source.Name(), "cves", len(ids), "dated", len(seen), "stamped", stamped)
	return nil
}
