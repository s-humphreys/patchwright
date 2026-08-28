// Package basescan answers, with certainty rather than inference, which of an
// image's vulnerabilities came from its base image and which of them a base
// upgrade would actually fix.
//
// The provider tells us which CVEs are in an image. It does not record which
// package carried each one in: its per-CVE `Solutions` block is the CVE's generic
// remediation record, and on a sample of six images 66% of its entries named an
// ecosystem the image does not even contain (docs/design/package-attribution.md).
// Inferring ownership from it sends work to the wrong team.
//
// Certainty does not require attributing packages to layers, which is the
// expensive way to ask. It requires scanning the base and doing set arithmetic:
//
//	in the base as built            -> the base image's, not the team's
//	in the app, not in its base     -> the Dockerfile installed it, the team owns it
//	gone in the candidate base      -> this upgrade fixes it
//
// The third is the one that makes a queue worth working. "A newer tag exists" asks
// a team to do an upgrade of unknown value; "this clears 3,664 of your 4,890"
// does not.
//
// The cost stays small because only BASE images are scanned - around 30
// repositories and 127 tags across an estate of thousands of images - and the
// results are shared by every image built on them.
package basescan

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Package is one package a scan found, the ecosystem it belongs to, and the
// version that fixes the CVE it was found under.
//
// FixedVersion comes from the same scan as the name, which is the point: the
// provider reports a fix per CVE rather than per package, so its version can
// belong to a different ecosystem than the package it is shown beside - an Alpine
// package version next to a Go module was how that failure actually looked.
type Package struct {
	Name         string
	Ecosystem    string // "debian", "alpine", "azurelinux", "gobinary", "dotnet-core", ...
	FixedVersion string
}

// Result is what a single image reference contains.
type Result struct {
	Ref string
	// OSFamily is the distro the scanner identified ("debian", "alpine",
	// "azurelinux", "redhat"). Empty for an image with no OS package database,
	// such as a distroless or FROM scratch image.
	OSFamily string
	// Ecosystems is every ecosystem present in the image. This is the value that
	// lets the provider's package names be filtered down to ones that could
	// actually be in this image.
	Ecosystems map[string]bool
	// CVEs maps a CVE id to the packages carrying it.
	CVEs map[string][]Package
}

// Has reports whether the image contains this CVE.
func (r *Result) Has(cve string) bool {
	if r == nil {
		return false
	}
	_, ok := r.CVEs[cve]
	return ok
}

// Scanner reads one image reference. Implemented against Trivy; a fake in tests.
type Scanner interface {
	Name() string
	ScanRef(ctx context.Context, ref string) (*Result, error)
}

// Resolver scans base references, once each, and hands the same result to every
// image built on them.
//
// Deduplication is the whole economy of this: 684 images on this estate resolve
// to 30 base repositories. Scanning per image would be the estate-wide scan this
// design exists to avoid.
type Resolver struct {
	Scanner Scanner
	// Concurrency bounds simultaneous scans. Each one pulls an image, so this is
	// network and disk bound rather than CPU bound.
	Concurrency int

	mu      sync.Mutex
	entries map[string]*entry
	sem     chan struct{}
	semOnce sync.Once
}

// entry is one reference's scan, shared by every caller that asks for it.
//
// A sync.Once per reference rather than a lock over the whole map: several images
// built on the same base are resolved concurrently, and without this they would
// each start their own scan of it - the duplicate work this type exists to avoid,
// reintroduced by the concurrency that makes it fast.
type entry struct {
	once sync.Once
	res  *Result
	err  error
}

// Scan returns the scan of ref, running it at most once per reference.
//
// A failed scan is cached too. Retrying it for every image built on the same
// broken base would multiply one unreachable registry into hundreds of identical
// failures and a very long run.
func (r *Resolver) Scan(ctx context.Context, ref string) (*Result, error) {
	if ref == "" {
		return nil, fmt.Errorf("basescan: empty reference")
	}
	r.mu.Lock()
	if r.entries == nil {
		r.entries = map[string]*entry{}
	}
	e, ok := r.entries[ref]
	if !ok {
		e = &entry{}
		r.entries[ref] = e
	}
	r.mu.Unlock()

	e.once.Do(func() {
		r.semOnce.Do(func() {
			n := r.Concurrency
			if n <= 0 {
				n = 4
			}
			r.sem = make(chan struct{}, n)
		})
		select {
		case r.sem <- struct{}{}:
			defer func() { <-r.sem }()
		case <-ctx.Done():
			e.err = ctx.Err()
			return
		}
		slog.DebugContext(ctx, "scanning base image", "ref", ref, "scanner", r.Scanner.Name())
		e.res, e.err = r.Scanner.ScanRef(ctx, ref)
		if e.err != nil {
			slog.WarnContext(ctx, "base image scan failed", "ref", ref, "error", e.err)
		}
	})
	return e.res, e.err
}

// Scanned reports how many distinct references have been scanned, for logging the
// cost of a run against the number of images it covered.
func (r *Resolver) Scanned() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
