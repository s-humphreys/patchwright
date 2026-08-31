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
	"time"
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

	// MaxAge bounds how long a scan is reused before the base is scanned again.
	//
	// It exists because a cache that never expires does not merely go stale, it
	// misattributes. An image's own CVEs are re-read every assessment; its base's
	// were not, and a CVE absent from the base scan is reported as coming from the
	// APPLICATION. So every CVE published against a base package after the process
	// started was blamed on the team that builds the image, for as long as the
	// process lived - which on a long-running server is weeks.
	//
	// Zero means DefaultMaxAge rather than "forever": the safe reading of an unset
	// bound is the one that cannot quietly grow. A negative value disables expiry
	// explicitly, for a one-shot command where the process outlives nothing.
	MaxAge time.Duration

	// Now is the clock, for tests.
	Now func() time.Time

	mu      sync.Mutex
	entries map[string]*entry
	sem     chan struct{}
	semOnce sync.Once
	// rescans counts entries replaced because they had expired, so a run can report
	// re-scanning as distinct from scanning something new.
	rescans int
}

// DefaultMaxAge is how long a base scan is reused when nothing says otherwise.
//
// Twelve hours is a compromise between two real costs. Shorter re-scans the estate's
// bases more often than the vulnerability data underneath them actually changes -
// Trivy's database updates daily - and each sweep of them measured 1m44s on a real
// estate. Longer widens the window in which a newly-published base CVE is attributed
// to the wrong team.
const DefaultMaxAge = 12 * time.Hour

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
	// at is when the scan finished, written and read under the resolver's mutex.
	// Zero means still in flight, which is NOT expired - a caller must wait for it
	// rather than starting a second scan of the same reference.
	at time.Time
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
	e := r.entryFor(ref)

	e.once.Do(func() {
		r.semOnce.Do(func() {
			n := r.Concurrency
			if n <= 0 {
				n = 8
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
		// Stamped under the lock, because entryFor reads it from other goroutines.
		// Stamped even on failure: a broken base must not be retried per image.
		r.mu.Lock()
		e.at = r.now()
		r.mu.Unlock()
	})
	return e.res, e.err
}

// entryFor returns the cache entry for ref, replacing one that has aged out.
//
// A scan still in flight is never replaced, whatever its age says: two callers asking
// for the same base at once must share one scan, which is the entire economy of this
// type.
func (r *Resolver) entryFor(ref string) *entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = map[string]*entry{}
	}
	e := r.entries[ref]
	if e != nil && r.expired(e) {
		// Replaced rather than reset: another goroutine may still hold the old pointer,
		// and it should finish reading the answer it already has.
		e = nil
		r.rescans++
	}
	if e == nil {
		e = &entry{}
		r.entries[ref] = e
	}
	return e
}

// expired reports whether an entry has outlived MaxAge. Callers hold the mutex.
func (r *Resolver) expired(e *entry) bool {
	max := r.MaxAge
	if max == 0 {
		max = DefaultMaxAge
	}
	if max < 0 || e.at.IsZero() {
		return false
	}
	return r.now().Sub(e.at) >= max
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Rescanned reports how many cached scans were discarded as too old, so a run can say
// what it re-read rather than leaving a re-scan looking like new work.
func (r *Resolver) Rescanned() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rescans
}

// Scanned reports how many distinct references have been scanned, for logging the
// cost of a run against the number of images it covered.
func (r *Resolver) Scanned() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
