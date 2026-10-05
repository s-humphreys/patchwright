package enrich

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/s-humphreys/patchwright/internal/metrics"
	"github.com/s-humphreys/patchwright/pkg/basescan"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// BaseDiffEnricher establishes, per image, which of its CVEs came from the base
// image and which of them a base upgrade would actually fix.
//
// Runs after remediation, not with the vuln scan: it needs the base references
// that base-image resolution produces, and those do not exist until then.
type BaseDiffEnricher struct {
	Resolver *basescan.Resolver
	// Concurrency bounds how many images are diffed at once. The scans behind
	// them are separately bounded by the resolver, and shared: most images here
	// are waiting on a base somebody else is already scanning.
	Concurrency int

	// ScanExploited also scans the IMAGE, not only its base, when it carries an
	// exploited CVE with a fix that the base does not account for. That is the
	// CVE a ticket has to name a package for: "an application dependency, fix in
	// 1.0.1" sends the assignee on a lockfile hunt with no name to look for, and
	// the base differential cannot name it because the base does not have it.
	//
	// Bounded by what it asks about rather than by the estate: only images with
	// such a CVE are scanned, cached per reference like the bases. Off by default
	// because it pulls first-party images, which needs credentials the base scans
	// may not.
	ScanExploited bool
	// ExploitedEPSS is the EPSS at or above which a CVE counts as exploited for
	// that purpose, alongside CISA KEV membership. Zero means DefaultExploitedEPSS.
	ExploitedEPSS float64

	// imagesScanned counts images scanned for their own packages, for the run log.
	imagesScanned atomic.Int64
}

// DefaultExploitedEPSS is the probability at which a CVE is worth naming a
// package for when nothing says otherwise: a coin-flip chance of exploitation
// in the next 30 days, matching the threshold the shipped policy rules use.
const DefaultExploitedEPSS = 0.5

// EnrichImages annotates each image with its base differential.
//
// An image with no resolvable base is left alone rather than marked. Every CVE on
// it then reports an unknown origin, which is the honest answer: nothing was
// compared, so nothing is known about where its packages came from.
//
// An image whose measurement failed in this run is marked, with BaseDiffError,
// because that unknown is temporary and must not be acted on as if it were the
// standing kind.
func (e *BaseDiffEnricher) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	if e == nil || e.Resolver == nil {
		return nil
	}
	var work []int
	for i := range images {
		img := &images[i]
		// Nothing to attribute. Scanning a base for an image whose own scan failed
		// would spend a pull to compare against an empty set, and report every
		// base CVE as "not present in the app".
		if !img.Scanned || len(img.Vulns) == 0 {
			continue
		}
		if !hasBase(img.Upgrade) && !e.ScanExploited {
			continue
		}
		work = append(work, i)
	}
	if len(work) == 0 {
		metrics.BaseDifferential(0, 0)
		return nil
	}

	// Once per run, before any scan. A scanner that cannot run fails every scan
	// for the same reason, and saying so once beats saying it per base.
	if err := e.Resolver.Prepare(ctx); err != nil {
		failed := 0
		for _, i := range work {
			if hasBase(images[i].Upgrade) {
				images[i].BaseDiffError = "the base scanner could not run: " + err.Error()
				failed++
			}
		}
		slog.WarnContext(ctx, "base differential measured nothing this run: the scanner could not be "+
			"prepared, so no upgrade was measured and none will be ticketed on it; retried next run",
			"error", err, "images_unmeasured", failed, "images", len(images))
		metrics.BaseDifferential(0, failed)
		return nil
	}

	n := e.Concurrency
	if n <= 0 {
		n = 8
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	var measured, failed, missing atomic.Int64
	var firstErr atomic.Value
	invalid := &refSet{}

	for _, i := range work {
		img := &images[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			// The differential first: it decides which exploited CVEs the base
			// already explains, and those need no scan of the image to name.
			if hasBase(img.Upgrade) {
				switch out, err := e.diff(ctx, img, img.Upgrade, invalid); out {
				case diffMeasured:
					measured.Add(1)
				case diffFailed:
					failed.Add(1)
					firstErr.CompareAndSwap(nil, err.Error())
				case diffMissing:
					missing.Add(1)
				}
			}
			if e.ScanExploited {
				e.namePackages(ctx, img)
			}
		}()
	}
	wg.Wait()

	// Re-scans reported separately from scans: a run that re-read forty bases because
	// their scans had aged out has done different work from one that found forty new
	// ones, and a single count reads the same for both. Failures likewise, or a run in
	// which every base failed reports them all as scanned.
	slog.InfoContext(ctx, "base differential complete",
		"base_images_scanned", e.Resolver.Scanned(),
		"base_images_failed", e.Resolver.Failed(),
		"base_images_rescanned", e.Resolver.Rescanned(),
		"images_measured", measured.Load(), "images_unmeasured", failed.Load(),
		"images_base_missing", missing.Load(),
		"images_scanned_for_packages", e.imagesScanned.Load(), "images", len(images))
	if f := failed.Load(); f > 0 && f >= measured.Load() {
		// One line with one example, rather than relying on the per-base warnings:
		// on a broken scanner those are hundreds of copies of the same cause.
		slog.WarnContext(ctx, "base differential mostly failed this run: upgrades it could not measure "+
			"are held rather than ticketed until a run measures them",
			"images_unmeasured", f, "images_measured", measured.Load(), "first_error", firstErr.Load())
	}
	if refs := invalid.sorted(); len(refs) > 0 {
		// Once per run, naming every reference: each recurs every run until
		// patchwright or the image label producing it is fixed, and no registry
		// change will clear it.
		slog.WarnContext(ctx, "base references could not be parsed, so their images are unmeasurable "+
			"rather than held for a retry; this is a patchwright or image-label problem, not a registry one",
			"refs", refs)
	}
	metrics.BaseDifferential(int(measured.Load()), int(failed.Load()))
	return nil
}

// refSet collects references from concurrent diffs.
type refSet struct {
	mu   sync.Mutex
	refs map[string]bool
}

func (s *refSet) add(ref string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refs == nil {
		s.refs = map[string]bool{}
	}
	s.refs[ref] = true
}

func (s *refSet) sorted() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.refs))
	for r := range s.refs {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// hasBase reports an upgrade the differential can measure: a base-image move with
// the base the image was built on known.
func hasBase(up *model.Upgrade) bool {
	return up != nil && up.Kind == "base" && up.FromRef != ""
}

// diffOutcome is what one image's differential came to, for the run's accounting.
type diffOutcome int

const (
	diffMeasured diffOutcome = iota
	// diffFailed is a scan that failed this run; the image carries BaseDiffError.
	diffFailed
	// diffMissing is a base no retry will measure: one the registry says no
	// longer exists, or a reference that does not parse. Left unmarked, as
	// unmeasurable rather than unmeasured.
	diffMissing
)

// exploitedThreshold is the configured EPSS bound, or the default.
func (e *BaseDiffEnricher) exploitedThreshold() float64 {
	if e.ExploitedEPSS > 0 {
		return e.ExploitedEPSS
	}
	return DefaultExploitedEPSS
}

// wantsPackages reports whether this image carries an exploited, fixable CVE the
// base differential did not name a package for. Those are the CVEs a ticket will
// have to tell somebody to fix, so they are the ones worth a pull.
func (e *BaseDiffEnricher) wantsPackages(img *model.AssessedImage) bool {
	thr := e.exploitedThreshold()
	for _, v := range img.Vulns {
		if !v.FixAvailable || !(v.KEV || v.EPSS >= thr) {
			continue
		}
		if len(v.Packages) == 0 {
			return true
		}
	}
	return false
}

// namePackages scans the image itself and names the packages behind every CVE
// the base scan left unnamed.
//
// Every unnamed CVE is filled, not only the exploited ones: the pull has been
// paid for, and a package name on a non-exploited CVE costs nothing. It is the
// DECISION to pull that the exploited CVEs gate.
func (e *BaseDiffEnricher) namePackages(ctx context.Context, img *model.AssessedImage) {
	if !e.wantsPackages(img) {
		return
	}
	res, err := e.Resolver.Scan(ctx, img.Image.Ref)
	if err != nil {
		// Unnamed rather than failed, for the same reason an unreadable base is:
		// one image the scanner cannot pull should cost that image its package
		// names, not the run. PackagesScanned stays false, so a consumer can tell
		// "nothing looked" from "nothing found".
		slog.DebugContext(ctx, "exploited image scan failed", "image", img.Image.Ref, "err", err)
		return
	}
	e.imagesScanned.Add(1)
	img.PackagesScanned = true
	for i := range img.Vulns {
		if len(img.Vulns[i].Packages) > 0 {
			continue
		}
		img.Vulns[i].Packages = affected(res.CVEs[img.Vulns[i].ID])
	}
}

// affected converts scanned packages to the model, deduplicated and ordered so
// the same CVE renders identically between runs.
func affected(pkgs []basescan.Package) []model.AffectedPackage {
	if len(pkgs) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]model.AffectedPackage, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		// The path is part of the identity: the same package declared in two
		// lockfiles is two places to make the change.
		key := p.Ecosystem + "\x00" + p.Name + "\x00" + p.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.AffectedPackage{
			Name: p.Name, Ecosystem: p.Ecosystem, FixedIn: p.FixedVersion, Path: p.Path,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func (e *BaseDiffEnricher) diff(ctx context.Context, img *model.AssessedImage, up *model.Upgrade, invalid *refSet) (diffOutcome, error) {
	built, err := e.Resolver.Scan(ctx, up.FromRef)
	if basescan.Unmeasurable(err) {
		if errors.Is(err, basescan.ErrInvalidReference) {
			invalid.add(up.FromRef)
		}
		slog.DebugContext(ctx, "base image cannot be measured", "image", img.Image.Ref, "base", up.FromRef, "error", err)
		return diffMissing, nil
	}
	if err != nil {
		// Left undetermined rather than failed. One unreadable base should cost
		// its own images their attribution, not the run.
		img.BaseDiffError = "base scan failed: " + err.Error()
		return diffFailed, err
	}

	// A candidate is optional: the base may be current, or the recommendation may
	// belong to a deeper link in the chain. Ownership is answerable either way.
	var candidate *basescan.Result
	var candErr error
	if up.ToRef != "" {
		c, cerr := e.Resolver.Scan(ctx, up.ToRef)
		switch {
		case cerr == nil:
			candidate = c
		case errors.Is(cerr, basescan.ErrInvalidReference):
			invalid.add(up.ToRef)
		case !errors.Is(cerr, basescan.ErrNotFound):
			// Ownership still stands; only the upgrade went unmeasured.
			img.BaseDiffError = "candidate base scan failed: " + cerr.Error()
			candErr = cerr
		}
	}

	ids := make([]string, 0, len(img.Vulns))
	for _, v := range img.Vulns {
		ids = append(ids, v.ID)
	}
	verdicts, summary := basescan.Diff(ids, built, candidate)

	for i := range img.Vulns {
		v := verdicts[img.Vulns[i].ID]
		img.Vulns[i].Origin = string(v.Origin)
		img.Vulns[i].FixedByUpgrade = v.FixedByUpgrade
		img.Vulns[i].OriginDetermined = v.Determined
		// Only for CVEs the base scan actually found. An application-introduced
		// CVE lives in a layer nothing scanned, so naming a package for it would
		// be a guess, and the guess available is the one measured at 66% wrong.
		if v.Origin == basescan.OriginBase {
			img.Vulns[i].Packages = affected(built.CVEs[img.Vulns[i].ID])
		}
	}

	img.BaseDiff = &model.BaseDiff{
		FromRef:    built.Ref,
		OSFamily:   built.OSFamily,
		Total:      summary.Total,
		FromBase:   summary.FromBase,
		FromApp:    summary.FromApp,
		Unknown:    summary.Unknown,
		Clears:     summary.Clears,
		Leaves:     summary.Leaves,
		Introduces: summary.Introduces,
		Determined: candidate != nil,
	}
	if candidate != nil {
		img.BaseDiff.ToRef = candidate.Ref
	}
	if candErr != nil {
		return diffFailed, candErr
	}
	return diffMeasured, nil
}
