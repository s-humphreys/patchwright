package enrich

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"

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
func (e *BaseDiffEnricher) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	if e == nil || e.Resolver == nil {
		return nil
	}
	n := e.Concurrency
	if n <= 0 {
		n = 8
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup

	for i := range images {
		img := &images[i]
		// Nothing to attribute. Scanning a base for an image whose own scan failed
		// would spend a pull to compare against an empty set, and report every
		// base CVE as "not present in the app".
		if !img.Scanned || len(img.Vulns) == 0 {
			continue
		}
		up := img.Upgrade
		hasBase := up != nil && up.Kind == "base" && up.FromRef != ""
		if !hasBase && !e.ScanExploited {
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
			// The differential first: it decides which exploited CVEs the base
			// already explains, and those need no scan of the image to name.
			if hasBase {
				e.diff(ctx, img, up)
			}
			if e.ScanExploited {
				e.namePackages(ctx, img)
			}
		}()
	}
	wg.Wait()

	// Re-scans reported separately from scans: a run that re-read forty bases because
	// their scans had aged out has done different work from one that found forty new
	// ones, and a single count reads the same for both.
	slog.InfoContext(ctx, "base differential complete",
		"base_images_scanned", e.Resolver.Scanned(),
		"base_images_rescanned", e.Resolver.Rescanned(),
		"images_scanned_for_packages", e.imagesScanned.Load(), "images", len(images))
	return nil
}

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

func (e *BaseDiffEnricher) diff(ctx context.Context, img *model.AssessedImage, up *model.Upgrade) {
	built, err := e.Resolver.Scan(ctx, up.FromRef)
	if err != nil {
		// Left undetermined rather than failed. One unreadable base should cost
		// its own images their attribution, not the run.
		return
	}

	// A candidate is optional: the base may be current, or the recommendation may
	// belong to a deeper link in the chain. Ownership is answerable either way.
	var candidate *basescan.Result
	if up.ToRef != "" {
		if c, cerr := e.Resolver.Scan(ctx, up.ToRef); cerr == nil {
			candidate = c
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
}
