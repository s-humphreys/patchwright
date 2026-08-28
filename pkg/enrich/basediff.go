package enrich

import (
	"context"
	"log/slog"
	"sort"
	"sync"

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
}

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
		up := img.Upgrade
		if up == nil || up.Kind != "base" || up.FromRef == "" {
			continue
		}
		// Nothing to attribute. Scanning a base for an image whose own scan failed
		// would spend a pull to compare against an empty set, and report every
		// base CVE as "not present in the app".
		if !img.Scanned || len(img.Vulns) == 0 {
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
			e.diff(ctx, img, up)
		}()
	}
	wg.Wait()

	slog.InfoContext(ctx, "base differential complete",
		"base_images_scanned", e.Resolver.Scanned(), "images", len(images))
	return nil
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
		key := p.Ecosystem + "\x00" + p.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.AffectedPackage{
			Name: p.Name, Ecosystem: p.Ecosystem, FixedIn: p.FixedVersion,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
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
