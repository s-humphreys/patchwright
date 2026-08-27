// Package upgrade implements upgrade sources: given how an image is deployed,
// what newer version is available.
package upgrade

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/support"
)

// Base-image upgrades, for images you build yourself.
//
// For a third-party image, "is there a fix" is answered by the registry: is there a
// newer tag. For a first-party application image it is not. Its tags are release
// numbers, and a newer one means somebody shipped application code, which says nothing
// about the CVEs — those live in the base image. Reporting "1.0.79 -> 1.0.80" as
// remediation is worse than reporting nothing, because it looks like an answer.
//
// So the question becomes: what base does this image draw from, and has that base
// moved? Images record it themselves. A spec-compliant builder writes
// org.opencontainers.image.base.name; BuildKit writes image.base.ref.name; some
// organisations set a label by hand. Which keys to read is configuration, because
// guessing is a silent wrong answer.
//
// Nothing here knows about any particular registry or naming convention. What counts
// as first-party, which labels to read and how far to follow a chain are all config.

// ImageInspector reads what an image says about itself. Implemented against a
// registry; a fake in tests.
type ImageInspector interface {
	// Labels returns the image config labels for a reference.
	Labels(ctx context.Context, ref string) (map[string]string, error)
	// Digest returns the digest a reference currently resolves to, for comparing a
	// floating tag against the digest an image was built from.
	Digest(ctx context.Context, ref string) (string, error)
}

// BaseResolver reports base-image upgrades for first-party images.
type BaseResolver struct {
	Cfg       config.RemediationConfig
	Inspector ImageInspector
	// Lister lists tags for a repository, shared with the image-tag source.
	Lister TagLister
	// Concurrency bounds registry calls in flight. Zero means the default.
	Concurrency int
	// Support resolves maintenance windows for the lines base images sit on. Optional:
	// nil means support status is not checked, and every finding then reports it as
	// unchecked rather than as supported.
	Support support.Source
	// Now is the day support windows are judged against, injectable so a test can
	// assert on a fixed date rather than on whatever today happens to be.
	Now func() time.Time
}

// now returns the day to judge support windows against.
func (r *BaseResolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// TagLister lists the tags of a repository.
type TagLister interface {
	Tags(ctx context.Context, repo string) ([]string, error)
}

// NewBaseResolver builds a resolver from configuration.
func NewBaseResolver(cfg config.RemediationConfig, inspector ImageInspector, lister TagLister) *BaseResolver {
	return &BaseResolver{Cfg: cfg, Inspector: inspector, Lister: lister}
}

// Upgrades reports, per first-party image, whether its base image has a newer
// version. Third-party images are left to the image-tag source.
func (r *BaseResolver) Upgrades(ctx context.Context, images []model.AssessedImage) (map[string]model.Upgrade, error) {
	out := map[string]model.Upgrade{}
	if len(r.Cfg.FirstPartyRegistries) == 0 {
		// Nothing is first-party, so there is no base question to ask. Not an error:
		// a deployment running only other people's images is the common case.
		return out, nil
	}

	// One config read per image, and an estate is hundreds of images, so these run
	// concurrently. Serially this took tens of minutes on a real estate,
	// which is longer than the refresh interval it has to fit inside.
	var todo []string
	for i := range images {
		if r.Cfg.IsFirstParty(images[i].Image.Registry) {
			todo = append(todo, images[i].Image.NameTag())
		}
	}
	if len(todo) == 0 {
		return out, nil
	}

	c := &baseCache{answers: map[string]*baseAnswer{}}
	var mu sync.Mutex
	sem := make(chan struct{}, r.concurrency())
	var wg sync.WaitGroup

	for _, ref := range todo {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return out, ctx.Err()
		}
		wg.Add(1)
		go func(ref string) {
			defer wg.Done()
			defer func() { <-sem }()
			up, err := r.answer(ctx, ref, c)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// One unreadable image must not lose the rest: it is reported as
				// unresolved, which is a coverage gap rather than "no upgrade".
				slog.DebugContext(ctx, "base image lookup failed", "image", ref, "error", err)
				out[ref] = unresolvedUpgrade(err.Error())
				return
			}
			out[ref] = up
		}(ref)
	}
	wg.Wait()

	var resolved int
	for _, u := range out {
		if u.Resolved {
			resolved++
		}
	}
	slog.InfoContext(ctx, "base image upgrades resolved",
		"first_party_images", len(out), "resolved", resolved, "unresolved", len(out)-resolved)
	return out, nil
}

// Concurrency bounds the registry calls in flight. Registries rate-limit, and the
// work is latency-bound rather than CPU-bound, so this is well above GOMAXPROCS.
const defaultConcurrency = 12

func (r *BaseResolver) concurrency() int {
	if r.Concurrency > 0 {
		return r.Concurrency
	}
	return defaultConcurrency
}

// answer resolves one image, sharing work with concurrent callers.
func (r *BaseResolver) answer(ctx context.Context, ref string, c *baseCache) (model.Upgrade, error) {
	ans, err := r.resolve(ctx, ref, c, 0)
	if err != nil {
		return model.Upgrade{}, err
	}
	return ans.upgrade, nil
}

// baseCache shares resolved answers across images. One base is commonly shared by
// hundreds of images, a large share of them sharing one base, and the answer
// for it is identical every time.
type baseCache struct {
	mu      sync.Mutex
	answers map[string]*baseAnswer
}

func (c *baseCache) get(ref string) (*baseAnswer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.answers[ref]
	return a, ok
}

func (c *baseCache) put(ref string, a *baseAnswer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.answers[ref] = a
}

// baseAnswer is a cached verdict for one image reference.
type baseAnswer struct {
	upgrade model.Upgrade
}

// resolve finds the first outdated link in an image's chain of first-party bases.
//
// The first outdated link is the actionable one: if an application sits on a base
// that is itself behind, the application's move is to the newest base it can use, and
// the base's own staleness belongs to whoever builds it.
func (r *BaseResolver) resolve(ctx context.Context, ref string, cache *baseCache, depth int) (*baseAnswer, error) {
	if ans, ok := cache.get(ref); ok {
		return ans, nil
	}
	if depth >= r.Cfg.Base.EffectiveMaxDepth() {
		// A chain this long is more likely a loop or a mistake than a real build.
		return &baseAnswer{upgrade: unresolvedUpgrade(fmt.Sprintf(
			"base image chain deeper than %d hops", r.Cfg.Base.EffectiveMaxDepth()))}, nil
	}

	labels, err := r.Inspector.Labels(ctx, ref)
	if err != nil {
		return nil, err
	}
	baseRef := firstLabel(labels, r.Cfg.Base.EffectiveRefLabels())
	if baseRef == "" {
		// The image does not say what it was built from. The fix is a build-system
		// change — emit the label — so say that rather than "no upgrade available".
		ans := &baseAnswer{upgrade: unresolvedUpgrade(
			"image records no base image; add one of " +
				strings.Join(r.Cfg.Base.EffectiveRefLabels(), " or ") + " at build time")}
		cache.put(ref, ans)
		return ans, nil
	}

	base := model.ParseImageRef(baseRef)
	up, err := r.baseUpgrade(ctx, base, firstLabel(labels, r.Cfg.Base.EffectiveDigestLabels()))
	if err != nil {
		return nil, err
	}
	// The base has moved: this image's remediation is to rebuild on it, whatever the
	// rest of the chain looks like.
	if up.Available {
		ans := &baseAnswer{upgrade: up}
		cache.put(ref, ans)
		return ans, nil
	}

	// The base is current. If it is itself first-party, the chain continues: being on
	// the newest available base is not the same as that base being up to date.
	if r.Cfg.IsFirstParty(base.Registry) {
		deeper, derr := r.resolve(ctx, base.NameTag(), cache, depth+1)
		if derr == nil && deeper.upgrade.Available {
			// Reported against this image, but naming the link that is actually
			// behind, so the ticket lands on whoever can move it.
			ans := &baseAnswer{upgrade: deeper.upgrade}
			cache.put(ref, ans)
			return ans, nil
		}
	}

	ans := &baseAnswer{upgrade: up}
	cache.put(ref, ans)
	return ans, nil
}

// baseUpgrade decides whether a base reference has a newer version.
func (r *BaseResolver) baseUpgrade(ctx context.Context, base model.Image, builtDigest string) (model.Upgrade, error) {
	up := model.Upgrade{
		Kind: "base",
		// Registry included: a bare "dotnet/aspnet" is ambiguous between an internal
		// mirror and the upstream it was copied from, and those are different images
		// with different owners.
		Name:    base.Registry + "/" + base.Repository,
		Current: base.Tag,
		// Rebuilding is the application's own pipeline, so this is directly
		// actionable by the team that owns the image.
		Actionable: true,
		Source:     base.NameTag(),
	}

	current, err := semver.StrictNewVersion(strings.TrimPrefix(base.Tag, "v"))
	if err != nil {
		// A floating tag has no version to compare, so the question becomes whether
		// the tag still resolves to the digest this image was built from.
		return r.floatingBase(ctx, base, builtDigest, up)
	}

	tags, err := r.Lister.Tags(ctx, base.Registry+"/"+base.Repository)
	if err != nil {
		return unresolvedUpgrade("could not list tags for base " + base.NameTag() + ": " + err.Error()), nil
	}
	up.Resolved = true
	up.Comparison = "version"

	// Two answers: how far policy says to move, and how far it is possible to move.
	// Reporting only the first hides a decision; reporting only the second asks for
	// work the team has already said it cannot take.
	strategy, ceiling, reason, expired := r.Cfg.Upgrade.For(up.Name)
	up.Strategy, up.Ceiling, up.CeilingReason, up.CeilingExpired = strategy, ceiling, reason, expired
	recommended := newestWithin(current, tags, strategy, ceiling)
	newest := newestWithin(current, tags, "latest", "")
	if recommended != nil {
		up.Latest = recommended.Original()
		up.Available = true
	}
	if newest != nil {
		up.Newest = newest.Original()
		// Only worth saying when it differs: "3.12.14, newest 3.12.14" is noise.
		if recommended == nil || newest.Original() == recommended.Original() {
			up.Newest = ""
		}
	}
	// Held back with nothing to offer is its own state: there IS a newer version, and
	// policy says not this one. Silence here would read as "already up to date".
	if recommended == nil && newest != nil {
		up.HeldBack = true
	}

	up.Support = r.supportStatus(ctx, base, r.now())
	// An exhausted track on a dead line has no in-track answer by definition, so the
	// only upgrade that helps crosses the line. Applied only when nothing in-track was
	// found: while the line still has newer patches, the safe rebuild is the better
	// first move and a migration can follow.
	if !up.Available {
		up = r.offTrackUpgrade(ctx, base, up)
	}
	return up, nil
}

// floatingBase compares digests when the base tag carries no version.
func (r *BaseResolver) floatingBase(ctx context.Context, base model.Image, builtDigest string, up model.Upgrade) (model.Upgrade, error) {
	if builtDigest == "" {
		return unresolvedUpgrade(fmt.Sprintf(
			"base %s has no comparable version and the image records no base digest",
			base.NameTag())), nil
	}
	now, err := r.Inspector.Digest(ctx, base.NameTag())
	if err != nil {
		return unresolvedUpgrade("could not resolve base " + base.NameTag() + ": " + err.Error()), nil
	}
	up.Resolved = true
	up.Comparison = "digest"
	// The case this exists for. A dead line's tag never moves again, so the digest
	// comparison below can only ever say "no change" - which is indistinguishable
	// from being current unless the support status is carried too.
	up.Support = r.supportStatus(ctx, base, r.now())
	up = r.offTrackUpgrade(ctx, base, up)
	if up.OutOfTrack {
		return up, nil
	}
	if now != builtDigest {
		// The tag moved under it. There is no version to name, so the digest is the
		// evidence: a rebuild would pick this up.
		up.Latest = shortDigest(now)
		up.Current = shortDigest(builtDigest)
		up.Available = true
	}
	return up, nil
}

// newestInTrack returns the newest tag on the same track as the current version.
//
// A track is the same major AND the same suffix. Both restrictions come from real
// data:
//
// Major, because a repository can hold several language versions at once, and taking
// the newest overall would present a framework migration as a patch.
//
// Suffix, because base images use the semver prerelease slot to mark a variant, not a
// prerelease: a distro-specific tag like 10.0.3-azurelinux3.0 sorts below the plain
// 10.0.11 by semver rules, so a naive comparison recommends swapping the operating
// system underneath the application and calls it a patch. Only tags carrying the same
// suffix are candidates, so azurelinux stays on azurelinux.
func newestInTrack(current *semver.Version, tags []string) *semver.Version {
	return newestWithin(current, tags, "latest", "")
}

// newestWithin picks the furthest version a strategy and ceiling allow.
//
// Strategy is about compatibility, and where the boundary sits depends on what is
// being upgraded. For an OS package "newest" is nearly always right. For a language
// runtime the MINOR is the boundary: 3.12 to 3.14 is a migration whose blast radius
// is somebody's whole dependency tree, while 3.12.3 to 3.12.14 is a rebuild that
// picks up the same patched packages and breaks nothing.
//
// Recommending the migration when the patch would do is not a harmless overshoot. The
// team cannot take it, so the finding sits in the queue looking like neglect, and the
// patch that would have closed the CVEs never gets made.
func newestWithin(current *semver.Version, tags []string, strategy, ceiling string) *semver.Version {
	var best *semver.Version
	for _, t := range tags {
		v, err := semver.StrictNewVersion(strings.TrimPrefix(t, "v"))
		if err != nil {
			continue
		}
		// A distro suffix lives in the prerelease slot, so the same suffix means the
		// same variant: staying on it is not optional, it is the operating system.
		if v.Major() != current.Major() || v.Prerelease() != current.Prerelease() {
			continue
		}
		if strategy == "patch" && v.Minor() != current.Minor() {
			continue
		}
		if !withinCeiling(v, ceiling) {
			continue
		}
		if !v.GreaterThan(current) {
			continue
		}
		if best == nil || v.GreaterThan(best) {
			best = v
		}
	}
	return best
}

// withinCeiling reports whether a version is at or below a version prefix ("3.12").
// An unparseable ceiling constrains nothing rather than everything: a typo must not
// silently stop an estate from being told about upgrades.
func withinCeiling(v *semver.Version, ceiling string) bool {
	ceiling = strings.TrimSpace(strings.TrimPrefix(ceiling, "v"))
	if ceiling == "" {
		return true
	}
	parts := strings.Split(ceiling, ".")
	major, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return true
	}
	if v.Major() != major {
		return v.Major() < major
	}
	if len(parts) < 2 {
		return true
	}
	minor, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return true
	}
	if v.Minor() != minor {
		return v.Minor() < minor
	}
	if len(parts) < 3 {
		return true
	}
	patch, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return true
	}
	return v.Patch() <= patch
}

// unresolvedUpgrade records that the question could not be answered, with the reason.
// Never "no upgrade available": those are different answers and only one of them is
// safe to act on.
func unresolvedUpgrade(reason string) model.Upgrade {
	return model.Upgrade{Kind: "base", Resolved: false, Reason: reason}
}

func firstLabel(labels map[string]string, keys []string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(labels[k]); v != "" {
			return v
		}
	}
	return ""
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// compile-time check that this satisfies the enricher's source interface.
var _ enrich.UpgradeSource = (*BaseResolver)(nil)
