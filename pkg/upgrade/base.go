// Package upgrade implements upgrade sources: given how an image is deployed,
// what newer version is available.
package upgrade

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
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
	// concurrently. Serially this took eighteen minutes on a real estate of 707,
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
// hundreds of images — 183 of one estate's 707 sat on a single base — and the answer
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
	if latest := newestInTrack(current, tags); latest != nil {
		up.Latest = latest.Original()
		up.Available = true
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
	var best *semver.Version
	for _, t := range tags {
		v, err := semver.StrictNewVersion(strings.TrimPrefix(t, "v"))
		if err != nil {
			continue
		}
		if v.Major() != current.Major() || v.Prerelease() != current.Prerelease() {
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
