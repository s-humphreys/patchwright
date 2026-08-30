package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"

	"github.com/s-humphreys/patchwright/pkg/registryauth"
)

// craneInspector reads an image's own description of itself from the registry,
// authenticating with the ambient docker/cloud keychain — the same credentials the
// tag lister and the scanner use, so there is one thing to grant.
//
// Only the image *config* is fetched, a few KB, never the layers. An estate of a
// thousand images is a thousand small requests rather than a thousand image pulls.
type craneInspector struct{}

// NewRegistryInspector returns an inspector backed by the registry.
func NewRegistryInspector() ImageInspector { return craneInspector{} }

func (craneInspector) Config(ctx context.Context, ref string) (ImageConfig, error) {
	cfg, err := crane.Config(ref, crane.WithContext(ctx), crane.WithAuthFromKeychain(registryauth.Keychain()))
	if err != nil {
		return ImageConfig{}, fmt.Errorf("read image config for %s: %w", ref, err)
	}
	// crane.Config returns the raw config JSON; decode only what is needed.
	var parsed struct {
		Created string `json:"created"`
		Config  struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		return ImageConfig{}, fmt.Errorf("decode image config for %s: %w", ref, err)
	}
	out := ImageConfig{Labels: parsed.Config.Labels}
	// An unparseable or absent timestamp leaves Built zero rather than failing the
	// read: the labels are what remediation needs, and losing them over a
	// decorative field would cost an upgrade recommendation.
	if t, err := time.Parse(time.RFC3339, parsed.Created); err == nil && !t.IsZero() {
		out.Built = t
	}
	return out, nil
}

func (craneInspector) Digest(ctx context.Context, ref string) (string, error) {
	d, err := crane.Digest(ref, crane.WithContext(ctx), crane.WithAuthFromKeychain(registryauth.Keychain()))
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	return d, nil
}

// craneTagLister lists tags with the same ambient credentials.
type craneTagLister struct{}

// NewTagLister returns a registry-backed tag lister.
func NewTagLister() TagLister { return craneTagLister{} }

func (craneTagLister) Tags(ctx context.Context, repo string) ([]string, error) {
	return crane.ListTags(repo, crane.WithContext(ctx), crane.WithAuthFromKeychain(registryauth.Keychain()))
}

// CachingInspector memoises label reads for the length of a run.
//
// The base resolver and the in-flight enricher both read the image config of every
// first-party image, minutes apart, for different labels out of the same map. On an
// estate of 700 images that is two full passes over the registry for one pass worth
// of data.
//
// The cache is deliberately time-bounded rather than permanent. Entries are keyed by
// reference, and a tag can be republished — an application tag rebuilt, a floating
// base tag moved — so an entry that outlived the run would answer for an image that
// has been superseded, which is a wrong answer rather than a slow one. The TTL only
// has to cover a single assessment.
//
// Digests are not cached: they are the thing a floating-tag comparison is measuring,
// and the saving is not where the cost is.
type CachingInspector struct {
	Inner ImageInspector
	// TTL bounds how long a label read is reused. Zero means the default.
	TTL time.Duration

	mu      sync.Mutex
	entries map[string]labelEntry
}

type labelEntry struct {
	cfg ImageConfig
	err error
	at  time.Time
}

// defaultInspectTTL comfortably covers one assessment (the slowest observed pass over
// 700 images was four minutes) without spanning the next one.
const defaultInspectTTL = 15 * time.Minute

// NewCachingInspector wraps an inspector with a run-scoped label cache.
func NewCachingInspector(inner ImageInspector) *CachingInspector {
	return &CachingInspector{Inner: inner, entries: map[string]labelEntry{}}
}

func (c *CachingInspector) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return defaultInspectTTL
}

// Config returns the cached image config for a reference, reading through on a miss
// or an expired entry.
//
// Failures are cached too, and for the same reason the successes are: an unreadable
// image is unreadable for both callers, and retrying it per stage doubles the wait
// for an answer that will not change within a run.
func (c *CachingInspector) Config(ctx context.Context, ref string) (ImageConfig, error) {
	c.mu.Lock()
	e, ok := c.entries[ref]
	fresh := ok && time.Since(e.at) < c.ttl()
	c.mu.Unlock()
	if fresh {
		return e.cfg, e.err
	}

	cfg, err := c.Inner.Config(ctx, ref)
	c.mu.Lock()
	c.entries[ref] = labelEntry{cfg: cfg, err: err, at: time.Now()}
	c.mu.Unlock()
	return cfg, err
}

// Digest passes straight through: see the type comment.
func (c *CachingInspector) Digest(ctx context.Context, ref string) (string, error) {
	return c.Inner.Digest(ctx, ref)
}
