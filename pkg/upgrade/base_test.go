package upgrade

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// fakeRegistry answers with whatever a test puts in it. Registry names here are
// deliberately generic: nothing in the resolver knows about any real registry.
// Upgrades resolves images concurrently, so `asked` is written from several
// goroutines at once. Unguarded it is a real data race that -race catches only
// sometimes, which is the worst kind: it failed one run in eight and looked like
// a flaky test rather than a broken double.
type fakeRegistry struct {
	labels  map[string]map[string]string
	built   map[string]time.Time
	digests map[string]string
	tags    map[string][]string
	err     error

	mu    sync.Mutex
	asked []string
}

// askedFor returns a copy of the references looked up, safe to read after a
// concurrent resolve.
func (f *fakeRegistry) askedFor() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

func (f *fakeRegistry) Config(_ context.Context, ref string) (ImageConfig, error) {
	f.mu.Lock()
	f.asked = append(f.asked, ref)
	f.mu.Unlock()
	if f.err != nil {
		return ImageConfig{}, f.err
	}
	l, ok := f.labels[ref]
	if !ok {
		return ImageConfig{}, errors.New("not found: " + ref)
	}
	return ImageConfig{Labels: l, Built: f.built[ref]}, nil
}

func (f *fakeRegistry) Digest(_ context.Context, ref string) (string, error) {
	d, ok := f.digests[ref]
	if !ok {
		return "", errors.New("no digest for " + ref)
	}
	return d, nil
}

func (f *fakeRegistry) Tags(_ context.Context, repo string) ([]string, error) {
	return f.tags[repo], nil
}

func cfgFor(registries ...string) config.RemediationConfig {
	return config.RemediationConfig{FirstPartyRegistries: registries}
}

func img(ref string) model.AssessedImage {
	return model.AssessedImage{Image: model.ParseImageRef(ref)}
}

func resolve(t *testing.T, reg *fakeRegistry, cfg config.RemediationConfig, refs ...string) map[string]model.Upgrade {
	t.Helper()
	images := make([]model.AssessedImage, 0, len(refs))
	for _, r := range refs {
		images = append(images, img(r))
	}
	got, err := NewBaseResolver(cfg, reg, reg).Upgrades(context.Background(), images)
	if err != nil {
		t.Fatalf("Upgrades: %v", err)
	}
	return got
}

// The core case: the application tag is a release number, the fix is the base.
func TestReportsANewerBaseImage(t *testing.T) {
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/app:1.0.79":    {"image.base.ref.name": "registry.example.com/runtime:1.0.5"},
			"registry.example.com/runtime:1.0.5": {},
		},
		tags: map[string][]string{"registry.example.com/runtime": {"1.0.4", "1.0.5", "1.1.0", "1.1.1"}},
	}
	got := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:1.0.79")

	u, ok := got["registry.example.com/app:1.0.79"]
	if !ok {
		t.Fatalf("no upgrade reported: %+v", got)
	}
	if u.Kind != "base" || !u.Available || !u.Resolved {
		t.Fatalf("upgrade = %+v", u)
	}
	if u.Current != "1.0.5" || u.Latest != "1.1.1" {
		t.Errorf("reported %s -> %s, want 1.0.5 -> 1.1.1", u.Current, u.Latest)
	}
	// Rebuilding is the owning team's own pipeline, so this is theirs to do.
	if !u.Actionable {
		t.Error("a base bump was reported as not actionable")
	}
}

// A repository can hold several tracks at once. Taking the newest overall would
// present a major migration as a patch.
func TestNewerMajorIsNotReportedAsTheUpgrade(t *testing.T) {
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/app:2.0.0":      {"image.base.ref.name": "registry.example.com/runtime:8.0.13"},
			"registry.example.com/runtime:8.0.13": {},
		},
		tags: map[string][]string{"registry.example.com/runtime": {
			"8.0.13", "8.0.17", "10.0.0", "10.0.1",
		}},
	}
	got := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:2.0.0")

	u := got["registry.example.com/app:2.0.0"]
	if u.Latest != "8.0.17" {
		t.Errorf("latest = %q, want 8.0.17 — a newer major is a migration, not this upgrade", u.Latest)
	}
}

// An image that never recorded its base has an unanswered question, not a clean
// bill of health. The reason has to name the fix, which is a build-system change.
func TestMissingBaseLabelIsUnresolvedWithAReason(t *testing.T) {
	reg := &fakeRegistry{labels: map[string]map[string]string{
		"registry.example.com/app:1.0.0": {"some.other.label": "x"},
	}}
	got := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:1.0.0")

	u := got["registry.example.com/app:1.0.0"]
	if u.Resolved {
		t.Error("an image with no base label was reported as resolved")
	}
	if u.Available {
		t.Error("an unresolved upgrade claimed one was available")
	}
	for _, want := range []string{"records no base", "org.opencontainers.image.base.name"} {
		if !strings.Contains(u.Reason, want) {
			t.Errorf("reason does not mention %q: %q", want, u.Reason)
		}
	}
}

// Third-party images are somebody else's release cadence: the tag source handles
// them, and this must not touch them.
func TestThirdPartyImagesAreLeftAlone(t *testing.T) {
	reg := &fakeRegistry{labels: map[string]map[string]string{}}
	got := resolve(t, reg, cfgFor("registry.example.com"),
		"docker.io/library/nginx:1.27.0", "quay.io/prometheus/prometheus:v3.0.0")
	if len(got) != 0 {
		t.Errorf("reported upgrades for third-party images: %+v", got)
	}
	if len(reg.askedFor()) != 0 {
		t.Errorf("inspected third-party images: %v", reg.askedFor())
	}
}

// With nothing declared first-party there is no base question to ask, and no
// registry calls to make.
func TestNoFirstPartyRegistriesIsANoOp(t *testing.T) {
	reg := &fakeRegistry{}
	got := resolve(t, reg, config.RemediationConfig{}, "registry.example.com/app:1.0.0")
	if len(got) != 0 || len(reg.askedFor()) != 0 {
		t.Errorf("did work with no first-party registries configured: %+v %v", got, reg.askedFor())
	}
}

// Chains of first-party bases exist. Being on the newest available base is not the
// same as that base being current.
func TestFollowsFirstPartyBaseChains(t *testing.T) {
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			// The app is on the newest "extras" base...
			"registry.example.com/app:1.0.0": {"image.base.ref.name": "registry.example.com/extras:2.0.0"},
			// ...but that base is itself behind.
			"registry.example.com/extras:2.0.0":  {"image.base.ref.name": "registry.example.com/runtime:1.1.0"},
			"registry.example.com/runtime:1.1.0": {},
		},
		tags: map[string][]string{
			"registry.example.com/extras":  {"1.0.0", "2.0.0"},
			"registry.example.com/runtime": {"1.1.0", "1.1.1"},
		},
	}
	got := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:1.0.0")

	u := got["registry.example.com/app:1.0.0"]
	if !u.Available {
		t.Fatalf("chain not followed: %+v", u)
	}
	// The link that is actually behind is the one to name, so the ticket reaches
	// whoever can move it.
	// Registry-qualified: "runtime" alone is ambiguous between an internal mirror and
	// the upstream it was copied from.
	if u.Name != "registry.example.com/runtime" || u.Latest != "1.1.1" {
		t.Errorf("reported %s -> %s on %q, want registry.example.com/runtime 1.1.0 -> 1.1.1",
			u.Current, u.Latest, u.Name)
	}
}

// The walk stops at a third-party base: upstream's release cadence is not ours to
// chase through.
func TestChainStopsAtThirdPartyBase(t *testing.T) {
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/app:1.0.0":     {"image.base.ref.name": "registry.example.com/runtime:1.1.1"},
			"registry.example.com/runtime:1.1.1": {"image.base.ref.name": "mcr.example.com/dotnet/runtime:10.0.11"},
		},
		tags: map[string][]string{"registry.example.com/runtime": {"1.1.0", "1.1.1"}},
	}
	got := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:1.0.0")

	u := got["registry.example.com/app:1.0.0"]
	if u.Available {
		t.Errorf("claimed an upgrade past a third-party boundary: %+v", u)
	}
	if !u.Resolved {
		t.Errorf("a current base was reported unresolved: %+v", u)
	}
	for _, ref := range reg.askedFor() {
		if strings.HasPrefix(ref, "mcr.example.com/") {
			t.Errorf("inspected a third-party base: %s", ref)
		}
	}
}

// A floating base tag has no version to compare, so the digest decides.
func TestFloatingBaseTagComparesDigests(t *testing.T) {
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/app:1.0.0": {
				"image.base.ref.name": "registry.example.com/runtime:stable",
				"image.base.digest":   "sha256:aaaaaaaaaaaaaaaa",
			},
		},
		digests: map[string]string{"registry.example.com/runtime:stable": "sha256:bbbbbbbbbbbbbbbb"},
	}
	got := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:1.0.0")

	u := got["registry.example.com/app:1.0.0"]
	if !u.Resolved || !u.Available {
		t.Fatalf("a moved floating tag was not reported: %+v", u)
	}
	if !strings.HasPrefix(u.Latest, "bbbb") || !strings.HasPrefix(u.Current, "aaaa") {
		t.Errorf("digests not reported as the versions: %s -> %s", u.Current, u.Latest)
	}
}

// Same digest means the base has not moved, which is a real answer rather than an
// unknown.
func TestFloatingBaseTagUnchangedIsCurrent(t *testing.T) {
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/app:1.0.0": {
				"image.base.ref.name": "registry.example.com/runtime:stable",
				"image.base.digest":   "sha256:aaaaaaaaaaaaaaaa",
			},
		},
		digests: map[string]string{"registry.example.com/runtime:stable": "sha256:aaaaaaaaaaaaaaaa"},
	}
	u := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:1.0.0")["registry.example.com/app:1.0.0"]
	if !u.Resolved || u.Available {
		t.Errorf("an unchanged base was misreported: %+v", u)
	}
}

// A floating tag with no recorded digest cannot be judged either way.
func TestFloatingBaseWithoutADigestIsUnresolved(t *testing.T) {
	reg := &fakeRegistry{labels: map[string]map[string]string{
		"registry.example.com/app:1.0.0": {"image.base.ref.name": "registry.example.com/runtime:stable"},
	}}
	u := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:1.0.0")["registry.example.com/app:1.0.0"]
	if u.Resolved || u.Available {
		t.Errorf("upgrade = %+v, want unresolved", u)
	}
	if !strings.Contains(u.Reason, "no comparable version") {
		t.Errorf("reason = %q", u.Reason)
	}
}

// The OCI standard key wins over the vendor one, so a spec-compliant build is read
// the way the spec intends.
func TestStandardLabelTakesPrecedence(t *testing.T) {
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/app:1.0.0": {
				"org.opencontainers.image.base.name": "registry.example.com/standard:1.0.0",
				"image.base.ref.name":                "registry.example.com/vendor:1.0.0",
			},
			"registry.example.com/standard:1.0.0": {},
		},
		tags: map[string][]string{"registry.example.com/standard": {"1.0.0", "1.0.1"}},
	}
	u := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:1.0.0")["registry.example.com/app:1.0.0"]
	if u.Name != "registry.example.com/standard" {
		t.Errorf("read %q, want the OCI standard label to win", u.Name)
	}
}

// Label keys are configuration: an organisation with its own convention names it
// rather than patching the tool.
func TestLabelKeysAreConfigurable(t *testing.T) {
	cfg := cfgFor("registry.example.com")
	cfg.Base.RefLabels = []string{"com.acme.base"}
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/app:1.0.0":     {"com.acme.base": "registry.example.com/runtime:1.0.0"},
			"registry.example.com/runtime:1.0.0": {},
		},
		tags: map[string][]string{"registry.example.com/runtime": {"1.0.0", "1.0.1"}},
	}
	u := resolve(t, reg, cfg, "registry.example.com/app:1.0.0")["registry.example.com/app:1.0.0"]
	if !u.Available || u.Latest != "1.0.1" {
		t.Errorf("a custom label key was not honoured: %+v", u)
	}
}

// One unreadable image must not cost the rest of the estate.
func TestAnUnreadableImageIsReportedNotFatal(t *testing.T) {
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/ok:1.0.0":      {"image.base.ref.name": "registry.example.com/runtime:1.0.0"},
			"registry.example.com/runtime:1.0.0": {},
		},
		tags: map[string][]string{"registry.example.com/runtime": {"1.0.0", "1.0.1"}},
	}
	got := resolve(t, reg, cfgFor("registry.example.com"),
		"registry.example.com/ok:1.0.0", "registry.example.com/missing:9.9.9")

	if u := got["registry.example.com/ok:1.0.0"]; !u.Available {
		t.Errorf("a readable image was not resolved: %+v", u)
	}
	u := got["registry.example.com/missing:9.9.9"]
	if u.Resolved || u.Reason == "" {
		t.Errorf("an unreadable image was not reported with a reason: %+v", u)
	}
}

// A cycle, or a chain longer than configured, must terminate rather than recurse.
func TestChainDepthIsBounded(t *testing.T) {
	cfg := cfgFor("registry.example.com")
	cfg.Base.MaxDepth = 2
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/a:1.0.0": {"image.base.ref.name": "registry.example.com/b:1.0.0"},
			"registry.example.com/b:1.0.0": {"image.base.ref.name": "registry.example.com/c:1.0.0"},
			"registry.example.com/c:1.0.0": {"image.base.ref.name": "registry.example.com/a:1.0.0"},
		},
		tags: map[string][]string{
			"registry.example.com/a": {"1.0.0"},
			"registry.example.com/b": {"1.0.0"},
			"registry.example.com/c": {"1.0.0"},
		},
	}
	done := make(chan struct{})
	go func() {
		resolve(t, reg, cfg, "registry.example.com/a:1.0.0")
		close(done)
	}()
	select {
	case <-done:
	case <-context.Background().Done():
	}
}

// Base images use the semver prerelease slot to mark a variant, not a prerelease.
// Found on real data: 10.0.3-azurelinux3.0 was "upgraded" to 10.0.11, which swaps the
// operating system underneath the application and calls it a patch.
func TestVariantSuffixIsTreatedAsATrack(t *testing.T) {
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/app:1.0.0": {
				"image.base.ref.name": "mcr.example.com/runtime:10.0.3-distro3.0",
			},
		},
		tags: map[string][]string{"mcr.example.com/runtime": {
			"10.0.3-distro3.0", "10.0.11-distro3.0", "10.0.11", "10.0.12",
		}},
	}
	u := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:1.0.0")["registry.example.com/app:1.0.0"]
	if u.Latest != "10.0.11-distro3.0" {
		t.Errorf("latest = %q, want 10.0.11-distro3.0 — the same variant, not a distro change", u.Latest)
	}
}

// The reverse: a plain tag must not be dragged onto a variant.
func TestPlainTagStaysPlain(t *testing.T) {
	reg := &fakeRegistry{
		labels: map[string]map[string]string{
			"registry.example.com/app:1.0.0": {"image.base.ref.name": "mcr.example.com/runtime:10.0.3"},
		},
		tags: map[string][]string{"mcr.example.com/runtime": {"10.0.3", "10.0.4", "10.0.20-distro3.0"}},
	}
	u := resolve(t, reg, cfgFor("registry.example.com"), "registry.example.com/app:1.0.0")["registry.example.com/app:1.0.0"]
	if u.Latest != "10.0.4" {
		t.Errorf("latest = %q, want 10.0.4", u.Latest)
	}
}
