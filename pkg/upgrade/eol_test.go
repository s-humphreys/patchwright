package upgrade

import (
	"context"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/support"
)

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// eolSupport stands in for endoflife.date with the real Node situation.
type eolSupport struct {
	err     error
	product support.Product
}

func (s eolSupport) Name() string { return "stub" }
func (s eolSupport) Product(context.Context, string) (support.Product, error) {
	if s.err != nil {
		return support.Product{}, s.err
	}
	return s.product, nil
}

func nodeSupport() eolSupport {
	return eolSupport{product: support.Product{Name: "nodejs", Cycles: []support.Cycle{
		{Name: "20", EOL: day("2026-04-30"), EOLKnown: true, LTS: day("2023-10-24"), HasLTS: true},
		{Name: "22", EOL: day("2027-04-30"), EOLKnown: true, LTS: day("2024-10-29"), HasLTS: true},
		{Name: "24", EOL: day("2028-04-30"), EOLKnown: true, LTS: day("2025-10-28"), HasLTS: true},
		{Name: "26", EOL: day("2029-04-30"), EOLKnown: true, LTS: day("2026-10-28"), HasLTS: true},
	}}}
}

// eolLister serves a fixed tag list.
type eolLister struct {
	tags []string
	err  error
}

func (s eolLister) Tags(context.Context, string) ([]string, error) { return s.tags, s.err }

// eolInspector reports a base image label and a digest that never moves, which is what
// a dead line looks like from the registry.
type eolInspector struct {
	labels map[string]string
}

func (s eolInspector) Config(context.Context, string) (ImageConfig, error) {
	return ImageConfig{Labels: s.labels}, nil
}

// Digest never changes, which is exactly what a dead line looks like: the tag is
// published once and then abandoned.
func (s eolInspector) Digest(context.Context, string) (string, error) {
	return "sha256:unchanged", nil
}

func nodeResolver(t *testing.T, sup support.Source, tags []string) *BaseResolver {
	t.Helper()
	return &BaseResolver{
		Cfg: config.RemediationConfig{
			FirstPartyRegistries: []string{"example.azurecr.io"},
		},
		Inspector: eolInspector{labels: map[string]string{
			"org.opencontainers.image.base.name":   "docker.io/node:20-alpine",
			"org.opencontainers.image.base.digest": "sha256:unchanged",
		}},
		Lister:  eolLister{tags: tags},
		Support: sup,
		Now:     func() time.Time { return day("2026-08-27") },
	}
}

func firstPartyImage() []model.AssessedImage {
	return []model.AssessedImage{{
		Image: model.Image{
			Registry:   "example.azurecr.io",
			Repository: "nightwatch-orchestrator",
			Tag:        "1.0.5",
		},
	}}
}

// The finding that prompted this: an image on Node 20, four months after Node 20 died,
// reporting no fix available while carrying 23 criticals.
func TestADeadLineIsReportedWithTheMoveThatActuallyExists(t *testing.T) {
	r := nodeResolver(t, nodeSupport(), []string{"20-alpine", "22-alpine", "24-alpine", "26-alpine"})
	got, err := r.Upgrades(context.Background(), firstPartyImage())
	if err != nil {
		t.Fatal(err)
	}
	up, ok := got["example.azurecr.io/nightwatch-orchestrator:1.0.5"]
	if !ok {
		t.Fatalf("no upgrade reported, have %v", got)
	}
	if up.Support == nil {
		t.Fatal("support status missing: the whole point is that this is carried")
	}
	if up.Support.Supported || !up.Support.Known {
		t.Errorf("support = %+v, want a known-unsupported verdict", up.Support)
	}
	if up.Support.EOL != "2026-04-30" {
		t.Errorf("EOL = %q, want 2026-04-30", up.Support.EOL)
	}
	if !up.Available {
		t.Error("Available is false: a dead line with a maintained successor DOES have an upgrade")
	}
	if !up.OutOfTrack {
		t.Error("OutOfTrack is false: crossing a runtime major is a migration, not a bump")
	}
	if up.Latest != "24-alpine" {
		t.Errorf("Latest = %q, want 24-alpine: newest already-LTS line, keeping the variant", up.Latest)
	}
}

func TestItDoesNotRecommendTheNewestMajorWhenThatIsNotYetLTS(t *testing.T) {
	// 26-alpine is present in the registry and maintained, but promoted to LTS in
	// October. Recommending it puts a team on Current, and advice a team should ignore
	// is worse than none: it spends the credibility the next recommendation needs.
	r := nodeResolver(t, nodeSupport(), []string{"20-alpine", "24-alpine", "26-alpine"})
	got, _ := r.Upgrades(context.Background(), firstPartyImage())
	if up := got["example.azurecr.io/nightwatch-orchestrator:1.0.5"]; up.Latest == "26-alpine" {
		t.Error("recommended 26-alpine, which is Current until its LTS date")
	}
}

func TestTheVariantIsPreservedAcrossTheMove(t *testing.T) {
	// "24" exists and is newer, but swapping "20-alpine" for "24" changes the
	// operating system underneath the application and calls it an upgrade.
	r := nodeResolver(t, nodeSupport(), []string{"20-alpine", "24", "24-alpine", "24-slim"})
	got, _ := r.Upgrades(context.Background(), firstPartyImage())
	if up := got["example.azurecr.io/nightwatch-orchestrator:1.0.5"]; up.Latest != "24-alpine" {
		t.Errorf("Latest = %q, want 24-alpine: the suffix is the variant, not a version", up.Latest)
	}
}

func TestAConstructedTagIsVerifiedAgainstTheRegistry(t *testing.T) {
	// The recommended line exists upstream but this repository has no tag for it.
	// Sending somebody to a tag that does not exist is worse than reporting no fix:
	// it is a fix that evaporates on contact.
	r := nodeResolver(t, nodeSupport(), []string{"20-alpine", "21-alpine"})
	got, _ := r.Upgrades(context.Background(), firstPartyImage())
	up := got["example.azurecr.io/nightwatch-orchestrator:1.0.5"]
	if up.Available && up.Latest != "" {
		t.Errorf("offered %q, which is not in the registry's tag list", up.Latest)
	}
	if up.Support == nil || up.Support.Supported {
		t.Error("the end-of-life verdict must still stand even when no target can be named")
	}
}

func TestAnUncheckableBaseReportsUncheckedRatherThanSupported(t *testing.T) {
	// A feed that could not be read, and a base image nobody recognises, are both
	// "we do not know". Neither may render as a clean bill of health.
	r := nodeResolver(t, eolSupport{err: context.DeadlineExceeded}, []string{"20-alpine", "24-alpine"})
	got, _ := r.Upgrades(context.Background(), firstPartyImage())
	if up := got["example.azurecr.io/nightwatch-orchestrator:1.0.5"]; up.Support != nil {
		t.Errorf("support = %+v, want nil (unchecked) when the source failed", up.Support)
	}

	noSource := nodeResolver(t, nil, []string{"20-alpine", "24-alpine"})
	got2, _ := noSource.Upgrades(context.Background(), firstPartyImage())
	if up := got2["example.azurecr.io/nightwatch-orchestrator:1.0.5"]; up.Support != nil {
		t.Errorf("support = %+v, want nil when no source is configured", up.Support)
	}
}

func TestSubstituteCycleRefusesTagsItDoesNotUnderstand(t *testing.T) {
	cases := []struct{ tag, from, to, want string }{
		{"20-alpine", "20", "24", "24-alpine"},
		{"20", "20", "24", "24"},
		{"20.19.5-alpine", "20", "24", "24-alpine"}, // patch numbers do not carry over
		{"20.19.5", "20", "24", "24"},
		{"200-alpine", "20", "24", ""}, // must not match a longer number
		{"alpine3.20", "20", "24", ""}, // not a leading version
		{"", "20", "24", ""},           // nothing to work with
		{"20-alpine", "20", "", ""},    // no target
		{"bookworm", "20", "24", ""},   // no version at all
		{"20-alpine3.19", "20", "24", "24-alpine3.19"},
	}
	for _, c := range cases {
		if got := substituteCycle(c.tag, c.from, c.to); got != c.want {
			t.Errorf("substituteCycle(%q,%q,%q) = %q, want %q", c.tag, c.from, c.to, got, c.want)
		}
	}
}
