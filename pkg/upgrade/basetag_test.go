package upgrade

import (
	"testing"

	"github.com/Masterminds/semver/v3"
)

// The recommended tag must be one the registry publishes. Versions are parsed with a
// leading "v" removed, and handing that trimmed string back proposed "1.63.0-noble"
// to a repository that only has "v1.63.0-noble": a 404 presented as a fix.
func TestBaseUpgradeNamesTheTagAsPublished(t *testing.T) {
	const app = "registry.example.com/app:1.0.0"
	cases := []struct {
		name       string
		base       string
		tags       []string
		wantLatest string
		wantTo     string
	}{
		{
			name:       "v prefix with variant suffix",
			base:       "mcr.example.com/browsers:v1.62.0-noble",
			tags:       []string{"v1.62.0-noble", "v1.63.0-noble", "v1.63.0-jammy", "v1.63.0"},
			wantLatest: "v1.63.0-noble",
			wantTo:     "mcr.example.com/browsers:v1.63.0-noble",
		},
		{
			name:       "v prefix, plain",
			base:       "docker.io/tool:v2.1.0",
			tags:       []string{"v2.1.0", "v2.1.4", "v3.0.0"},
			wantLatest: "v2.1.4",
			wantTo:     "docker.io/tool:v2.1.4",
		},
		{
			name:       "no prefix stays unprefixed",
			base:       "docker.io/runtime:3.12.3-slim",
			tags:       []string{"3.12.3-slim", "3.12.15-slim", "3.12.15"},
			wantLatest: "3.12.15-slim",
			wantTo:     "docker.io/runtime:3.12.15-slim",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := &fakeRegistry{
				labels: map[string]map[string]string{app: {"image.base.ref.name": c.base}},
				tags:   map[string][]string{repoOf(c.base): c.tags},
			}
			u := resolve(t, reg, cfgFor("registry.example.com"), app)[app]
			if u.Latest != c.wantLatest {
				t.Errorf("Latest = %q, want %q", u.Latest, c.wantLatest)
			}
			if u.ToRef != c.wantTo {
				t.Errorf("ToRef = %q, want %q", u.ToRef, c.wantTo)
			}
		})
	}
}

// Newest, reported beside a held-back recommendation, is a tag too.
func TestBaseUpgradeNewestIsTheTagAsPublished(t *testing.T) {
	v, tags := mustVersion(t, "1.62.0-noble"), []string{"v1.62.0-noble", "v1.62.3-noble", "v1.63.0-noble"}
	if got := newestWithin(v, tags, "patch", ""); got == nil || got.Original() != "v1.62.3-noble" {
		t.Errorf("patch picked %v, want v1.62.3-noble", got)
	}
	if got := newestWithin(v, tags, "latest", ""); got == nil || got.Original() != "v1.63.0-noble" {
		t.Errorf("latest picked %v, want v1.63.0-noble", got)
	}
}

func repoOf(ref string) string {
	for i := len(ref) - 1; i >= 0; i-- {
		switch ref[i] {
		case ':':
			return ref[:i]
		case '/':
			return ref
		}
	}
	return ref
}

func mustVersion(t *testing.T, s string) *semver.Version {
	t.Helper()
	v, err := semver.StrictNewVersion(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
