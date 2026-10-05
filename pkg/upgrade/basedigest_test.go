package upgrade

import (
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

// A build pipeline that writes the base digest label as bare hex produced
// "repo@<hex>", which no reference parser accepts, so every scan of the base as
// built failed and a digest comparison could never match.
func TestBaseDigestLabelWithoutAlgorithmPrefix(t *testing.T) {
	const (
		hexA = "008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"
		hexB = "534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55"
		app  = "registry.example.com/app:1.0.0"
	)
	cases := []struct {
		name      string
		baseRef   string
		digest    string
		regDigest string
		tags      []string
		wantFrom  string
		wantTo    string
		wantAvail bool
	}{
		{
			name:      "floating tag, bare hex, moved",
			baseRef:   "docker.io/ubuntu:noble",
			digest:    hexA,
			regDigest: "sha256:" + hexB,
			wantFrom:  "docker.io/ubuntu@sha256:" + hexA,
			wantTo:    "docker.io/ubuntu@sha256:" + hexB,
			wantAvail: true,
		},
		{
			name:      "floating tag, bare hex, unchanged",
			baseRef:   "docker.io/ubuntu:noble",
			digest:    hexA,
			regDigest: "sha256:" + hexA,
			wantFrom:  "docker.io/ubuntu@sha256:" + hexA,
		},
		{
			name:      "floating tag, upper-case bare hex",
			baseRef:   "docker.io/ubuntu:noble",
			digest:    strings.ToUpper(hexA),
			regDigest: "sha256:" + hexA,
			wantFrom:  "docker.io/ubuntu@sha256:" + hexA,
		},
		{
			name:      "versioned tag, bare hex",
			baseRef:   "mcr.example.com/runtime:10.0.1",
			digest:    hexA,
			tags:      []string{"10.0.1", "10.0.2"},
			wantFrom:  "mcr.example.com/runtime@sha256:" + hexA,
			wantTo:    "mcr.example.com/runtime:10.0.2",
			wantAvail: true,
		},
		{
			name:      "already prefixed",
			baseRef:   "docker.io/ubuntu:noble",
			digest:    "sha256:" + hexA,
			regDigest: "sha256:" + hexA,
			wantFrom:  "docker.io/ubuntu@sha256:" + hexA,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := &fakeRegistry{
				labels: map[string]map[string]string{
					app: {"image.base.ref.name": c.baseRef, "image.base.digest": c.digest},
				},
				digests: map[string]string{c.baseRef: c.regDigest},
				tags:    map[string][]string{strings.SplitN(c.baseRef, ":", 2)[0]: c.tags},
			}
			u := resolve(t, reg, cfgFor("registry.example.com"), app)[app]
			if u.FromRef != c.wantFrom {
				t.Errorf("FromRef = %q, want %q", u.FromRef, c.wantFrom)
			}
			if u.ToRef != c.wantTo {
				t.Errorf("ToRef = %q, want %q", u.ToRef, c.wantTo)
			}
			if u.Available != c.wantAvail {
				t.Errorf("Available = %v, want %v (%+v)", u.Available, c.wantAvail, u)
			}
			for _, ref := range []string{u.FromRef, u.ToRef} {
				if ref == "" {
					continue
				}
				if _, err := name.ParseReference(ref); err != nil {
					t.Errorf("reference %q does not parse: %v", ref, err)
				}
			}
		})
	}
}
