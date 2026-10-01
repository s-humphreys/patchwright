package upgrade

import (
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

func TestChartImageTag(t *testing.T) {
	img := func(ref string) model.Image { return model.ParseImageRef(ref) }
	for _, tc := range []struct {
		name       string
		image      string
		release    map[string]any
		chart      map[string]any
		appVersion string
		tag        string
		pinned     bool
		// from defaults to "values" whenever tag is set.
		from string
		repo string
	}{
		{
			name:  "chart pins the same tag it already runs",
			image: "ghcr.io/smarter-project/smarter-device-manager:v1.20.12",
			chart: map[string]any{"rr": map[string]any{"devicePlugin": map[string]any{"image": map[string]any{
				"repository": "ghcr.io/smarter-project/smarter-device-manager", "tag": "v1.20.12"}}}},
			tag: "v1.20.12",
		},
		{
			name:    "release pins the tag beside the repository",
			image:   "tryretool/backend:4.34.1-stable",
			release: map[string]any{"image": map[string]any{"repository": "tryretool/backend", "tag": "4.34.1-stable"}},
			chart:   map[string]any{"image": map[string]any{"repository": "tryretool/backend", "tag": ""}},
			tag:     "4.34.1-stable", pinned: true,
		},
		{
			name:    "release overrides only the tag at the chart's path",
			image:   "acme/app:1.0",
			release: map[string]any{"app": map[string]any{"image": map[string]any{"tag": "1.0"}}},
			chart:   map[string]any{"app": map[string]any{"image": map[string]any{"repository": "acme/app", "tag": "2.0"}}},
			tag:     "1.0", pinned: true,
		},
		{
			name:  "chart moves the tag",
			image: "acme/app:1.0",
			chart: map[string]any{"image": map[string]any{"repository": "acme/app", "tag": "2.0"}},
			tag:   "2.0",
		},
		{
			name:  "registry and repository split, as many charts do",
			image: "quay.io/org/app:1.0",
			chart: map[string]any{"image": map[string]any{"registry": "quay.io", "repository": "org/app", "tag": "1.0"}},
			tag:   "1.0",
		},
		{
			name:  "a whole reference in an image string",
			image: "nginx:1.27",
			chart: map[string]any{"proxy": map[string]any{"image": "docker.io/library/nginx:1.27"}},
			tag:   "1.27",
		},
		{
			name:  "images in a list",
			image: "acme/worker:3",
			chart: map[string]any{"workers": []any{map[string]any{"image": map[string]any{"repository": "acme/worker", "tag": "4"}}}},
			tag:   "4",
		},
		{
			name:  "empty tag and no appVersion: unknown",
			image: "acme/app:1.0",
			chart: map[string]any{"image": map[string]any{"repository": "acme/app", "tag": ""}},
		},
		{
			name:       "empty tag falls back to appVersion, gaining the running tag's v",
			image:      "example.com/old/app:v1.9.5",
			chart:      map[string]any{"image": map[string]any{"repository": "example.com/old/app", "tag": ""}},
			appVersion: "1.10.0",
			tag:        "v1.10.0", from: "appVersion",
		},
		{
			name:       "absent tag falls back to appVersion, losing a v the running tag lacks",
			image:      "example.com/old/app:1.9.5",
			chart:      map[string]any{"image": map[string]any{"repository": "example.com/old/app"}},
			appVersion: "v1.10.0",
			tag:        "1.10.0", from: "appVersion",
		},
		{
			name:       "appVersion styled like the running tag is used as is",
			image:      "example.com/old/app:v1.9.5",
			chart:      map[string]any{"image": map[string]any{"repository": "example.com/old/app", "tag": ""}},
			appVersion: "v1.10.0",
			tag:        "v1.10.0", from: "appVersion",
		},
		{
			name:       "a running tag that merely starts with v is not v-styled",
			image:      "example.com/old/app:valid-1",
			chart:      map[string]any{"image": map[string]any{"repository": "example.com/old/app", "tag": ""}},
			appVersion: "2.0",
			tag:        "2.0", from: "appVersion",
		},
		{
			name:  "a digest beside an empty tag: no appVersion fallback",
			image: "example.com/old/app:1.9.5",
			chart: map[string]any{"image": map[string]any{
				"repository": "example.com/old/app", "tag": "", "digest": "sha256:0123"}},
			appVersion: "1.10.0",
		},
		{
			name:       "a digest the release sets: no appVersion fallback",
			image:      "example.com/old/app:1.9.5",
			release:    map[string]any{"image": map[string]any{"digest": "sha256:0123"}},
			chart:      map[string]any{"image": map[string]any{"repository": "example.com/old/app", "tag": ""}},
			appVersion: "1.10.0",
		},
		{
			name:       "a tag the release pins wins over appVersion",
			image:      "example.com/old/app:1.9.5",
			release:    map[string]any{"image": map[string]any{"tag": "1.9.5"}},
			chart:      map[string]any{"image": map[string]any{"repository": "example.com/old/app", "tag": ""}},
			appVersion: "1.10.0",
			tag:        "1.9.5", pinned: true,
		},
		{
			name:       "a tag the release pins beside the repository wins over appVersion",
			image:      "example.com/old/app:1.9.5",
			release:    map[string]any{"image": map[string]any{"repository": "example.com/old/app", "tag": "1.9.5"}},
			chart:      map[string]any{"image": map[string]any{"repository": "example.com/old/app", "tag": ""}},
			appVersion: "1.10.0",
			tag:        "1.9.5", pinned: true,
		},
		{
			name:       "registry move to the one repository with the same name, tag from appVersion",
			image:      "docker.io/vendor/app:v1.9.5",
			chart:      map[string]any{"image": map[string]any{"repository": "registry.example.org/vendor/oss/app", "tag": ""}},
			appVersion: "1.10.0",
			tag:        "v1.10.0", from: "appVersion", repo: "registry.example.org/vendor/oss/app",
		},
		{
			name:  "registry move with a values tag, registry split out",
			image: "example.com/old/app:1.0",
			chart: map[string]any{"image": map[string]any{
				"registry": "registry.example.org", "repository": "new/app", "tag": "2.0"}},
			tag:  "2.0",
			repo: "registry.example.org/new/app",
		},
		{
			name:  "registry move named in two places agreeing on the tag",
			image: "example.com/old/app:1.0",
			chart: map[string]any{
				"image":      map[string]any{"repository": "registry.example.org/new/app", "tag": "2.0"},
				"migrations": map[string]any{"image": "registry.example.org/new/app:2.0"},
			},
			tag:  "2.0",
			repo: "registry.example.org/new/app",
		},
		{
			name:  "registry move with two same-name candidates: unknown",
			image: "example.com/old/app:1.0",
			chart: map[string]any{
				"a": map[string]any{"image": map[string]any{"repository": "registry.example.org/new/app", "tag": "2.0"}},
				"b": map[string]any{"image": map[string]any{"repository": "registry.example.org/other/app", "tag": "2.0"}},
			},
		},
		{
			name:       "registry move with no same-name candidate: unknown",
			image:      "example.com/old/app:1.0",
			chart:      map[string]any{"image": map[string]any{"repository": "registry.example.org/new/server", "tag": ""}},
			appVersion: "2.0",
		},
		{
			name:  "a numeric tag has lost its formatting: unknown",
			image: "acme/app:1.20",
			chart: map[string]any{"image": map[string]any{"repository": "acme/app", "tag": 1.2}},
		},
		{
			name:  "two places disagree: unknown",
			image: "acme/app:1.0",
			chart: map[string]any{
				"a": map[string]any{"image": map[string]any{"repository": "acme/app", "tag": "1.0"}},
				"b": map[string]any{"image": map[string]any{"repository": "acme/app", "tag": "2.0"}},
			},
		},
		{
			name:  "not in the chart's values: unknown",
			image: "acme/other:1.0",
			chart: map[string]any{"image": map[string]any{"repository": "acme/app", "tag": "1.0"}},
		},
		{
			// The same tag on another registry is a move, never the image staying put.
			name:  "a different registry is a different image",
			image: "ghcr.io/acme/app:1.0",
			chart: map[string]any{"image": map[string]any{"repository": "acme/app", "tag": "1.0"}},
			tag:   "1.0", repo: "docker.io/acme/app",
		},
		{name: "nothing to read", image: "acme/app:1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ChartImage{Tag: tc.tag, Pinned: tc.pinned, From: tc.from, Repo: tc.repo}
			if want.Tag != "" && want.From == "" {
				want.From = model.ImageTagFromValues
			}
			got := ChartImageTag(img(tc.image), tc.release, ChartValues{Values: tc.chart, AppVersion: tc.appVersion})
			if got != want {
				t.Errorf("got %+v, want %+v", got, want)
			}
		})
	}
}
