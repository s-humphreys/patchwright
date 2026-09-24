package upgrade

import (
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

func TestChartImageTag(t *testing.T) {
	img := func(ref string) model.Image { return model.ParseImageRef(ref) }
	for _, tc := range []struct {
		name    string
		image   string
		release map[string]any
		chart   map[string]any
		tag     string
		pinned  bool
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
			name:  "empty tag defers to the chart's templates: unknown",
			image: "acme/app:1.0",
			chart: map[string]any{"image": map[string]any{"repository": "acme/app", "tag": ""}},
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
			name:  "a different registry is a different image",
			image: "ghcr.io/acme/app:1.0",
			chart: map[string]any{"image": map[string]any{"repository": "acme/app", "tag": "1.0"}},
		},
		{name: "nothing to read", image: "acme/app:1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tag, pinned := ChartImageTag(img(tc.image), tc.release, tc.chart)
			if tag != tc.tag || pinned != tc.pinned {
				t.Errorf("got %q pinned=%v, want %q pinned=%v", tag, pinned, tc.tag, tc.pinned)
			}
		})
	}
}
