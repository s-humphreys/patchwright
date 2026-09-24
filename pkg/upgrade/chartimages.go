package upgrade

import (
	"sort"
	"strconv"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// ChartImageTag works out the tag a Helm release would deploy for img once its
// chart is bumped, from the target chart's values.yaml and the release's own
// values. It returns "" when that cannot be established, and pinned when the
// release's values set the tag, so no chart bump moves it.
//
// It reads values, not templates. A map that names img's repository beside a tag
// is taken to be what deploys it, which is the convention nearly every chart
// follows and the only one that can be read without rendering the chart. Anything
// else is unknown rather than guessed: an empty tag that the chart's templates
// default to its appVersion, an image in a subchart, or two places naming the
// repository with different tags all return "". A wrong "unchanged" suppresses a
// ticket that should exist, so the answer is only ever given when it is read
// directly.
//
// Either map may be nil. Release values alone can still answer, since a tag we
// pin ourselves is the tag that runs whatever the chart ships.
func ChartImageTag(img model.Image, release, chart map[string]any) (tag string, pinned bool) {
	var overrides []string
	for _, e := range imageEntries(release, img) {
		overrides = append(overrides, e.tag)
	}
	switch tags := distinctTags(overrides); len(tags) {
	case 1:
		return tags[0], true
	case 0:
	default:
		return "", false
	}

	entries := imageEntries(chart, img)
	if len(entries) == 0 {
		return "", false
	}
	var resolved []string
	pinned = true
	for _, e := range entries {
		// A release commonly overrides only the tag, at the path the chart uses,
		// without restating the repository beside it.
		if t := tagAt(release, e.path); t != "" {
			resolved = append(resolved, t)
			continue
		}
		if e.tag == "" {
			return "", false
		}
		pinned = false
		resolved = append(resolved, e.tag)
	}
	if tags := distinctTags(resolved); len(tags) == 1 {
		return tags[0], pinned
	}
	return "", false
}

// imageEntry is one place in a values tree that names an image.
type imageEntry struct {
	path []string
	tag  string
}

// imageEntries finds every map in values that names img's repository, with the
// tag set beside it ("" when none or not a string), and every "image" key whose
// string value is a reference to it.
func imageEntries(values map[string]any, img model.Image) []imageEntry {
	var out []imageEntry
	var walk func(v any, path []string)
	walk = func(v any, path []string) {
		switch node := v.(type) {
		case map[string]any:
			if repo, ok := node["repository"].(string); ok && repo != "" {
				ref := repo
				if reg, ok := node["registry"].(string); ok && reg != "" {
					ref = strings.TrimRight(reg, "/") + "/" + repo
				}
				if sameRepository(model.ParseImageRef(ref), img) {
					// A YAML number such as 1.20 has already lost its trailing zero by
					// the time it arrives here, so only a string is trusted as a tag.
					t, _ := node["tag"].(string)
					out = append(out, imageEntry{path: clone(path), tag: t})
				}
			}
			keys := make([]string, 0, len(node))
			for k := range node {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if s, ok := node[k].(string); ok && k == "image" {
					if ref := model.ParseImageRef(s); ref.Tag != "" && sameRepository(ref, img) {
						out = append(out, imageEntry{path: clone(append(path, k)), tag: ref.Tag})
					}
					continue
				}
				walk(node[k], append(path, k))
			}
		case []any:
			for i, item := range node {
				walk(item, append(path, strconv.Itoa(i)))
			}
		}
	}
	if values != nil {
		walk(values, nil)
	}
	return out
}

// tagAt returns the tag a values tree sets at path: a "tag" beside it when path
// names a map, or the tag of the reference when path names an image string.
func tagAt(values map[string]any, path []string) string {
	var node any = values
	for _, key := range path {
		switch n := node.(type) {
		case map[string]any:
			node = n[key]
		case []any:
			i, err := strconv.Atoi(key)
			if err != nil || i < 0 || i >= len(n) {
				return ""
			}
			node = n[i]
		default:
			return ""
		}
	}
	switch n := node.(type) {
	case map[string]any:
		t, _ := n["tag"].(string)
		return t
	case string:
		return model.ParseImageRef(n).Tag
	}
	return ""
}

func sameRepository(a, b model.Image) bool {
	return canonical(a) == canonical(b)
}

// canonical folds the spellings Docker Hub accepts for one repository together.
func canonical(i model.Image) string {
	reg := strings.ToLower(i.Registry)
	repo := i.Repository
	switch reg {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		reg = "docker.io"
		repo = strings.TrimPrefix(repo, "library/")
	}
	return reg + "/" + repo
}

func distinctTags(tags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range tags {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func clone(path []string) []string {
	return append([]string(nil), path...)
}
