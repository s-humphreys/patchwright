package upgrade

import (
	"sort"
	"strconv"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// ChartImage is what a Helm release would deploy for one running image once its
// chart is bumped.
type ChartImage struct {
	// Tag is the tag it would deploy, "" when that cannot be established.
	Tag string
	// Pinned reports that the release's own values set the tag, so no chart bump
	// moves it.
	Pinned bool
	// From is where Tag was read: model.ImageTagFromValues,
	// model.ImageTagFromAppVersion, or "" when Tag is unknown.
	From string
	// Repo is the repository, registry included, the target chart deploys the image
	// from. Set only when that is not the repository running.
	Repo string
}

// ChartImageTag works out what a Helm release would deploy for img once its chart
// is bumped, from the target chart's values.yaml and appVersion and the release's
// own values. The tag is "" when that cannot be established, and pinned when the
// release's values set it.
//
// It reads values, not templates. A map that names img's repository beside a tag
// is taken to be what deploys it, which is the convention nearly every chart
// follows and the only one that can be read without rendering the chart. Two
// further conventions are common enough to read:
//
//   - an empty tag, which the chart's templates fill from its appVersion, styled
//     like the running tag ("v" prefix or not). Not when a digest is set, since
//     templates that honour a digest use it over any tag.
//   - a new chart version moving the image to another repository. When nothing
//     names img's repository but exactly one repository in the values ends in the
//     same name, that is taken to be its replacement.
//
// Anything else is unknown rather than guessed: an image in a subchart, two places
// naming the repository with different tags, or two candidate replacements all
// return "". A wrong "unchanged" suppresses a ticket that should exist, so
// whoever reads this must treat only a values tag on the same repository as
// proof the image stays put.
//
// Either values map may be nil. Release values alone can still answer, since a
// tag we pin ourselves is the tag that runs whatever the chart ships.
func ChartImageTag(img model.Image, release map[string]any, chart ChartValues) ChartImage {
	same := func(ref model.Image) bool { return sameRepository(ref, img) }

	var overrides []string
	for _, e := range imageEntries(release, same) {
		overrides = append(overrides, e.tag)
	}
	switch tags := distinctTags(overrides); len(tags) {
	case 1:
		return ChartImage{Tag: tags[0], Pinned: true, From: model.ImageTagFromValues}
	case 0:
	default:
		return ChartImage{}
	}

	entries := imageEntries(chart.Values, same)
	var repo string
	if len(entries) == 0 {
		entries, repo = movedEntries(chart.Values, img)
	}
	if len(entries) == 0 {
		return ChartImage{}
	}
	var resolved []string
	pinned, from := true, model.ImageTagFromValues
	for _, e := range entries {
		// A release commonly overrides only the tag, at the path the chart uses,
		// without restating the repository beside it.
		if t := tagAt(release, e.path); t != "" {
			resolved = append(resolved, t)
			continue
		}
		pinned = false
		switch {
		case e.tag != "":
			resolved = append(resolved, e.tag)
		case e.digest || digestAt(release, e.path) || chart.AppVersion == "":
			return ChartImage{}
		default:
			resolved = append(resolved, styledLike(chart.AppVersion, img.Tag))
			from = model.ImageTagFromAppVersion
		}
	}
	if tags := distinctTags(resolved); len(tags) == 1 {
		return ChartImage{Tag: tags[0], Pinned: pinned, From: from, Repo: repo}
	}
	return ChartImage{}
}

// movedEntries finds where a target chart deploys img when it has moved the image
// to another repository: the entries naming a repository whose last path segment
// is img's. All of them must name the one repository, returned beside them; with
// two, nothing says which replaces img.
func movedEntries(values map[string]any, img model.Image) ([]imageEntry, string) {
	name := lastPathSegment(img.Repository)
	if name == "" {
		return nil, ""
	}
	entries := imageEntries(values, func(ref model.Image) bool {
		return lastPathSegment(ref.Repository) == name
	})
	repos := map[string]bool{}
	for _, e := range entries {
		repos[canonical(e.ref)] = true
	}
	if len(repos) != 1 {
		return nil, ""
	}
	return entries, canonical(entries[0].ref)
}

// styledLike writes version the way the running tag writes its version, since
// charts disagree on whether appVersion carries the "v" their images are tagged
// with: v1.10.0 beside a running v1.9.5, 1.10.0 beside a running 1.9.5.
func styledLike(version, running string) string {
	switch {
	case running == "":
		return version
	case vPrefixed(running) && !vPrefixed(version):
		return "v" + version
	case !vPrefixed(running) && vPrefixed(version):
		return version[1:]
	}
	return version
}

// vPrefixed reports a "v" before a version number, not any tag starting with v.
func vPrefixed(s string) bool {
	return len(s) > 1 && s[0] == 'v' && s[1] >= '0' && s[1] <= '9'
}

// imageEntry is one place in a values tree that names an image.
type imageEntry struct {
	path []string
	ref  model.Image
	tag  string
	// digest reports a digest set beside the repository.
	digest bool
}

// imageEntries finds every map in values that names a repository match accepts,
// with the tag set beside it ("" when none or not a string), and every "image" key
// whose string value is a tagged reference match accepts.
func imageEntries(values map[string]any, match func(model.Image) bool) []imageEntry {
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
				if parsed := model.ParseImageRef(ref); match(parsed) {
					// A YAML number such as 1.20 has already lost its trailing zero by
					// the time it arrives here, so only a string is trusted as a tag.
					t, _ := node["tag"].(string)
					d, _ := node["digest"].(string)
					out = append(out, imageEntry{path: clone(path), ref: parsed, tag: t, digest: d != ""})
				}
			}
			keys := make([]string, 0, len(node))
			for k := range node {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if s, ok := node[k].(string); ok && k == "image" {
					if ref := model.ParseImageRef(s); ref.Tag != "" && match(ref) {
						out = append(out, imageEntry{path: clone(append(path, k)), ref: ref, tag: ref.Tag})
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
	switch n := nodeAt(values, path).(type) {
	case map[string]any:
		t, _ := n["tag"].(string)
		return t
	case string:
		return model.ParseImageRef(n).Tag
	}
	return ""
}

// digestAt reports a "digest" a values tree sets at path.
func digestAt(values map[string]any, path []string) bool {
	n, _ := nodeAt(values, path).(map[string]any)
	d, _ := n["digest"].(string)
	return d != ""
}

func nodeAt(values map[string]any, path []string) any {
	var node any = values
	for _, key := range path {
		switch n := node.(type) {
		case map[string]any:
			node = n[key]
		case []any:
			i, err := strconv.Atoi(key)
			if err != nil || i < 0 || i >= len(n) {
				return nil
			}
			node = n[i]
		default:
			return nil
		}
	}
	return node
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
