// Package upgrade determines whether a newer version is available for the
// artifact that deploys an image — the remediation path. Today it checks Helm
// chart repositories; git/OCI source revisions and direct image tags follow.
package upgrade

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-containerregistry/pkg/crane"

	"github.com/s-humphreys/patchwright/pkg/registryauth"
	"gopkg.in/yaml.v3"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// ChartRef identifies a deployed Helm chart and its repository.
type ChartRef struct {
	RepoURL string // Helm repository base URL (index.yaml lives under it)
	Name    string // chart name
	Version string // currently deployed chart version
}

// HelmChecker queries a Helm repository for the latest version of a chart. It
// handles both HTTP repositories (an index.yaml of chart versions) and OCI
// repositories (chart versions are tags of the OCI artifact).
type HelmChecker struct {
	HTTP *http.Client
	// ociTags lists the tags of an OCI chart artifact; injectable for tests.
	ociTags func(ctx context.Context, repo string) ([]string, error)
}

// NewHelmChecker returns a HelmChecker with sensible defaults.
func NewHelmChecker() *HelmChecker {
	return &HelmChecker{
		HTTP: &http.Client{Timeout: 20 * time.Second},
		ociTags: func(ctx context.Context, repo string) ([]string, error) {
			return crane.ListTags(repo, crane.WithContext(ctx), crane.WithAuthFromKeychain(registryauth.Keychain()))
		},
	}
}

// helmIndex is the subset of a Helm repository index.yaml we read.
type helmIndex struct {
	Entries map[string][]struct {
		Version string `yaml:"version"`
	} `yaml:"entries"`
}

// Check reports the newest chart version and whether it is an upgrade over
// ref.Version. It reads an OCI repository's tags when the URL is oci://,
// otherwise the HTTP index.yaml. Pre-release versions are ignored unless the
// current version is itself a pre-release.
func (c *HelmChecker) Check(ctx context.Context, ref ChartRef) (model.Upgrade, error) {
	up := model.Upgrade{Kind: "chart", Name: ref.Name, Current: ref.Version, Source: ref.RepoURL}

	versions, err := c.chartVersions(ctx, ref)
	if err != nil {
		return up, err
	}
	// Versions were obtained, so "no newer version" below is a real finding
	// rather than a failed lookup.
	up.Resolved = true

	current, curErr := semver.NewVersion(ref.Version)
	allowPre := curErr == nil && current.Prerelease() != ""

	latest := latestStable(versions, allowPre)
	if latest == nil {
		return up, nil
	}
	up.Latest = latest.Original()
	up.Available = curErr == nil && latest.GreaterThan(current)
	up.Actionable = up.Available // a chart bump is directly actionable
	return up, nil
}

// chartVersions returns the available versions of a chart, from an OCI artifact's
// tags or an HTTP repository index.
func (c *HelmChecker) chartVersions(ctx context.Context, ref ChartRef) ([]string, error) {
	if strings.HasPrefix(ref.RepoURL, "oci://") {
		repo := strings.TrimRight(strings.TrimPrefix(ref.RepoURL, "oci://"), "/") + "/" + ref.Name
		tags, err := c.ociTags(ctx, repo)
		if err != nil {
			return nil, fmt.Errorf("list oci chart tags %s: %w", repo, err)
		}
		return tags, nil
	}

	idx, err := c.fetchIndex(ctx, ref.RepoURL)
	if err != nil {
		return nil, err
	}
	entries, ok := idx.Entries[ref.Name]
	if !ok {
		return nil, fmt.Errorf("chart %q not found in %s", ref.Name, ref.RepoURL)
	}
	versions := make([]string, 0, len(entries))
	for _, e := range entries {
		versions = append(versions, e.Version)
	}
	return versions, nil
}

// latestStable returns the highest semver version, ignoring pre-releases unless
// allowPre is set.
func latestStable(versions []string, allowPre bool) *semver.Version {
	var latest *semver.Version
	for _, v := range versions {
		parsed, err := semver.NewVersion(v)
		if err != nil {
			continue
		}
		if parsed.Prerelease() != "" && !allowPre {
			continue
		}
		if latest == nil || parsed.GreaterThan(latest) {
			latest = parsed
		}
	}
	return latest
}

func (c *HelmChecker) fetchIndex(ctx context.Context, repoURL string) (*helmIndex, error) {
	url := strings.TrimRight(repoURL, "/") + "/index.yaml"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	// Stream-decode rather than buffering the whole index (Helm indexes can be
	// large), and cap the read so a huge/hostile response can't exhaust memory.
	var idx helmIndex
	dec := yaml.NewDecoder(io.LimitReader(resp.Body, maxIndexBytes))
	if err := dec.Decode(&idx); err != nil {
		return nil, fmt.Errorf("parse index.yaml: %w", err)
	}
	return &idx, nil
}

// maxIndexBytes caps how much of a Helm repository index.yaml we read (256 MiB).
const maxIndexBytes = 256 << 20
