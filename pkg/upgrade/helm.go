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
	"gopkg.in/yaml.v3"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// ChartRef identifies a deployed Helm chart and its repository.
type ChartRef struct {
	RepoURL string // Helm repository base URL (index.yaml lives under it)
	Name    string // chart name
	Version string // currently deployed chart version
}

// HelmChecker queries a Helm repository index for the latest version of a chart.
type HelmChecker struct {
	HTTP *http.Client
}

// NewHelmChecker returns a HelmChecker with a sensible default HTTP client.
func NewHelmChecker() *HelmChecker {
	return &HelmChecker{HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// helmIndex is the subset of a Helm repository index.yaml we read.
type helmIndex struct {
	Entries map[string][]struct {
		Version string `yaml:"version"`
	} `yaml:"entries"`
}

// Check fetches the repository index and reports the newest chart version and
// whether it is an upgrade over ref.Version. Pre-release versions are ignored
// unless the current version is itself a pre-release.
func (c *HelmChecker) Check(ctx context.Context, ref ChartRef) (model.Upgrade, error) {
	up := model.Upgrade{Kind: "chart", Name: ref.Name, Current: ref.Version, Source: ref.RepoURL}

	idx, err := c.fetchIndex(ctx, ref.RepoURL)
	if err != nil {
		return up, err
	}
	versions, ok := idx.Entries[ref.Name]
	if !ok {
		return up, fmt.Errorf("chart %q not found in %s", ref.Name, ref.RepoURL)
	}

	current, curErr := semver.NewVersion(ref.Version)
	allowPre := curErr == nil && current.Prerelease() != ""

	var latest *semver.Version
	for _, v := range versions {
		parsed, err := semver.NewVersion(v.Version)
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
	if latest == nil {
		return up, nil
	}

	up.Latest = latest.Original()
	up.Available = curErr == nil && latest.GreaterThan(current)
	up.Actionable = up.Available // a chart bump is directly actionable
	return up, nil
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var idx helmIndex
	if err := yaml.Unmarshal(body, &idx); err != nil {
		return nil, fmt.Errorf("parse index.yaml: %w", err)
	}
	return &idx, nil
}
