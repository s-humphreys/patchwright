package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"gopkg.in/yaml.v3"

	"github.com/s-humphreys/patchwright/pkg/registryauth"
)

// helmChartLayer is the media type of the packaged chart inside an OCI artifact.
const helmChartLayer = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"

// Caps on what a chart download may cost. Packaged charts are small; these exist
// so a misbehaving repository cannot make an assessment read without limit.
const (
	maxChartBytes  = 32 << 20
	maxValuesBytes = 8 << 20
)

// Values returns the top-level values.yaml that version of a chart ships, so an
// upgrade can say which image tags the target version would deploy.
//
// Subcharts' values are not read: their images are left unknown by whoever uses
// this, which is the honest answer when only the parent chart was opened.
func (c *HelmChecker) Values(ctx context.Context, ref ChartRef, version string) (map[string]any, error) {
	body, err := c.openChart(ctx, ref, version)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return valuesFromArchive(io.LimitReader(body, maxChartBytes))
}

func (c *HelmChecker) openChart(ctx context.Context, ref ChartRef, version string) (io.ReadCloser, error) {
	if strings.HasPrefix(ref.RepoURL, "oci://") {
		repo := strings.TrimRight(strings.TrimPrefix(ref.RepoURL, "oci://"), "/") + "/" + ref.Name
		if c.ociChart == nil {
			return nil, fmt.Errorf("no oci chart reader configured")
		}
		return c.ociChart(ctx, repo+":"+version)
	}

	c.mu.Lock()
	urls, known := c.urls[chartKey(ref.RepoURL, ref.Name, version)]
	c.mu.Unlock()
	if !known {
		// Check was not called first on this checker; ask the index directly.
		if _, err := c.chartVersions(ctx, ref); err != nil {
			return nil, err
		}
		c.mu.Lock()
		urls = c.urls[chartKey(ref.RepoURL, ref.Name, version)]
		c.mu.Unlock()
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("chart %s %s has no download URL in %s", ref.Name, version, ref.RepoURL)
	}
	target, err := chartURL(ref.RepoURL, urls[0])
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", target, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("fetch %s: status %d", target, resp.StatusCode)
	}
	return resp.Body, nil
}

// chartURL resolves an index entry's URL, which Helm allows to be relative to the
// repository.
func chartURL(repoURL, entry string) (string, error) {
	u, err := url.Parse(entry)
	if err != nil {
		return "", fmt.Errorf("chart url %q: %w", entry, err)
	}
	if u.IsAbs() {
		return u.String(), nil
	}
	base, err := url.Parse(strings.TrimRight(repoURL, "/") + "/")
	if err != nil {
		return "", fmt.Errorf("repository url %q: %w", repoURL, err)
	}
	return base.ResolveReference(u).String(), nil
}

// pullOCIChart opens the packaged chart layer of an OCI chart artifact.
func pullOCIChart(ctx context.Context, ref string) (io.ReadCloser, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse oci chart reference %s: %w", ref, err)
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(registryauth.Keychain())}
	desc, err := remote.Get(r, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetch oci chart manifest %s: %w", ref, err)
	}
	manifest, err := v1.ParseManifest(bytes.NewReader(desc.Manifest))
	if err != nil {
		return nil, fmt.Errorf("parse oci chart manifest %s: %w", ref, err)
	}
	for _, l := range manifest.Layers {
		if string(l.MediaType) != helmChartLayer {
			continue
		}
		layer, err := remote.Layer(r.Context().Digest(l.Digest.String()), opts...)
		if err != nil {
			return nil, fmt.Errorf("fetch oci chart layer %s: %w", ref, err)
		}
		return layer.Compressed()
	}
	return nil, fmt.Errorf("oci artifact %s has no helm chart layer", ref)
}

// valuesFromArchive reads the top-level values.yaml out of a packaged chart: the
// one file at depth one in the archive, beside Chart.yaml.
func valuesFromArchive(r io.Reader) (map[string]any, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open chart archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("chart archive has no values.yaml")
		}
		if err != nil {
			return nil, fmt.Errorf("read chart archive: %w", err)
		}
		parts := strings.Split(path.Clean(hdr.Name), "/")
		if len(parts) != 2 || parts[1] != "values.yaml" || hdr.Typeflag != tar.TypeReg {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(tr, maxValuesBytes))
		if err != nil {
			return nil, fmt.Errorf("read values.yaml: %w", err)
		}
		values := map[string]any{}
		if err := yaml.Unmarshal(raw, &values); err != nil {
			return nil, fmt.Errorf("parse values.yaml: %w", err)
		}
		return values, nil
	}
}

func chartKey(repoURL, chart, version string) string {
	return strings.TrimRight(repoURL, "/") + "|" + chart + "|" + version
}
