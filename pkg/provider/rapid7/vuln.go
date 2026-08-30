package rapid7

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// Rapid7 as a vuln source: per-CVE detail for an image, from the platform that
// already scanned it.
//
// This matters more than "one more scanner". Trivy pulls the image itself, so it
// needs registry credentials wherever it runs — and on a private registry with no
// local credentials that means no per-CVE detail for exactly the images an
// organisation cares most about. The platform has already scanned those images from
// inside the account, and will hand over what it found:
//
//	POST /v3/cvm/resource/{resource_id}/vulnerabilities
//
// It gives severity, CVSS, the platform's risk score, whether a public exploit
// exists, first-found dates and the fixed version, per CVE, per resource. It gives
// neither EPSS nor CISA KEV — run --exploit-source public alongside for those.
//
// The endpoint is keyed by resource rather than by image, so this maps images to a
// representative resource first. One resource is enough: the CVEs belong to the
// image, and every resource running that image reports the same set.

func init() {
	enrich.RegisterVulnSource("rapid7", func(opts enrich.Options) (enrich.VulnSource, error) {
		p, err := newAPIProvider(opts.String("base-url"), apiKeyFromEnv())
		if err != nil {
			return nil, err
		}
		return &vulnSource{api: p}, nil
	})
}

type vulnSource struct {
	api *apiProvider

	// resources maps image reference to a resource that runs it, built once on first
	// use. The mapping is the only reason a second sweep is needed, and it is the
	// same listing the provider already reads, so it is cheap relative to the CVE
	// fetches that follow.
	once      sync.Once
	resources map[string]string
	mapErr    error
}

func (v *vulnSource) Name() string { return "rapid7" }

// resourceVulnRow rows carry both keys, which is what makes the mapping possible.
type resourceRef struct {
	ImageID    string `json:"image_id"`
	ResourceID string `json:"resource_id"`
	Assessment struct {
		Status string `json:"status"`
	} `json:"assessment_info"`
}

// buildMap sweeps the resource listing once, preferring a resource the platform
// actually assessed: an unassessed one would report no CVEs, which would read as a
// clean image rather than as the wrong resource to have asked.
func (v *vulnSource) buildMap(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	assessed := map[string]bool{}
	refs, err := sweep[resourceRef](ctx, v.api, func(page int) string {
		return fmt.Sprintf("/v3/cvm/resource/vulnerabilities?page=%d&page_size=%d", page, apiPageSize)
	})
	if err != nil {
		return nil, fmt.Errorf("rapid7 resource vulnerabilities: %w", err)
	}
	for _, r := range refs {
		img := strings.TrimSpace(r.ImageID)
		if img == "" || r.ResourceID == "" {
			continue
		}
		ok := strings.EqualFold(r.Assessment.Status, "COMPLETED")
		if _, seen := out[img]; seen && (!ok || assessed[img]) {
			continue
		}
		out[img], assessed[img] = r.ResourceID, ok
	}

	slog.InfoContext(ctx, "mapped images to rapid7 resources", "images", len(out))
	return out, nil
}

// Scan implements enrich.VulnSource.
func (v *vulnSource) Scan(ctx context.Context, image model.Image) ([]model.Vulnerability, error) {
	v.once.Do(func() { v.resources, v.mapErr = v.buildMap(ctx) })
	if v.mapErr != nil {
		return nil, v.mapErr
	}

	resource, ok := v.lookup(image)
	if !ok {
		// The platform has no resource running this image, so it has nothing to say
		// about it. An error rather than an empty list: empty would be recorded as a
		// scanned image with no CVEs, which is the one thing this must never claim.
		return nil, fmt.Errorf("no rapid7 resource runs %s, so it has no vulnerability data for it", image.NameTag())
	}

	rows, err := sweep[cveRow](ctx, v.api, func(page int) string {
		return fmt.Sprintf("/v3/cvm/resource/%s/vulnerabilities?page=%d&page_size=%d",
			url.PathEscape(resource), page, apiPageSize)
	})
	if err != nil {
		return nil, fmt.Errorf("rapid7 vulnerabilities for %s: %w", image.NameTag(), err)
	}
	out := make([]model.Vulnerability, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.vulnerability())
	}
	return out, nil
}

// cveRow is one CVE on one resource.
type cveRow struct {
	CVEID       string  `json:"cve_id"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss_score"`
	RiskScore   float64 `json:"riskscore"`
	HasExploits bool    `json:"has_exploits"`
	HasThreats  bool    `json:"has_threats"`
	FirstFound  string  `json:"first_found"`
	Meta        struct {
		FixedVersion string `json:"FixedVersion"`
	} `json:"vuln_meta"`
}

func (r cveRow) vulnerability() model.Vulnerability {
	v := model.Vulnerability{
		ID:       strings.ToUpper(strings.TrimSpace(r.CVEID)),
		Severity: strings.ToLower(strings.TrimSpace(r.Severity)),
		CVSS:     r.CVSS,
		// The platform's own signals, carried here so a run needs no second source to
		// rank CVEs. EPSS and KEV are deliberately absent: this API has neither, and
		// inventing them from the risk score would be a lie on a different scale.
		RiskScore:    r.RiskScore,
		ExploitKnown: r.HasExploits || r.HasThreats,
		// A fixed version is the platform stating a patch exists. Absent means no fix
		// published, which is the distinction the whole "fixable" tier rests on.
		FixedVersion: strings.TrimSpace(r.Meta.FixedVersion),
	}
	v.FixAvailable = v.FixedVersion != ""
	if t, ok := parseAPITime(r.FirstFound); ok {
		v.FirstSeen = t
	}
	return v
}

// lookup finds the resource for an image, tolerating how the platform writes a
// reference. Docker Hub images are recorded without a registry ("n8nio/n8n:2.36.1")
// while an image parsed from a cluster carries the implied one, so an exact match on
// the qualified form misses every Docker Hub image in the estate.
func (v *vulnSource) lookup(image model.Image) (string, bool) {
	for _, key := range []string{image.NameTag(), image.Ref} {
		if key == "" {
			continue
		}
		if r, ok := v.resources[key]; ok {
			return r, true
		}
		for _, implied := range []string{"docker.io/library/", "docker.io/", "index.docker.io/"} {
			if bare := strings.TrimPrefix(key, implied); bare != key {
				if r, ok := v.resources[bare]; ok {
					return r, true
				}
			}
		}
	}
	return "", false
}
