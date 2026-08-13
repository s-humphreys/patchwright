package rapid7

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/pkg/enrich"
)

// CVE first-seen times from InsightCloudSec.
//
// POST /v3/cvm/vulnerabilities lists every CVE the platform has found across the
// estate, each with first_found and last_seen. One sweep of that is far cheaper than
// asking per image: the per-resource endpoint would be one request per assessed
// resource — hundreds — for data that is identical wherever the CVE appears.
//
// The trade is deliberate and worth stating: first_found here is when the platform
// first saw the CVE *anywhere in the estate*, not on the specific image. For "how
// long has this been known about" that is the right number. For "how long has this
// image been exposed" it can be earlier than the truth, if the image adopted the CVE
// later. The per-resource endpoint is the fix for anyone who needs that precision.

func init() {
	enrich.RegisterAgeSource("rapid7", func(opts enrich.Options) (enrich.AgeSource, error) {
		p, err := newAPIProvider(opts.String("base-url"), apiKeyFromEnv())
		if err != nil {
			return nil, err
		}
		return &ageSource{api: p}, nil
	})
}

type ageSource struct {
	api *apiProvider
}

func (a *ageSource) Name() string { return "rapid7" }

// vulnRow is the subset of a CVE row this needs.
type vulnRow struct {
	CVEID      string `json:"cve_id"`
	FirstFound string `json:"first_found"`
	LastSeen   string `json:"last_seen"`
}

// FirstSeen sweeps the estate's CVEs and returns the times for the ids asked about.
//
// Ids the platform knows nothing about are omitted, not zeroed: a CVE Trivy found
// and Rapid7 has never seen has an unknown age, and reporting it as the epoch would
// make it the oldest thing in the queue.
func (a *ageSource) FirstSeen(ctx context.Context, cveIDs []string) (map[string]time.Time, error) {
	want := make(map[string]struct{}, len(cveIDs))
	for _, id := range cveIDs {
		want[strings.ToUpper(id)] = struct{}{}
	}

	out := make(map[string]time.Time, len(cveIDs))
	for page := 1; page <= apiMaxPages; page++ {
		path := fmt.Sprintf("/v3/cvm/vulnerabilities?page=%d&page_size=%d", page, apiPageSize)
		var resp pagedResponse[vulnRow]
		if err := a.api.post(ctx, path, &resp); err != nil {
			return nil, fmt.Errorf("rapid7 vulnerabilities: page %d: %w", page, err)
		}
		for _, row := range resp.Data {
			id := strings.ToUpper(strings.TrimSpace(row.CVEID))
			if id == "" {
				continue
			}
			if _, ok := want[id]; !ok {
				continue
			}
			if t, ok := parseAPITime(row.FirstFound); ok {
				out[id] = t
			}
		}
		if page == 1 {
			slog.DebugContext(ctx, "sweeping rapid7 vulnerabilities for first-seen dates",
				"total_cves", resp.TotalCount, "pages", resp.TotalPages)
		}
		if len(resp.Data) == 0 || page >= resp.TotalPages {
			break
		}
	}
	return out, nil
}

// parseAPITime accepts the two shapes this API uses for a timestamp, and reports
// failure rather than returning a zero time that would read as 1970.
func parseAPITime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"2006-01-02T15:04:05", lastAssessmentLayout, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
