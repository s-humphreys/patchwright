package rapid7

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/enrich"
)

// One sweep of the platform's vulnerability catalogue, shared by everything that needs
// it.
//
// Two sources read this endpoint: ages take first_found, exploit intelligence takes
// riskscore and the exploit flags. They were sweeping it separately, and on a real
// estate each sweep was about two minutes of a ten-minute assessment - the same pages,
// minutes apart, decoded into different structs.
//
// So the row type carries the union of what both want and the sweep is memoised for
// the run. Where only one source is configured nothing changes: the first caller pays
// and there is no second.

// catalogueRow is a CVE as the platform reports it, with every field any source here
// needs. Kept as one type deliberately: two types over one response is what let the
// duplicate sweep hide.
type catalogueRow struct {
	CVEID      string `json:"cve_id"`
	FirstFound string `json:"first_found"`
	LastSeen   string `json:"last_seen"`
	// RiskScore is the platform's own composite ranking, roughly 0..1000. Not
	// comparable with EPSS, which the API does not carry at all.
	RiskScore   float64 `json:"riskscore"`
	HasExploits bool    `json:"has_exploits"`
	HasThreats  bool    `json:"has_threats"`
}

// catalogue sweeps every CVE the platform has found, once per assessment.
//
// Keyed by base URL, so two configured platforms do not share an answer, and memoised
// on the run rather than the process: a cache with its own lifetime would need a
// time-to-live, and any value for that is a guess about how stale an assessment's
// exploit intelligence may be.
func catalogue(ctx context.Context, api *apiProvider) ([]catalogueRow, error) {
	return enrich.Memo(ctx, "rapid7:vulnerabilities:"+api.baseURL, func() ([]catalogueRow, error) {
		rows, err := sweep[catalogueRow](ctx, api, func(page int) string {
			return fmt.Sprintf("/v3/cvm/vulnerabilities?page=%d&page_size=%d", page, apiPageSize)
		})
		if err != nil {
			return nil, fmt.Errorf("rapid7 vulnerabilities: %w", err)
		}
		slog.InfoContext(ctx, "swept the rapid7 vulnerability catalogue", "rows", len(rows))
		return rows, nil
	})
}

// wanted indexes the ids a caller asked about, upper-cased, so a sweep of the whole
// estate can be narrowed to them in one pass.
func wanted(cveIDs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(cveIDs))
	for _, id := range cveIDs {
		if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
			out[id] = struct{}{}
		}
	}
	return out
}
