package rapid7

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// The InsightCloudSec API.
//
// This queries the same data the CSV export contains, and three things besides
// that the export drops on the floor:
//
//   - assessment_info, which says whether the platform assessed an image and,
//     when it did not, why. The export leaves last_assessment empty and says
//     nothing further, so every uncovered image looks alike. In practice they
//     are not alike at all: on a real estate 3,215 of 4,243 rows were failing
//     for one fixable reason (a registry credential), which the export made
//     invisible and this makes the first thing you see.
//   - k8s_cluster_name, so a finding can name the cluster it came from without
//     waiting for live reconciliation.
//   - report_id, the image digest the platform actually assessed, which pins a
//     result to an image rather than to a mutable tag.
//
// Endpoint shape, established by probing the live API rather than the docs
// (which describe a request body this deployment rejects):
//
//	POST /v3/cvm/resource/vulnerabilities?page=N&page_size=M
//	body {} — filters/limit/offset in the body are rejected as unknown fields
//	response {data: [...], page, page_size, total_count, total_pages}
//
// page_size is capped at 100 server-side, and rows are ordered by id, so paging
// is stable rather than a moving window.

// apiDefaults are the pieces of the endpoint contract worth naming.
const (
	// apiPageSize is the server's maximum. Anything larger is a 400, so there is
	// no point being polite about it.
	apiPageSize = 100
	// apiMaxPages bounds a run against an API that keeps claiming another page.
	// At the maximum page size this is far more rows than any real estate.
	apiMaxPages = 2000
	// apiTimeout is per request, not per run.
	apiTimeout = 2 * time.Minute
)

// Assessment statuses the platform reports. Only assessmentCompleted means the
// counts on a row are a measurement; every other value means they are zero
// because nothing looked.
const (
	assessmentCompleted = "COMPLETED"
	assessmentFailed    = "FAILED"
	assessmentQueued    = "QUEUED"
)

// apiProvider queries InsightCloudSec directly.
type apiProvider struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func newAPIProvider(baseURL, apiKey string) (*apiProvider, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("rapid7 api mode requires option \"base-url\" " +
			"(e.g. https://example.customer.divvycloud.com)")
	}
	if apiKey == "" {
		// Deliberately not an option: a key in a config file or a Helm values
		// file ends up in a git repository. It comes from the environment, which
		// a Secret can populate.
		return nil, fmt.Errorf("rapid7 api mode requires the %s environment variable", EnvAPIKey)
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("rapid7 api: base-url %q is not an absolute URL", baseURL)
	}
	if u.Scheme != "https" {
		// The API key is a bearer credential sent on every request.
		return nil, fmt.Errorf("rapid7 api: base-url must be https, got %q", u.Scheme)
	}
	return &apiProvider{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		client:  &http.Client{Timeout: apiTimeout},
	}, nil
}

func (p *apiProvider) Name() string { return "rapid7" }

// resourceVulnRow is one row of POST /v3/cvm/resource/vulnerabilities: one image
// on one resource, with the platform's aggregate counts for it.
type resourceVulnRow struct {
	ImageID       string  `json:"image_id"`
	ResourceID    string  `json:"resource_id"`
	ResourceType  string  `json:"resource_type"`
	ResourceName  string  `json:"resource_name"`
	Cloud         string  `json:"cloud"`
	Account       string  `json:"account"`
	AccountID     string  `json:"account_id"`
	Platform      string  `json:"platform"`
	ReportID      string  `json:"report_id"`
	ClusterName   string  `json:"k8s_cluster_name"`
	PublicAccess  bool    `json:"public_accessible"`
	RiskScore     float64 `json:"riskscore"`
	CriticalCount int     `json:"critical_count"`
	HighCount     int     `json:"high_count"`
	MediumCount   int     `json:"medium_count"`
	LowCount      int     `json:"low_count"`
	NoneCount     int     `json:"none_count"`
	TotalCount    int     `json:"total_count"`
	Severity      string  `json:"severity"`

	// LastAssessment is null on rows the platform never assessed.
	LastAssessment *string `json:"last_assessment"`

	AssessmentInfo struct {
		Status              string  `json:"status"`
		ErrorReason         *string `json:"error_reason"`
		AssessmentCompleted *string `json:"assessment_completed_at"`
		PulledFrom          *string `json:"pulled_from"`
	} `json:"assessment_info"`
}

// pagedResponse is the envelope every list endpoint returns.
type pagedResponse[T any] struct {
	Data       []T `json:"data"`
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

func (p *apiProvider) Fetch(ctx context.Context) ([]model.Occurrence, error) {
	var occurrences []model.Occurrence
	var statuses = map[string]int{}

	for page := 1; page <= apiMaxPages; page++ {
		path := fmt.Sprintf("/v3/cvm/resource/vulnerabilities?page=%d&page_size=%d", page, apiPageSize)
		var resp pagedResponse[resourceVulnRow]
		if err := p.post(ctx, path, &resp); err != nil {
			// Failing mid-way is reported rather than returning what arrived so
			// far: a partial estate silently missing its last pages would read
			// as an estate that has shrunk, and every count drawn from it would
			// be wrong in the direction of "better".
			return nil, fmt.Errorf("rapid7 api: page %d: %w", page, err)
		}
		for i := range resp.Data {
			occurrences = append(occurrences, rowToOccurrence(&resp.Data[i]))
			statuses[resp.Data[i].AssessmentInfo.Status]++
		}
		if page == 1 {
			slog.InfoContext(ctx, "fetching rapid7 resource vulnerabilities",
				"total_rows", resp.TotalCount, "pages", resp.TotalPages, "page_size", resp.PageSize)
		}
		// Trust the reported page count, but stop on an empty page too: an API
		// that says "one more page" forever would otherwise spin to the cap.
		if len(resp.Data) == 0 || page >= resp.TotalPages {
			break
		}
	}

	slog.InfoContext(ctx, "fetched rapid7 resource vulnerabilities",
		"occurrences", len(occurrences), "assessment_status", statuses)
	return occurrences, nil
}

// post issues the POST-as-query these endpoints use and decodes the envelope.
func (p *apiProvider) post(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+path,
		bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	req.Header.Set("Api-Key", p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Body first, status second: this API explains a rejection in the body
		// ({"messages": {...}}) and a bare "400 Bad Request" is unactionable.
		// Bounded because an error page can be arbitrarily large.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			// Named explicitly: the usual cause is an expired or wrong key, and
			// the API's own message for it is not obviously about the key.
			return fmt.Errorf("%s (check RAPID7_API_KEY): %s", resp.Status, msg)
		}
		return fmt.Errorf("%s: %s", resp.Status, msg)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// rowToOccurrence maps one API row to the generic model. The counterpart of
// recordToOccurrence for the CSV, and the only place the API's schema is
// interpreted.
func rowToOccurrence(r *resourceVulnRow) model.Occurrence {
	dims := map[string]string{
		"cloud":             r.Cloud,
		"account":           r.Account,
		"account_id":        r.AccountID,
		"namespace":         namespaceFromResourceID(r.ResourceID),
		"resource_type":     r.ResourceType,
		"resource_name":     r.ResourceName,
		"public_accessible": fmt.Sprintf("%t", r.PublicAccess),
	}
	// Only from the API: the cluster, and the platform the image was built for.
	// Kept out of the map when empty so a rule matching on them cannot succeed
	// against an empty string.
	if c := clusterName(r.ClusterName); c != "" {
		dims["cluster"] = c
	}
	if r.Platform != "" {
		dims["platform"] = r.Platform
	}

	counts := model.Counts{}
	for sev, n := range map[string]int{
		model.SeverityCritical: r.CriticalCount,
		model.SeverityHigh:     r.HighCount,
		model.SeverityMedium:   r.MediumCount,
		model.SeverityLow:      r.LowCount,
		"none":                 r.NoneCount,
	} {
		if n > 0 {
			counts[sev] = n
		}
	}

	// Assessed means the platform completed an assessment of this image. Every
	// other status leaves the counts at zero for want of data, which must not
	// read as a clean result.
	status := strings.ToUpper(strings.TrimSpace(r.AssessmentInfo.Status))
	assessed := status == assessmentCompleted

	image := model.ParseImageRef(r.ImageID)
	// report_id is the digest the platform actually assessed. Only trusted when
	// it did assess: on a failed row it can name a digest nothing was read from.
	if assessed && image.Digest == "" && strings.HasPrefix(r.ReportID, "sha256:") {
		image.Digest = r.ReportID
	}

	return model.Occurrence{
		Image: image,
		Resource: model.Resource{
			ID:         r.ResourceID,
			Type:       r.ResourceType,
			Name:       r.ResourceName,
			Dimensions: dims,
			Labels:     map[string]string{}, // the API does not carry them; live reconciliation supplies them
		},
		Counts:           counts,
		RiskScore:        r.RiskScore,
		LastSeen:         assessmentTime(r),
		Assessed:         assessed,
		AssessmentStatus: status,
		AssessmentError:  assessmentError(r, status, assessed),
	}
}

// assessmentError explains a missing assessment in the platform's own words.
//
// Reported for any status other than COMPLETED, including the empty one: a row
// with no status and no error is still unassessed, and "unknown" is a better
// answer to "why?" than nothing at all, because nothing reads as "no reason to
// worry".
func assessmentError(r *resourceVulnRow, status string, assessed bool) string {
	if assessed {
		return ""
	}
	if r.AssessmentInfo.ErrorReason != nil {
		if reason := strings.TrimSpace(*r.AssessmentInfo.ErrorReason); reason != "" {
			return reason
		}
	}
	switch status {
	case assessmentQueued:
		return "queued for assessment, not yet assessed"
	case assessmentFailed:
		return "assessment failed, no reason given"
	case "":
		return "never assessed, no status reported"
	default:
		return fmt.Sprintf("assessment status %q", status)
	}
}

// assessmentTime is when the platform last looked. It prefers the assessment's
// own completion time over last_assessment, and returns the zero time when the
// row carries neither, so "we do not know when" is never rendered as an epoch
// date that looks like a real answer.
func assessmentTime(r *resourceVulnRow) time.Time {
	for _, ts := range []*string{r.AssessmentInfo.AssessmentCompleted, r.LastAssessment} {
		if ts == nil || strings.TrimSpace(*ts) == "" {
			continue
		}
		if t, err := time.Parse(lastAssessmentLayout, strings.TrimSpace(*ts)); err == nil {
			return t
		}
		// The API has also been seen using RFC3339 without a zone on other
		// fields, so try that before giving up on the value.
		if t, err := time.Parse("2006-01-02T15:04:05", strings.TrimSpace(*ts)); err == nil {
			return t
		}
	}
	return time.Time{}
}

// clusterName trims the platform's "<resource group>|<cluster>" encoding down to
// the cluster, which is the half anyone recognises.
func clusterName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "|"); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}
