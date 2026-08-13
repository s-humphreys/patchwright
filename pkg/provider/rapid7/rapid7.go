// Package rapid7 implements the Rapid7 provider. It is the reference provider
// and the first supported source of scan data. All Rapid7-specific knowledge —
// the InsightCloudSec CSV column layout, the resource_id encoding, the meaning
// of each field — is contained here; everything it emits is patchwright's
// generic model.
//
// Modes:
//
//	csv (default) — parse an exported InsightCloudSec "Resources" CSV.
//	api           — query the InsightCloudSec API directly. Needs "base-url" and
//	                the RAPID7_API_KEY environment variable. Reports why an image
//	                was not assessed, which the CSV export cannot.
package rapid7

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/provider"
)

func init() {
	provider.Register("rapid7", func(opts provider.Options) (provider.Provider, error) {
		mode := opts.StringOr("mode", "csv")
		switch mode {
		case "csv":
			path := opts.String("input")
			if path == "" {
				return nil, fmt.Errorf("rapid7 csv mode requires option \"input\" (path to the exported CSV)")
			}
			return &csvProvider{path: path}, nil
		case "api":
			// The key comes from the environment, never from options: options are
			// populated from config files and Helm values, which live in git.
			return newAPIProvider(opts.String("base-url"), apiKeyFromEnv())
		default:
			return nil, fmt.Errorf("rapid7: unknown mode %q (want csv or api)", mode)
		}
	})
}

// EnvAPIKey holds the InsightCloudSec API key. Read from the environment, never
// from options: options come from config files and Helm values, which live in git.
const EnvAPIKey = "RAPID7_API_KEY"

func apiKeyFromEnv() string { return os.Getenv(EnvAPIKey) }

// csvProvider reads an exported InsightCloudSec "Resources" CSV.
type csvProvider struct {
	path string
}

func (p *csvProvider) Name() string { return "rapid7" }

// lastAssessmentLayout is the timestamp format used in the CSV export, e.g.
// "2026-08-07 18:59:47".
const lastAssessmentLayout = "2006-01-02 15:04:05"

func (p *csvProvider) Fetch(ctx context.Context) ([]model.Occurrence, error) {
	f, err := os.Open(p.path)
	if err != nil {
		return nil, fmt.Errorf("open rapid7 csv: %w", err)
	}
	defer f.Close()
	return parseCSV(ctx, f)
}

// parseCSV is separated from Fetch so it can be exercised directly in tests.
func parseCSV(ctx context.Context, r io.Reader) ([]model.Occurrence, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // tolerate trailing/empty fields

	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read csv header: %w", err)
	}
	col := make(map[string]int, len(header))
	for i, name := range header {
		col[strings.TrimSpace(name)] = i
	}
	for _, required := range []string{"image_id", "resource_id", "resource_type", "account"} {
		if _, ok := col[required]; !ok {
			return nil, fmt.Errorf("rapid7 csv missing required column %q", required)
		}
	}

	var occurrences []model.Occurrence
	line := 1
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read csv line %d: %w", line+1, err)
		}
		line++

		get := func(name string) string {
			i, ok := col[name]
			if !ok || i >= len(rec) {
				return ""
			}
			return strings.TrimSpace(rec[i])
		}

		occurrences = append(occurrences, recordToOccurrence(get))
	}
	slog.DebugContext(ctx, "parsed rapid7 csv", "occurrences", len(occurrences))
	return occurrences, nil
}

// recordToOccurrence maps one CSV row (via a column accessor) to the generic
// model. This is the single place Rapid7's schema is interpreted.
func recordToOccurrence(get func(string) string) model.Occurrence {
	namespace := namespaceFromResourceID(get("resource_id"))

	dims := map[string]string{
		"cloud":             get("cloud"),
		"account":           get("account"),
		"account_id":        get("account_id"),
		"namespace":         namespace,
		"resource_type":     get("resource_type"),
		"resource_name":     get("resource_name"),
		"public_accessible": get("public_accessible"),
	}

	counts := model.Counts{}
	for sev, colName := range map[string]string{
		model.SeverityCritical: "critical_count",
		model.SeverityHigh:     "high_count",
		model.SeverityMedium:   "medium_count",
		model.SeverityLow:      "low_count",
		"none":                 "none_count",
	} {
		if n := atoi(get(colName)); n > 0 {
			counts[sev] = n
		}
	}

	// An empty last_assessment means InsightCloudSec never assessed this image
	// (it reports severity UNKNOWN and zero counts for these). That is a
	// coverage gap, not a clean bill of health, so record it explicitly.
	var lastSeen time.Time
	assessed := false
	if ts := get("last_assessment"); ts != "" {
		assessed = true
		if t, err := time.Parse(lastAssessmentLayout, ts); err == nil {
			lastSeen = t
		}
	}

	return model.Occurrence{
		Image: model.ParseImageRef(get("image_id")),
		Resource: model.Resource{
			ID:         get("resource_id"),
			Type:       get("resource_type"),
			Name:       get("resource_name"),
			Dimensions: dims,
			Labels:     map[string]string{}, // labels are not present in the CSV; live reconciliation supplies them
		},
		Counts:    counts,
		RiskScore: atof(get("riskscore")),
		LastSeen:  lastSeen,
		Assessed:  assessed,
	}
}

// namespaceFromResourceID extracts the Kubernetes namespace from Rapid7's
// resource_id encoding, which is colon-delimited as
// "<type>:<n>:<namespace>:<uid>:" — e.g.
// "kubernetesdaemonset:67:kube-system:f464407a-...:".
func namespaceFromResourceID(id string) string {
	parts := strings.Split(id, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func atof(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}
