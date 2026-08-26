// Package intel implements the "public" exploit source: it enriches CVEs with
// CISA KEV membership (exploited in the wild) and FIRST EPSS scores (predicted
// probability of exploitation). Both are public feeds keyed by CVE id, so this
// needs network egress but no credentials.
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/httpretry"
)

const (
	defaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	defaultEPSSURL = "https://api.first.org/data/v1/epss"
	defaultBatch   = 100
)

func init() {
	enrich.RegisterExploitSource("public", func(opts enrich.Options) (enrich.ExploitSource, error) {
		return &public{
			http:    &http.Client{Timeout: 30 * time.Second},
			kevURL:  opts.StringOr("kevURL", defaultKEVURL),
			epssURL: opts.StringOr("epssURL", defaultEPSSURL),
			batch:   defaultBatch,
		}, nil
	})
}

type public struct {
	http    *http.Client
	kevURL  string
	epssURL string
	batch   int
}

func (p *public) Name() string { return "public" }

func (p *public) Lookup(ctx context.Context, cveIDs []string) (map[string]enrich.ExploitInfo, error) {
	kev, err := p.fetchKEV(ctx)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	epss, err := p.fetchEPSS(ctx, cveIDs)
	if err != nil {
		return nil, fmt.Errorf("epss: %w", err)
	}
	out := make(map[string]enrich.ExploitInfo, len(cveIDs))
	for _, id := range cveIDs {
		out[id] = enrich.ExploitInfo{EPSS: epss[id], KEV: kev[id]}
	}
	return out, nil
}

func (p *public) fetchKEV(ctx context.Context) (map[string]bool, error) {
	slog.DebugContext(ctx, "fetching CISA KEV catalog", "url", p.kevURL)
	body, err := p.get(ctx, p.kevURL)
	if err != nil {
		return nil, err
	}
	kev, err := parseKEV(body)
	if err != nil {
		return nil, err
	}
	slog.DebugContext(ctx, "fetched CISA KEV catalog", "entries", len(kev))
	return kev, nil
}

func (p *public) fetchEPSS(ctx context.Context, cveIDs []string) (map[string]float64, error) {
	scores := make(map[string]float64, len(cveIDs))
	for start := 0; start < len(cveIDs); start += p.batch {
		end := start + p.batch
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[start:end]
		u := fmt.Sprintf("%s?cve=%s&limit=%d", p.epssURL, url.QueryEscape(strings.Join(batch, ",")), len(batch))
		body, err := p.get(ctx, u)
		if err != nil {
			return nil, err
		}
		part, err := parseEPSS(body)
		if err != nil {
			return nil, err
		}
		for k, v := range part {
			scores[k] = v
		}
	}
	return scores, nil
}

func (p *public) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	// Retried: one 502 from a public feed used to fail the whole assessment, discarding
	// a completed scan of every image over one request in a hundred.
	resp, err := httpretry.Do(ctx, p.http, req, httpretry.Attempts)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// parseKEV extracts the set of CVE ids from CISA's KEV catalog JSON.
func parseKEV(data []byte) (map[string]bool, error) {
	var doc struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse kev json: %w", err)
	}
	set := make(map[string]bool, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if v.CveID != "" {
			set[v.CveID] = true
		}
	}
	return set, nil
}

// parseEPSS extracts CVE->EPSS score from a FIRST EPSS API response. Scores are
// returned as strings in the feed.
func parseEPSS(data []byte) (map[string]float64, error) {
	var doc struct {
		Data []struct {
			CVE  string `json:"cve"`
			EPSS string `json:"epss"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse epss json: %w", err)
	}
	out := make(map[string]float64, len(doc.Data))
	for _, d := range doc.Data {
		if d.CVE == "" {
			continue
		}
		score, err := strconv.ParseFloat(d.EPSS, 64)
		if err != nil {
			continue // skip unparseable rows rather than failing the batch
		}
		out[d.CVE] = score
	}
	return out, nil
}
