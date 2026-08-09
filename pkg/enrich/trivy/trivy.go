// Package trivy implements a VulnSource backed by Trivy. It scans a container
// image and returns per-CVE detail — crucially including fix availability
// (FixedVersion), which drives true actionability and prioritisation.
//
// It shells out to the `trivy` binary:
//
//	trivy image --quiet --format json --scanners vuln <ref>
//
// Trivy pulls the image itself, so it needs network egress and, for private
// registries, credentials via the standard docker config / cloud keychain.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

func init() {
	enrich.RegisterVulnSource("trivy", func(opts enrich.Options) (enrich.VulnSource, error) {
		return &source{
			binary:   opts.StringOr("binary", "trivy"),
			severity: opts.String("severity"), // e.g. "CRITICAL,HIGH"; empty = all
			timeout:  opts.StringOr("timeout", "5m"),
		}, nil
	})
}

type source struct {
	binary   string
	severity string
	timeout  string
}

func (s *source) Name() string { return "trivy" }

func (s *source) Scan(ctx context.Context, image model.Image) ([]model.Vulnerability, error) {
	args := []string{"image", "--quiet", "--format", "json", "--scanners", "vuln"}
	if s.severity != "" {
		args = append(args, "--severity", s.severity)
	}
	if s.timeout != "" {
		args = append(args, "--timeout", s.timeout)
	}
	args = append(args, image.Ref)

	slog.DebugContext(ctx, "running trivy", "image", image.Ref, "severity", s.severity)
	cmd := exec.CommandContext(ctx, s.binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return parseReport(stdout.Bytes())
}

// trivyReport is the subset of Trivy's JSON output we consume.
type trivyReport struct {
	Results []struct {
		Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
	} `json:"Results"`
}

type trivyVuln struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	FixedVersion    string `json:"FixedVersion"`
	Severity        string `json:"Severity"`
	Title           string `json:"Title"`
	Description     string `json:"Description"`
	PrimaryURL      string `json:"PrimaryURL"`
	CVSS            map[string]struct {
		V3Score float64 `json:"V3Score"`
	} `json:"CVSS"`
}

// parseReport maps a Trivy JSON report to model vulnerabilities, deduped by CVE
// id (a CVE can appear for several packages), preferring an entry with a fix.
func parseReport(data []byte) ([]model.Vulnerability, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}

	byID := make(map[string]model.Vulnerability)
	var order []string
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			if v.VulnerabilityID == "" {
				continue
			}
			mv := model.Vulnerability{
				ID:           v.VulnerabilityID,
				Severity:     strings.ToLower(v.Severity),
				CVSS:         maxV3(v.CVSS),
				FixAvailable: v.FixedVersion != "",
				FixedVersion: v.FixedVersion,
				Description:  firstNonEmpty(v.Title, v.Description),
			}
			if v.PrimaryURL != "" {
				mv.Links = []string{v.PrimaryURL}
			}
			if cur, ok := byID[mv.ID]; ok {
				if !cur.FixAvailable && mv.FixAvailable {
					byID[mv.ID] = mv
				}
				continue
			}
			byID[mv.ID] = mv
			order = append(order, mv.ID)
		}
	}

	out := make([]model.Vulnerability, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}

func maxV3(cvss map[string]struct {
	V3Score float64 `json:"V3Score"`
}) float64 {
	max := 0.0
	for _, c := range cvss {
		if c.V3Score > max {
			max = c.V3Score
		}
	}
	return max
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
