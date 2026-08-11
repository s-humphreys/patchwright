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
	prepared bool // true once the DB has been pre-downloaded (see Prepare)
}

func (s *source) Name() string { return "trivy" }

// Prepare downloads the vulnerability DB once, up front, so concurrent scans
// don't race to update it. It is called once by the ImageScanner before the
// concurrent scan loop.
func (s *source) Prepare(ctx context.Context) error {
	slog.DebugContext(ctx, "pre-downloading trivy vulnerability DB")
	args := []string{"image", "--quiet", "--download-db-only"}
	if s.timeout != "" {
		args = append(args, "--timeout", s.timeout)
	}
	cmd := exec.CommandContext(ctx, s.binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy --download-db-only: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	s.prepared = true
	return nil
}

func (s *source) Scan(ctx context.Context, image model.Image) ([]model.Vulnerability, error) {
	// --cache-backend memory avoids Trivy's on-disk BoltDB cache, whose
	// exclusive lock makes concurrent `trivy image` processes fail with
	// "cache may be in use by another process". --skip-db-update (safe once
	// Prepare has run) avoids concurrent DB downloads.
	args := []string{"image", "--quiet", "--format", "json", "--scanners", "vuln", "--cache-backend", "memory"}
	if s.prepared {
		args = append(args, "--skip-db-update")
	}
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
		return nil, fmt.Errorf("%w: %s", err, scanFailureReason(stderr.String()))
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

// scanFailureReason reduces Trivy's stderr to the part that explains the failure.
//
// Trivy prefixes a timestamp and the words "FATAL Fatal error", then nests the
// cause through several layers of wrapping. Reproduced verbatim inside our own
// WARN line that reads like the tool crashed, rather than one image out of 65
// failing to scan, which is how a handled timeout gets mistaken for an outage.
func scanFailureReason(stderr string) string {
	out := strings.TrimSpace(stderr)
	if out == "" {
		return "no output"
	}
	// Trivy prints progress above the error; the error itself is the last line,
	// with its causes appended to it.
	lines := strings.Split(out, "\n")
	out = strings.TrimSpace(lines[len(lines)-1])
	if i := strings.Index(out, "Fatal error"); i >= 0 {
		out = out[i+len("Fatal error"):]
	}
	out = strings.TrimSpace(strings.TrimLeft(out, "\t "))
	// The innermost cause is the useful half; the wrapping chain above it is noise.
	if i := strings.LastIndex(out, ": "); i >= 0 && len(out)-i < 120 {
		return strings.TrimSpace(out[i+2:]) + " (while: " + firstCause(out[:i]) + ")"
	}
	return out
}

// firstCause returns the outermost wrapped context, which names what was being
// scanned when the innermost error happened.
func firstCause(s string) string {
	if i := strings.Index(s, ": "); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
