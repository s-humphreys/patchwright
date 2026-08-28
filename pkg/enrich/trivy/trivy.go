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
	"time"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

func init() {
	enrich.RegisterVulnSource("trivy", func(opts enrich.Options) (enrich.VulnSource, error) {
		return &source{
			binary:   opts.StringOr("binary", "trivy"),
			severity: opts.String("severity"), // e.g. "CRITICAL,HIGH"; empty = all
			timeout:  opts.StringOr("timeout", "5m"),
			dbRepo:   opts.String("db-repository"),
		}, nil
	})
}

type source struct {
	binary   string
	severity string
	timeout  string
	// dbRepo overrides where the vulnerability DB is pulled from. Empty means
	// Trivy's own default, which is a mirror list.
	dbRepo   string
	prepared bool // true once the DB has been pre-downloaded (see Prepare)
}

// dbDownloadAttempts is how many times Prepare will try to fetch the DB.
//
// Downloading it is the one step in a run that depends on a public CDN, and it
// is observably flaky: mirror.gcr.io serves a 404 for a layer it has just
// advertised in its own manifest, and the same command succeeds seconds later.
// Trivy does not retry that itself, so a single bad response would otherwise
// cost the entire assessment, including the provider data that needed no
// network at all.
const dbDownloadAttempts = 3

// dbDownloadBackoff is the wait before each retry. Short: a mirror 404 clears
// immediately, and anything that does not is not worth waiting minutes for.
var dbDownloadBackoff = []time.Duration{2 * time.Second, 5 * time.Second}

// fallbackDBRepository is tried when the default mirror list fails and the
// caller has not named a repository of its own. This is the upstream source
// rather than a cache of it, so it is not subject to the mirror's staleness.
const fallbackDBRepository = "ghcr.io/aquasecurity/trivy-db:2"

func (s *source) Name() string { return "trivy" }

// Prepare downloads the vulnerability DB once, up front, so concurrent scans
// don't race to update it. It is called once by the ImageScanner before the
// concurrent scan loop.
// It retries, and falls back to the upstream DB repository, because the download
// is the flakiest step in a run and losing a whole assessment to one bad CDN
// response is a poor trade.
func (s *source) Prepare(ctx context.Context) error {
	var lastErr error
	for attempt := 1; attempt <= dbDownloadAttempts; attempt++ {
		// Stick with the configured repository when there is one: the caller
		// naming a repository usually means the default is unreachable (an
		// air-gapped mirror), so silently reaching past it to the internet
		// would be wrong.
		repo := s.dbRepo
		if repo == "" && attempt > 1 {
			repo = fallbackDBRepository
		}
		if err := s.downloadDB(ctx, repo); err == nil {
			s.prepared = true
			return nil
		} else if lastErr = err; ctx.Err() != nil {
			// A cancelled context will not heal, so stop rather than burning
			// the remaining attempts on it.
			return lastErr
		}
		if attempt < dbDownloadAttempts {
			slog.WarnContext(ctx, "trivy vulnerability DB download failed, retrying",
				"attempt", attempt, "of", dbDownloadAttempts, "error", lastErr)
			select {
			case <-time.After(dbDownloadBackoff[min(attempt, len(dbDownloadBackoff))-1]):
			case <-ctx.Done():
				return lastErr
			}
		}
	}
	return lastErr
}

func (s *source) downloadDB(ctx context.Context, repo string) error {
	slog.DebugContext(ctx, "pre-downloading trivy vulnerability DB", "db_repository", repo)
	args := []string{"image", "--quiet", "--download-db-only"}
	if s.timeout != "" {
		args = append(args, "--timeout", s.timeout)
	}
	if repo != "" {
		args = append(args, "--db-repository", repo)
	}
	cmd := exec.CommandContext(ctx, s.binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy --download-db-only: %w: %s", err, scanFailureReason(stderr.String()))
	}
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
		// Class and Type say which ecosystem a result block came from:
		// "os-pkgs"/"debian" for the distribution's packages, "lang-pkgs"/"gomod"
		// for the application's own. That is the distinction between a fix a
		// rebuild delivers and one only the application's manifest can.
		Class           string      `json:"Class"`
		Type            string      `json:"Type"`
		Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
	} `json:"Results"`
}

type trivyVuln struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	InstalledVer    string `json:"InstalledVersion"`
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
		// The ecosystem comes from the result block rather than the finding, which is
		// where Trivy puts it.
		ecosystem := strings.ToLower(strings.TrimSpace(result.Type))
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
			if v.PkgName != "" {
				mv.Packages = []model.AffectedPackage{{
					Name: v.PkgName, Ecosystem: ecosystem, FixedIn: v.FixedVersion,
				}}
			}
			if v.PrimaryURL != "" {
				mv.Links = []string{v.PrimaryURL}
			}
			if cur, ok := byID[mv.ID]; ok {
				// One CVE routinely affects several packages in one image. Keeping
				// only the first would understate the work, so the lists merge even
				// when the surviving entry is the existing one.
				merged := append(cur.Packages, mv.Packages...)
				if !cur.FixAvailable && mv.FixAvailable {
					cur = mv
				}
				cur.Packages = merged
				byID[mv.ID] = cur
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
