// Package trivy implements a VulnSource backed by Trivy. It scans a container
// image and returns per-CVE detail — crucially including fix availability
// (FixedVersion), which drives true actionability and prioritisation.
//
// It shells out to the `trivy` binary:
//
//	trivy image --quiet --format json --scanners vuln <ref>
//
// Trivy pulls the image itself, so it needs network egress and, for private
// registries, credentials. Those are resolved here and handed over explicitly in
// an isolated docker config rather than left to Trivy's own keychain - see
// registryauth.WriteDockerConfig for why. Before that, this source could not read
// a private registry the rest of the tool could, which mattered most in the one
// place it is now used as a fallback: the images a scan provider failed on are
// usually the private ones.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/registryauth"
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

	// credentials resolves the credentials for a reference. Nil uses
	// registryauth.Credentials; injected so tests need no registry.
	credentials func(ref string) (*authn.AuthConfig, bool, error)
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

	// Credentials before the scan, in a config of this scan's own. When nothing
	// claims the registry the config is empty, so an anonymous pull stays
	// anonymous rather than silently picking up the ambient docker config.
	dir, cleanup, err := registryauth.IsolatedDockerConfig(image.Ref, s.credentials)
	if err != nil {
		return nil, fmt.Errorf("credentials for %s: %w", image.Ref, err)
	}
	defer cleanup()

	slog.DebugContext(ctx, "running trivy", "image", image.Ref, "severity", s.severity)
	cmd := exec.CommandContext(ctx, s.binary, args...)
	cmd.Env = append(os.Environ(), "DOCKER_CONFIG="+dir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// The reason leads, the exit status trails. "exit status 1: unauthorized"
		// reads the same to a human either way, but anything counting these by cause
		// cuts at the first clause - and with the wrapping the other way round, every
		// distinct failure folded to the bucket "exit status 1".
		return nil, fmt.Errorf("%s (%w)", scanFailureReason(stderr.String()), err)
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
	out = strings.TrimSpace(trailingID.ReplaceAllString(out, ""))
	// The innermost cause is the useful half; the wrapping chain above it is noise.
	if i := strings.LastIndex(out, ": "); i >= 0 && len(out)-i < 120 {
		return strings.TrimSpace(out[i+2:]) + " (while: " + firstCause(out[:i]) + ")"
	}
	return out
}

// trailingID matches a per-request identifier a registry appends to its errors -
// ACR ends an auth failure with "CorrelationId: <uuid>".
//
// Stripped before the cause is picked out, because the innermost-clause heuristic
// below would otherwise choose the identifier as the reason. That reported an
// expired credential as a bare UUID, which is unactionable to read and, once these
// are counted by cause, one metric bucket per request.
var trailingID = regexp.MustCompile(`(?i)[,.;]?\s*\b\w*(?:id|uuid)\s*[:=]\s*\S+\s*$`)

// firstCause returns the outermost wrapped context, which names what was being
// scanned when the innermost error happened.
func firstCause(s string) string {
	if i := strings.Index(s, ": "); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
