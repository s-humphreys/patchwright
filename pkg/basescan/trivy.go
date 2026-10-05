package basescan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/s-humphreys/patchwright/pkg/registryauth"
	"github.com/s-humphreys/patchwright/pkg/trivydb"
)

// TrivyScanner scans one image reference by shelling out to the trivy binary.
//
// Separate from the trivy VulnSource in pkg/enrich/trivy, which answers a
// different question: that one maps an image to model.Vulnerability for the
// queue, and discards package and ecosystem detail. This one keeps exactly the
// detail the differential needs and none of the severity handling it does not.
type TrivyScanner struct {
	Binary  string // default "trivy"
	Timeout string // passed through as --timeout
	// DBRepository overrides where the vulnerability database is pulled from.
	// Empty uses Trivy's own mirror list, then trivydb.FallbackRepository.
	DBRepository string

	// mu serialises database preparation; prepared records that it succeeded.
	// A failure is deliberately not remembered: see Prepare.
	mu       sync.Mutex
	prepared bool

	// Credentials resolves the credentials for a reference. Defaults to
	// registryauth.Credentials. Injected so tests need no registry.
	Credentials func(ref string) (*authn.AuthConfig, bool, error)
}

func (t *TrivyScanner) Name() string { return "trivy" }

// ErrDBUnavailable marks a scan that did not run because the vulnerability
// database could not be prepared. It says nothing about the image, so nothing
// may be concluded or cached about the image from it.
var ErrDBUnavailable = errors.New("vulnerability database unavailable")

// ErrNotFound marks a reference the registry says does not exist: a base whose
// recorded digest or tag has since been deleted. Unlike any other failure it is
// an answer about the image, and retrying will not change it.
var ErrNotFound = errors.New("image not found in its registry")

// ErrInvalidReference marks a reference that is not a valid image reference at
// all. Like ErrNotFound it is deterministic: the same reference fails the same way
// every run, so it must never be treated as a failure that a retry could clear. It
// points at patchwright or at the label the reference was read from, not at the
// registry.
var ErrInvalidReference = errors.New("invalid image reference")

// Unmeasurable reports a scan failure that will recur on every run for the same
// reference, so its image is unmeasurable rather than unmeasured this run.
func Unmeasurable(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidReference)
}

// Prepare downloads the vulnerability database, before any scan.
//
// Serialised deliberately. Concurrent scans each racing to populate the database
// is the failure --skip-db-update exists to avoid, and doing it here means the
// bound on concurrent scans does not also become a bound on concurrent downloads.
//
// A failure is not remembered. It once was, behind a sync.Once, and one 404 from
// the mirror on the first run after a restart failed every base scan for the life
// of the process. The next caller tries again; the differential calls this once
// per run, so a lasting outage costs one bounded retry per run rather than one
// per image.
func (t *TrivyScanner) Prepare(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.prepared {
		return nil
	}
	if err := trivydb.Download(ctx, t.DBRepository, t.downloadDB); err != nil {
		return fmt.Errorf("%w: %w", ErrDBUnavailable, err)
	}
	t.prepared = true
	return nil
}

func (t *TrivyScanner) downloadDB(ctx context.Context, repo string) error {
	args := []string{"image", "--quiet", "--download-db-only"}
	if t.Timeout != "" {
		args = append(args, "--timeout", t.Timeout)
	}
	if repo != "" {
		args = append(args, "--db-repository", repo)
	}
	cmd := exec.CommandContext(ctx, t.binary(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy --download-db-only: %w: %s", err, lastLine(stderr.String()))
	}
	return nil
}

func (t *TrivyScanner) binary() string {
	if t.Binary != "" {
		return t.Binary
	}
	return "trivy"
}

// ScanRef scans one reference and returns what it contains.
func (t *TrivyScanner) ScanRef(ctx context.Context, ref string) (*Result, error) {
	// --cache-backend memory: concurrent `trivy image` processes fail on the
	// on-disk BoltDB cache's exclusive lock. --skip-db-update because the DB is
	// downloaded once, up front, rather than raced for by every scan.
	args := []string{
		"image", "--quiet", "--format", "json", "--scanners", "vuln",
		"--cache-backend", "memory", "--skip-db-update",
	}
	if t.Timeout != "" {
		args = append(args, "--timeout", t.Timeout)
	}
	args = append(args, ref)

	// Credentials are handed over explicitly rather than left to Trivy's own
	// keychain, which reaches for the docker credential helper carrying
	// GO-2026-6225. See registryauth.Credentials.
	//
	// Written as an isolated docker config rather than TRIVY_USERNAME/PASSWORD:
	// several registries authenticate with an identity token and no password at
	// all, which those variables cannot express. Isolating it also means Trivy
	// cannot fall back to the developer's own config and its credential helpers.
	// An isolated config either way. When nothing claims the registry the config
	// is empty, so an anonymous pull stays anonymous instead of silently picking
	// up the ambient docker config and its credential helpers.
	dir, cleanup, err := registryauth.IsolatedDockerConfig(ref, t.Credentials)
	if err != nil {
		if name.IsErrBadName(err) {
			err = fmt.Errorf("%w: %w", ErrInvalidReference, err)
		}
		return nil, fmt.Errorf("credentials for %s: %w", ref, err)
	}
	defer cleanup()

	// After credentials, deliberately. Resolving them costs nothing and fails
	// fast; the database download is a network fetch, and doing it first turns a
	// misconfigured identity into a slow failure - and made the test for that
	// path pass for the wrong reason.
	if err := t.Prepare(ctx); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, t.binary(), args...)
	cmd.Env = append(os.Environ(), "DOCKER_CONFIG="+dir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		switch {
		case notFound(stderr.String()):
			err = fmt.Errorf("%w: %w", ErrNotFound, err)
		case invalidReference(stderr.String()):
			err = fmt.Errorf("%w: %w", ErrInvalidReference, err)
		}
		return nil, fmt.Errorf("trivy %s: %w: %s", ref, err, lastLine(stderr.String()))
	}
	return parseRefReport(ref, stdout.Bytes())
}

// refReport is the subset of Trivy's output the differential needs.
type refReport struct {
	Metadata struct {
		OS struct {
			Family string `json:"Family"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Type            string `json:"Type"`
		Class           string `json:"Class"`
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			PkgName         string `json:"PkgName"`
			FixedVersion    string `json:"FixedVersion"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func parseRefReport(ref string, data []byte) (*Result, error) {
	var rep refReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse trivy json for %s: %w", ref, err)
	}
	out := &Result{
		Ref:        ref,
		OSFamily:   rep.Metadata.OS.Family,
		Ecosystems: map[string]bool{},
		CVEs:       map[string][]Package{},
	}
	for _, res := range rep.Results {
		eco := strings.ToLower(res.Type)
		if eco != "" {
			// Recorded from the result block, not from the vulnerabilities in it:
			// an ecosystem with no CVEs is still present in the image, and it is
			// the presence that decides whether a provider-named package could
			// belong here.
			out.Ecosystems[eco] = true
		}
		// Only a language result's target is a file somebody edits. An OS result's
		// target is the distro name, which is not where anybody makes a change.
		var path string
		if res.Class == "lang-pkgs" {
			path = res.Target
		}
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" {
				continue
			}
			out.CVEs[v.VulnerabilityID] = append(out.CVEs[v.VulnerabilityID],
				Package{Name: v.PkgName, Ecosystem: eco, FixedVersion: v.FixedVersion, Path: path})
		}
	}
	return out, nil
}

// notFound reports a registry saying the reference does not exist. Matched on the
// OCI distribution spec's error codes, which registries return verbatim and Trivy
// passes through, rather than on Trivy's own wording around them.
func notFound(stderr string) bool {
	return strings.Contains(stderr, "MANIFEST_UNKNOWN") || strings.Contains(stderr, "NAME_UNKNOWN")
}

// invalidReference reports Trivy rejecting the reference itself, before any registry
// was asked. Matched on the reference parsers' own messages, which Trivy passes
// through: go-containerregistry's and the docker distribution library's.
func invalidReference(stderr string) bool {
	return strings.Contains(stderr, "could not parse reference") ||
		strings.Contains(stderr, "invalid reference format")
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output"
	}
	lines := strings.Split(s, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
