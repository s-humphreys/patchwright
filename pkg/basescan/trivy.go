package basescan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/s-humphreys/patchwright/pkg/registryauth"
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
	// Empty uses Trivy's own mirror list.
	DBRepository string

	// prepared guards the one-time database download.
	prepared sync.Once
	prepErr  error

	// Credentials resolves the credentials for a reference. Defaults to
	// registryauth.Credentials. Injected so tests need no registry.
	Credentials func(ref string) (*authn.AuthConfig, bool, error)
}

func (t *TrivyScanner) Name() string { return "trivy" }

// prepare downloads the vulnerability database once, before any scan.
//
// Serialised deliberately. Concurrent scans each racing to populate the database
// is the failure --skip-db-update exists to avoid, and doing it here means the
// bound on concurrent scans does not also become a bound on concurrent downloads.
func (t *TrivyScanner) prepare(ctx context.Context) error {
	t.prepared.Do(func() {
		args := []string{"image", "--quiet", "--download-db-only"}
		if t.Timeout != "" {
			args = append(args, "--timeout", t.Timeout)
		}
		if t.DBRepository != "" {
			args = append(args, "--db-repository", t.DBRepository)
		}
		cmd := exec.CommandContext(ctx, t.binary(), args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.prepErr = fmt.Errorf("trivy --download-db-only: %w: %s", err, lastLine(stderr.String()))
		}
	})
	return t.prepErr
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
	resolve := t.Credentials
	if resolve == nil {
		resolve = registryauth.Credentials
	}
	cfg, _, err := resolve(ref)
	if err != nil {
		return nil, fmt.Errorf("credentials for %s: %w", ref, err)
	}
	// An isolated config either way. When nothing claims the registry the config
	// is empty, so an anonymous pull stays anonymous instead of silently picking
	// up the ambient docker config and its credential helpers.
	dir, cleanup, err := writeDockerConfig(ref, cfg)
	if err != nil {
		return nil, fmt.Errorf("credentials for %s: %w", ref, err)
	}
	defer cleanup()

	// After credentials, deliberately. Resolving them costs nothing and fails
	// fast; the database download is a network fetch, and doing it first turns a
	// misconfigured identity into a slow failure - and made the test for that
	// path pass for the wrong reason.
	if err := t.prepare(ctx); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, t.binary(), args...)
	cmd.Env = append(os.Environ(), "DOCKER_CONFIG="+dir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
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
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			PkgName         string `json:"PkgName"`
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
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" {
				continue
			}
			out.CVEs[v.VulnerabilityID] = append(out.CVEs[v.VulnerabilityID],
				Package{Name: v.PkgName, Ecosystem: eco})
		}
	}
	return out, nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output"
	}
	lines := strings.Split(s, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// writeDockerConfig writes a config containing exactly one registry's credentials,
// and nothing else - no credsStore, no credHelpers.
func writeDockerConfig(ref string, cfg *authn.AuthConfig) (dir string, cleanup func(), err error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return "", nil, err
	}
	dir, err = os.MkdirTemp("", "pw-docker-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	entry := map[string]string{}
	if cfg == nil {
		cfg = &authn.AuthConfig{}
	}
	if cfg.Auth != "" {
		entry["auth"] = cfg.Auth
	}
	if cfg.Username != "" {
		entry["username"] = cfg.Username
	}
	if cfg.Password != "" {
		entry["password"] = cfg.Password
	}
	if cfg.IdentityToken != "" {
		entry["identitytoken"] = cfg.IdentityToken
	}
	if cfg.RegistryToken != "" {
		entry["registrytoken"] = cfg.RegistryToken
	}
	body, err := json.Marshal(map[string]any{
		"auths": map[string]any{parsed.Context().RegistryStr(): entry},
	})
	if err != nil {
		cleanup()
		return "", nil, err
	}
	// 0600: the file holds a live registry credential for as long as the scan runs.
	if err := os.WriteFile(filepath.Join(dir, "config.json"), body, 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}
