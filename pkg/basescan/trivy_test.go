package basescan

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
)

// A trimmed real Trivy report: an OS result and a language result, one of which
// has no vulnerabilities.
const report = `{
  "Metadata": {"OS": {"Family": "azurelinux", "Name": "3.0"}},
  "Results": [
    {"Type": "azurelinux", "Class": "os-pkgs", "Vulnerabilities": [
      {"VulnerabilityID": "CVE-1", "PkgName": "openssl"},
      {"VulnerabilityID": "CVE-1", "PkgName": "openssl-libs"},
      {"VulnerabilityID": "CVE-2", "PkgName": "zlib"}
    ]},
    {"Type": "dotnet-core", "Class": "lang-pkgs", "Vulnerabilities": []}
  ]
}`

func TestParseKeepsPackagesAndEcosystems(t *testing.T) {
	got, err := parseRefReport("base:1", []byte(report))
	if err != nil {
		t.Fatal(err)
	}
	if got.OSFamily != "azurelinux" {
		t.Errorf("OSFamily = %q", got.OSFamily)
	}
	if len(got.CVEs["CVE-1"]) != 2 {
		t.Errorf("CVE-1 affects two packages here, got %+v", got.CVEs["CVE-1"])
	}
	if !got.Has("CVE-2") || got.Has("CVE-404") {
		t.Error("Has should reflect exactly what the report listed")
	}
	// An ecosystem with no CVEs is still present in the image, and presence is
	// what decides whether a provider-named package could belong to it.
	if !got.Ecosystems["dotnet-core"] {
		t.Error("an ecosystem with no vulnerabilities is still in the image")
	}
	if !got.Ecosystems["azurelinux"] {
		t.Error("missing the OS ecosystem")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	// A non-zero exit is handled by the caller; malformed JSON on success is not,
	// and silently returning an empty result would read as a clean base image -
	// which would attribute every CVE to the application.
	if _, err := parseRefReport("base:1", []byte("not json")); err == nil {
		t.Error("malformed output must be an error, not an empty base image")
	}
}

func TestScanRefFailsWhenCredentialsCannotBeResolved(t *testing.T) {
	// Running the scan anonymously after a credential error would report a
	// private base image as unreadable for the wrong reason, or worse, succeed
	// against a public image of the same name.
	s := &TrivyScanner{
		Credentials: func(string) (*authn.AuthConfig, bool, error) {
			return nil, false, errors.New("no identity")
		},
	}
	_, err := s.ScanRef(context.Background(), "example.azurecr.io/base:1")
	if err == nil {
		t.Fatal("a credential failure must not fall through to an anonymous pull")
	}
	// Asserted on the message so this cannot pass merely because trivy is absent
	// from the machine, which would make it a test of the environment.
	if !strings.Contains(err.Error(), "credentials for") {
		t.Errorf("expected a credential error, got %v", err)
	}
}

func TestDockerConfigCarriesAnIdentityTokenAndNothingElse(t *testing.T) {
	// ACR and `az acr login` authenticate with an identity token and no password.
	// An earlier version wrote TRIVY_USERNAME/TRIVY_PASSWORD, which cannot express
	// that: the token was dropped and every private base image failed to pull.
	dir, cleanup, err := writeDockerConfig("example.azurecr.io/base:1",
		&authn.AuthConfig{Username: "00000000-0000-0000-0000-000000000000", IdentityToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Auths map[string]map[string]string `json:"auths"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	entry, ok := got.Auths["example.azurecr.io"]
	if !ok {
		t.Fatalf("no entry for the registry: %s", b)
	}
	if entry["identitytoken"] != "tok" {
		t.Errorf("identity token not written: %v", entry)
	}

	// The whole point of writing our own config is that Trivy cannot reach the
	// docker credential helpers, which carry GO-2026-6225.
	if s := string(b); strings.Contains(s, "credsStore") || strings.Contains(s, "credHelpers") {
		t.Errorf("config must not enable any credential helper: %s", s)
	}
	// One registry only: a config naming others would send credentials to hosts
	// this scan has no business authenticating to.
	if len(got.Auths) != 1 {
		t.Errorf("expected exactly one registry, got %v", got.Auths)
	}

	info, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("credential file mode = %o, want 600", perm)
	}
}

func TestDockerConfigIsEmptyWhenNothingClaimsTheRegistry(t *testing.T) {
	// An anonymous pull must stay anonymous rather than inheriting the developer's
	// own docker config and its helpers.
	dir, cleanup, err := writeDockerConfig("docker.io/library/alpine:3", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "credsStore") {
		t.Errorf("unexpected helper config: %s", b)
	}
}

func TestDockerConfigIsRemovedAfterUse(t *testing.T) {
	// It holds a live registry credential; leaving one temp dir per scan behind
	// would leave hundreds on disk after a run.
	dir, cleanup, err := writeDockerConfig("example.azurecr.io/base:1", &authn.AuthConfig{IdentityToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("credential directory survived cleanup: %v", err)
	}
}
