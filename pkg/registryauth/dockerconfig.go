package registryauth

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// WriteDockerConfig writes a docker config directory containing exactly one
// registry's credentials, and nothing else - no credsStore, no credHelpers.
//
// Handing a subprocess an isolated config rather than setting TRIVY_USERNAME and
// TRIVY_PASSWORD is not incidental. Several registries authenticate with an
// identity token and no password at all, which those variables cannot express;
// ACR is one. Isolating it also means the subprocess cannot fall back to the
// ambient docker config and the credential helper chain that carries
// GO-2026-6225. See Credentials.
//
// The caller must call cleanup, which removes the directory and the live
// credential in it.
func WriteDockerConfig(ref string, cfg *authn.AuthConfig) (dir string, cleanup func(), err error) {
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

// IsolatedDockerConfig resolves the credentials for ref and writes them to a
// config directory of their own.
//
// resolve is injectable so callers can be tested without a registry; nil uses
// Credentials. An empty config is still written when nothing claims the
// registry, so an anonymous pull stays anonymous rather than silently picking up
// the ambient docker config.
func IsolatedDockerConfig(ref string, resolve func(string) (*authn.AuthConfig, bool, error)) (dir string, cleanup func(), err error) {
	if resolve == nil {
		resolve = Credentials
	}
	cfg, _, err := resolve(ref)
	if err != nil {
		return "", nil, err
	}
	return WriteDockerConfig(ref, cfg)
}
