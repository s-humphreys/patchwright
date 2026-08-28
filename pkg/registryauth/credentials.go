package registryauth

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// Credentials resolves the credentials for a registry reference, using the same
// keychains the rest of the tool pulls with.
//
// This exists so a subprocess can be handed credentials explicitly rather than
// left to find its own. Trivy's default path is the docker credential helper
// chain, which is what azure.go refuses to use: the helper carries GO-2026-6225,
// credential leakage to untrusted hosts, with no fixed version.
//
// The full AuthConfig is returned rather than a username and password, because
// for several registries there is no password. ACR and `az acr login` both hand
// back an identity token, and a signature that could only express user/pass
// silently reported those as unauthenticated - a private base image then looks
// unreadable, or worse resolves to a public image of the same name.
//
// ok is false when no keychain claims the registry, which is the normal case for
// a public one: the caller should proceed anonymously rather than fail.
func Credentials(ref string) (cfg *authn.AuthConfig, ok bool, err error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, false, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	auth, err := Keychain().Resolve(parsed.Context())
	if err != nil {
		return nil, false, fmt.Errorf("resolve credentials for %q: %w", ref, err)
	}
	if auth == authn.Anonymous {
		return nil, false, nil
	}
	cfg, err = auth.Authorization()
	if err != nil {
		return nil, false, fmt.Errorf("authorization for %q: %w", ref, err)
	}
	if cfg == nil || (cfg.Username == "" && cfg.Password == "" &&
		cfg.Auth == "" && cfg.IdentityToken == "" && cfg.RegistryToken == "") {
		return nil, false, nil
	}
	return cfg, true, nil
}
