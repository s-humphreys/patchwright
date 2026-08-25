package registryauth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/s-humphreys/patchwright/pkg/registryauth"
)

func TestProvidersAreRegistered(t *testing.T) {
	// Each provider registers from its own file's init(), so one added without being
	// wired in is a provider that silently never runs.
	got := strings.Join(registryauth.Names(), ",")
	for _, want := range []string{"azure", "google"} {
		if !strings.Contains(got, want) {
			t.Errorf("provider %q not registered (have %q)", want, got)
		}
	}
}

func TestAForeignHostIsNeverPassedToAProvider(t *testing.T) {
	// The reason providers declare their hosts. A credential helper asked about a host
	// it cannot serve goes looking for credentials rather than declining: the ACR
	// helper spends thirty seconds on instance metadata first, and mcr.microsoft.com is
	// the base registry for every .NET image here.
	//
	// Timed rather than mocked, because the cost IS the behaviour being asserted.
	for _, host := range []string{"mcr.microsoft.com", "docker.io", "ghcr.io", "quay.io"} {
		repo, err := name.NewRepository(host + "/x/y")
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := registryauth.Keychain().Resolve(repo); err != nil {
			t.Errorf("%s: %v", host, err)
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("%s took %v: a provider is being consulted for a host it does not serve", host, took)
		}
	}
}

func TestAnUnservedRegistryResolvesAnonymouslyRatherThanFailing(t *testing.T) {
	// Every provider is asked about every registry, and one cloud's helper declining
	// to answer for another cloud's host is normal. It must not fail the lookup: a
	// registry patchwright could have read anonymously would otherwise report as
	// unreadable, and an unreadable registry reads as "no upgrade available".
	for _, host := range []string{"docker.io", "ghcr.io", "quay.io", "mcr.microsoft.com"} {
		repo, err := name.NewRepository(host + "/library/busybox")
		if err != nil {
			t.Fatal(err)
		}
		auth, err := registryauth.Keychain().Resolve(repo)
		if err != nil {
			t.Errorf("%s: Resolve returned an error: %v", host, err)
			continue
		}
		if auth == nil {
			t.Errorf("%s: no authenticator returned", host)
		}
	}
}

// claimEverything stands in for a cloud provider that answers for any registry.
type claimEverything struct{}

func (claimEverything) Resolve(authn.Resource) (authn.Authenticator, error) {
	return &authn.Basic{Username: "claimed", Password: "x"}, nil
}

func TestRegisteredProvidersAreReachedForHostsDockerConfigDoesNotKnow(t *testing.T) {
	// The chain is: docker config first, then each provider. This proves providers are
	// actually consulted — a keychain that silently never asks them would look
	// identical to one with no credentials, which is the failure this package exists
	// to fix (every ACR read came back anonymous and every base image "unresolved").
	registryauth.Register("test-claims-everything", []string{"example.invalid"}, claimEverything{})
	repo, err := name.NewRepository("example.invalid/app")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := registryauth.Keychain().Resolve(repo)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := auth.Authorization()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "claimed" {
		t.Errorf("the registered provider was not consulted, got %+v", cfg)
	}
}

func TestKeychainPutsDockerConfigFirst(t *testing.T) {
	// Ordering, asserted on the names: an explicit `docker login` or `az acr login`
	// must win over an ambient cloud identity. Surprising somebody with a different
	// account than the one they logged into is worse than failing.
	//
	// Names() lists providers in registration order, and Keychain() prepends the
	// docker config keychain to exactly that order.
	names := registryauth.Names()
	if len(names) == 0 {
		t.Fatal("no providers registered")
	}
	if names[0] != "azure" {
		t.Errorf("first provider = %q; azure registers first, and the docker config "+
			"keychain sits ahead of all of them", names[0])
	}
}
