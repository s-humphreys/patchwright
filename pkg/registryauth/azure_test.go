package registryauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// stubCred stands in for whatever Azure identity the process has.
type stubCred struct {
	token string
	err   error
	calls int
}

func (s *stubCred) GetToken(context.Context, policy.TokenRequestOptions) (azcoreToken, error) {
	s.calls++
	if s.err != nil {
		return azcoreToken{}, s.err
	}
	return azcoreToken{Token: s.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestExchangeSendsTheDocumentedFormAndReadsTheRefreshToken(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/exchange" {
			t.Errorf("path = %q, want /oauth2/exchange", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		gotForm = r.PostForm
		_, _ = w.Write([]byte(`{"refresh_token":"acr-refresh"}`))
	}))
	defer srv.Close()

	// The exchange talks to the registry host it was asked about and nowhere else,
	// which is the whole point of not using a helper that leaks credentials to
	// untrusted hosts (GO-2026-6225).
	registry := strings.TrimPrefix(srv.URL, "https://")
	client := srv.Client()
	got, err := exchangeWith(context.Background(), client, registry, "aad-token")
	if err != nil {
		t.Fatal(err)
	}
	if got != "acr-refresh" {
		t.Errorf("refresh token = %q", got)
	}
	// Parsed rather than string-matched: the form is URL-encoded, so a registry with a
	// port is service=127.0.0.1%3A5000 on the wire and a substring check on the plain
	// value fails against correct code.
	for field, want := range map[string]string{
		"grant_type":   "access_token",
		"access_token": "aad-token",
		"service":      registry,
	} {
		if got := gotForm.Get(field); got != want {
			t.Errorf("form %s = %q, want %q", field, got, want)
		}
	}
}

func TestExchangeRejectsAnEmptyRefreshToken(t *testing.T) {
	// A 200 with no token is a failure, not a credential. Presenting an empty password
	// would produce a 401 that looks like a permissions problem rather than a broken
	// exchange.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if _, err := exchangeWith(context.Background(), srv.Client(), strings.TrimPrefix(srv.URL, "https://"), "t"); err == nil {
		t.Fatal("expected an error when no refresh token is returned")
	}
}

func TestNoIdentityResolvesAnonymouslyRatherThanFailing(t *testing.T) {
	// An anonymous read of a private registry fails with a 401 naming the registry,
	// which the report shows as a remediation blocker somebody can act on. An error
	// here would fail the whole lookup and lose that.
	k := &acrKeychain{}
	k.credOnce.Do(func() { k.credErr = errNoIdentity })
	repo, err := name.NewRepository("example.azurecr.io/app")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := k.Resolve(repo)
	if err != nil {
		t.Fatalf("Resolve returned an error: %v", err)
	}
	if auth != authn.Anonymous {
		t.Errorf("want anonymous, got %#v", auth)
	}
}

func TestATokenIsCachedPerRegistry(t *testing.T) {
	// One assessment reads hundreds of images from one registry, and each exchange is
	// two network round trips.
	k := &acrKeychain{}
	k.store("example.azurecr.io", "cached", time.Now().Add(time.Hour))
	repo, err := name.NewRepository("example.azurecr.io/app")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := k.Resolve(repo)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := auth.Authorization()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "cached" || cfg.Username != acrNullGUID {
		t.Errorf("got %+v, want the cached token with the null GUID username", cfg)
	}
}

func TestAnExpiredCachedTokenIsNotReused(t *testing.T) {
	k := &acrKeychain{}
	k.store("example.azurecr.io", "stale", time.Now().Add(-time.Minute))
	if _, ok := k.fromCache("example.azurecr.io"); ok {
		t.Error("an expired token must not be served")
	}
}
