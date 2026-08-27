package kube

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"k8s.io/client-go/rest"
	api "k8s.io/client-go/tools/clientcmd/api"
)

type stubCred struct {
	token   string
	expires time.Time
	calls   int
	err     error
}

func (s *stubCred) GetToken(context.Context, policy.TokenRequestOptions) (azureToken, error) {
	s.calls++
	if s.err != nil {
		return azureToken{}, s.err
	}
	return azureToken{Token: s.token, ExpiresOn: s.expires}, nil
}

func TestOneTokenServesEveryClusterAndEveryRequest(t *testing.T) {
	// A single AAD token is valid for every AAD-integrated cluster in the tenant, so
	// a whole fleet and thousands of list calls cost one token acquisition.
	cred := &stubCred{token: "aad", expires: time.Now().Add(time.Hour)}
	src := &azureTokenSource{cred: cred}
	for i := 0; i < 50; i++ {
		got, err := src.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got != "aad" {
			t.Fatalf("token = %q", got)
		}
	}
	if cred.calls != 1 {
		t.Errorf("acquired %d tokens, want 1", cred.calls)
	}
}

func TestATokenNearingExpiryIsRefreshedEarly(t *testing.T) {
	// A read that starts before expiry and lands after it fails as an authentication
	// error, which reads like a permissions problem rather than a clock one.
	cred := &stubCred{token: "first", expires: time.Now().Add(2 * time.Minute)}
	src := &azureTokenSource{cred: cred}
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	cred.token, cred.expires = "second", time.Now().Add(time.Hour)
	got, err := src.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != "second" {
		t.Errorf("token = %q, want a refreshed one: two minutes of validity is not enough", got)
	}
}

func TestAFailureToGetATokenIsReported(t *testing.T) {
	// Unlike a registry read, this cannot degrade to anonymous: an unauthenticated API
	// server read fails, and reporting a fleet as unreadable because of a token is a
	// different problem from reporting it as unreadable because of permissions.
	src := &azureTokenSource{cred: &stubCred{err: errors.New("no identity")}}
	if _, err := src.Token(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestApplyClearsWhateverTheKubeconfigCarried(t *testing.T) {
	// A kubeconfig for this mode carries a URL and a CA and nothing else. Silently
	// honouring a credential found in one would authenticate as something other than
	// the identity the operator configured.
	src := &azureTokenSource{cred: &stubCred{token: "aad", expires: time.Now().Add(time.Hour)}}
	cfg := &rest.Config{
		BearerToken:     "stale-service-account-token",
		BearerTokenFile: "/var/run/secrets/token",
		Username:        "someone",
		Password:        "hunter2",
		ExecProvider:    &api.ExecConfig{Command: "kubelogin"},
	}
	src.apply(cfg)
	if cfg.BearerToken != "" || cfg.BearerTokenFile != "" || cfg.Username != "" || cfg.Password != "" {
		t.Errorf("kubeconfig credentials survived: %+v", cfg)
	}
	if cfg.ExecProvider != nil {
		t.Error("an exec plugin survived: the image has no kubelogin, and using one would be a different identity")
	}
}

func TestTheTokenIsSentAsABearerHeader(t *testing.T) {
	src := &azureTokenSource{cred: &stubCred{token: "aad", expires: time.Now().Add(time.Hour)}}
	var seen string
	rt := &azureRoundTripper{source: src, next: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		seen = r.Header.Get("Authorization")
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://cluster.example/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if seen != "Bearer aad" {
		t.Errorf("Authorization = %q", seen)
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("the original request was modified: a RoundTripper must not do that")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAnUnknownAuthModeIsRejected(t *testing.T) {
	// Rather than silently falling back to the kubeconfig's own credentials, which
	// would read as working while authenticating as somebody else.
	s := &Source{authMode: "gcp", kubeconfig: "/nonexistent"}
	if _, err := s.restConfigs(); err == nil {
		t.Fatal("expected an unknown authMode to be rejected")
	}
}
