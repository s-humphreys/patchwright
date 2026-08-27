package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// The sign-in flow end to end, against a provider that actually issues tokens.
//
// This exists because the cheaper tests could not tell "rejected because the state did
// not match" from "rejected because the token endpoint was unreachable". With the CSRF
// comparison deleted they still passed, which made them worse than no tests: they
// asserted that a request was refused without saying why, and the why is the entire
// control. A working provider means a refusal can only come from the control under test.

// fakeProvider is a minimal OIDC provider: discovery, JWKS, and a token endpoint that
// signs an ID token for whoever it is told to.
type fakeProvider struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	issuer string

	// What the next token exchange should assert about the user.
	subject string
	email   string
	groups  []string
	// nonce is what the ID token will carry. Empty means "echo whatever the client
	// asked for", which is the honest provider; setting it simulates one that returns
	// a token minted for a different attempt.
	nonce string
	// lastNonce records what the authorize step asked for, so the token endpoint can
	// echo it.
	lastNonce string
	audience  string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{key: key, subject: "user-1", email: "someone@example.com", audience: "test-client"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.issuer,
			"authorization_endpoint":                p.issuer + "/authorize",
			"token_endpoint":                        p.issuer + "/token",
			"jwks_uri":                              p.issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: key.Public(), KeyID: "test", Algorithm: "RS256", Use: "sig",
		}}})
	})
	// The authorize endpoint records the nonce and bounces straight back, standing in
	// for a user who signs in successfully.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		p.lastNonce = r.URL.Query().Get("nonce")
		redirect := r.URL.Query().Get("redirect_uri")
		http.Redirect(w, r, fmt.Sprintf("%s?code=the-code&state=%s",
			redirect, url.QueryEscape(r.URL.Query().Get("state"))), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		// x/oauth2 parses a token response as form-encoded unless the content type
		// says otherwise, so omitting this made every exchange fail with "missing
		// access_token" - a fault in the double, not in the code under test.
		w.Header().Set("Content-Type", "application/json")
		nonce := p.nonce
		if nonce == "" {
			nonce = p.lastNonce
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"id_token":     p.idToken(t, nonce),
			"expires_in":   3600,
		})
	})
	p.srv = httptest.NewServer(mux)
	p.issuer = p.srv.URL
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) idToken(t *testing.T, nonce string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss":    p.issuer,
		"aud":    p.audience,
		"sub":    p.subject,
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"nonce":  nonce,
		"email":  p.email,
		"groups": p.groups,
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// signInServer wires a Server to the fake provider, with the given restrictions.
func signInServer(t *testing.T, p *fakeProvider, cfg OIDCConfig) (*Server, *httptest.Server) {
	t.Helper()
	s := New(stubAssessor{findings: nil})
	// The page is served too, so a redirect can be followed to something real.
	app := httptest.NewServer(s.Handler())
	t.Cleanup(app.Close)

	cfg.IssuerURL = p.issuer
	cfg.ClientID = "test-client"
	cfg.ClientSecret = "test-secret"
	cfg.RedirectURL = app.URL + callbackPath
	out, err := s.WithOIDC(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Rebuild the handler now sign-in routes exist.
	app.Config.Handler = out.Handler()
	return out, app
}

// browser is an http.Client that keeps cookies and follows redirects, i.e. the thing
// this flow is actually for.
func browser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func TestSomebodyCanActuallySignIn(t *testing.T) {
	p := newFakeProvider(t)
	_, app := signInServer(t, p, OIDCConfig{})

	c := browser(t)
	// Straight to a protected page, as somebody following a link would.
	req, _ := http.NewRequest(http.MethodGet, app.URL+"/?team=orders", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 after a completed sign-in", resp.StatusCode)
	}
	// And they land where they were going, not at the root.
	if got := resp.Request.URL.RequestURI(); got != "/?team=orders" {
		t.Errorf("landed at %q, want the page they asked for", got)
	}
	// A session cookie now exists, so the next request needs no round trip.
	u, _ := url.Parse(app.URL)
	var found bool
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == sessionCookie {
			found = true
		}
	}
	if !found {
		t.Error("no session cookie was issued")
	}
}

func TestTheCallbackRefusesAStateThatWasNotIssued(t *testing.T) {
	// The CSRF control, isolated: the provider works, the code is real, and the ONLY
	// thing wrong is the state. An earlier version of this test passed with the
	// comparison deleted, because the token endpoint was unreachable and every path
	// ended in the same 403.
	p := newFakeProvider(t)
	_, app := signInServer(t, p, OIDCConfig{})
	c := browser(t)

	// Start properly, so a valid state cookie is in the jar.
	req, _ := http.NewRequest(http.MethodGet, app.URL+loginPath, nil)
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}

	// Now come back with a state the server never issued.
	resp, err := c.Get(app.URL + callbackPath + "?code=the-code&state=forged")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a state that was never issued", resp.StatusCode)
	}
}

func TestAnIDTokenMintedForAnotherAttemptIsRefused(t *testing.T) {
	// The nonce control. Everything else is valid: correct issuer, audience, signature
	// and a state the server did issue. Only the nonce belongs to a different attempt.
	p := newFakeProvider(t)
	p.nonce = "some-other-attempts-nonce"
	_, app := signInServer(t, p, OIDCConfig{})
	c := browser(t)

	req, _ := http.NewRequest(http.MethodGet, app.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 when the id token's nonce is not ours", resp.StatusCode)
	}
}

func TestGroupRestrictionsAreEnforcedAgainstARealToken(t *testing.T) {
	p := newFakeProvider(t)
	p.groups = []string{"data-platform"}
	_, app := signInServer(t, p, OIDCConfig{AllowedGroups: []string{"platform-engineering"}})

	c := browser(t)
	req, _ := http.NewRequest(http.MethodGet, app.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for somebody outside the permitted group", resp.StatusCode)
	}

	// Same provider, same user, group now permitted: the restriction is the only thing
	// that changed.
	p.groups = []string{"platform-engineering"}
	_, app2 := signInServer(t, p, OIDCConfig{AllowedGroups: []string{"platform-engineering"}})
	c2 := browser(t)
	req2, _ := http.NewRequest(http.MethodGet, app2.URL+"/", nil)
	req2.Header.Set("Accept", "text/html")
	resp2, err := c2.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 for a member of the permitted group", resp2.StatusCode)
	}
}

func TestSigningOutMeansSigningInAgain(t *testing.T) {
	p := newFakeProvider(t)
	_, app := signInServer(t, p, OIDCConfig{})
	c := browser(t)

	req, _ := http.NewRequest(http.MethodGet, app.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(app.URL + logoutPath); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(app.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == sessionCookie && ck.Value != "" {
			t.Error("the session survived signing out")
		}
	}
}

func TestAMisconfiguredIssuerFailsAtStartupNotOnSomebodysFirstSignIn(t *testing.T) {
	// A sign-in page that only fails when somebody tries to use it is a page nobody
	// tests until it matters.
	// A server that answers, badly. An unroutable address would do the same job in
	// principle and took thirty seconds waiting on a connect timeout, which is thirty
	// seconds added to every CI run for no extra assurance.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no discovery document here", http.StatusNotFound)
	}))
	defer broken.Close()

	s := New(stubAssessor{})
	_, err := s.WithOIDC(context.Background(), OIDCConfig{
		IssuerURL: broken.URL, ClientID: "c", ClientSecret: "s",
		RedirectURL: "https://x.example/auth/callback",
	})
	if err == nil {
		t.Fatal("want an error for an unreachable issuer")
	}
	if !strings.Contains(err.Error(), "discover") {
		t.Errorf("error should say what failed, got: %v", err)
	}

	// And the incomplete configurations, which are easier to get wrong than the URL.
	for _, cfg := range []OIDCConfig{
		{IssuerURL: "https://x.example", ClientID: "c", RedirectURL: "https://x/cb"},
		{IssuerURL: "https://x.example", ClientSecret: "s", RedirectURL: "https://x/cb"},
		{IssuerURL: "https://x.example", ClientID: "c", ClientSecret: "s"},
	} {
		if _, err := New(stubAssessor{}).WithOIDC(context.Background(), cfg); err == nil {
			t.Errorf("incomplete config accepted: %+v", cfg)
		}
	}
}
