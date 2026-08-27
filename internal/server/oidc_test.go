package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// Auth code earns closer tests than the rest: every one of these is a control that, if it
// silently stopped working, would leave the page open while looking protected.

func testAuthenticator(t *testing.T, cfg OIDCConfig) *authenticator {
	t.Helper()
	return &authenticator{
		cfg: cfg,
		key: []byte("test-key-not-a-real-one-0123456789"),
		ttl: time.Hour,
		now: time.Now,
	}
}

// testOAuthConfig is a provider-shaped config with no network behind it: the login
// handler only needs endpoint URLs to build a redirect.
func testOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURL:  "https://patchwright.example/auth/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.example/authorize",
			TokenURL: "https://login.example/token",
		},
		Scopes: []string{"openid", "email"},
	}
}

func TestASessionCookieCannotBeForgedOrEdited(t *testing.T) {
	a := testAuthenticator(t, OIDCConfig{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := a.issue(rec, req, session{Subject: "abc", Email: "someone@example.com"}); err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]

	// The genuine article works.
	req.AddCookie(cookie)
	if s, ok := a.current(req); !ok || s.Email != "someone@example.com" {
		t.Fatalf("valid session rejected: %+v ok=%v", s, ok)
	}

	// Edited payload, original signature: the classic attempt.
	payload, sig, _ := strings.Cut(cookie.Value, ".")
	raw, err := decode(payload)
	if err != nil {
		t.Fatal(err)
	}
	var edited session
	_ = json.Unmarshal(raw, &edited)
	edited.Email = "someone-else@example.com"
	tampered, _ := json.Marshal(edited)
	forged := encode(tampered) + "." + sig

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookie, Value: forged})
	if _, ok := a.current(req2); ok {
		t.Error("a cookie with an edited payload was accepted")
	}

	// A different key must not validate: this is what stops one deployment's cookie
	// working against another's.
	other := testAuthenticator(t, OIDCConfig{})
	other.key = []byte("a-completely-different-signing-key0")
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.AddCookie(cookie)
	if _, ok := other.current(req3); ok {
		t.Error("a cookie signed with another key was accepted")
	}
}

func TestAnExpiredSessionIsNotAccepted(t *testing.T) {
	a := testAuthenticator(t, OIDCConfig{})
	a.ttl = time.Minute
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := a.issue(rec, req, session{Subject: "abc"}); err != nil {
		t.Fatal(err)
	}
	req.AddCookie(rec.Result().Cookies()[0])

	// Same cookie, later clock. A session has to end on its own, or "signed in once"
	// becomes "signed in forever".
	a.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, ok := a.current(req); ok {
		t.Error("an expired session was accepted")
	}
}

func TestSessionCookiesAreNotReadableOrSentCrossSite(t *testing.T) {
	a := testAuthenticator(t, OIDCConfig{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https") // behind an ingress that terminated TLS
	if err := a.issue(rec, req, session{Subject: "abc"}); err != nil {
		t.Fatal(err)
	}
	c := rec.Result().Cookies()[0]
	if !c.HttpOnly {
		t.Error("session cookie is readable by scripts")
	}
	if !c.Secure {
		t.Error("session cookie lost its Secure flag behind a TLS-terminating proxy, which is exactly where it matters")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
}

func TestTheSignInDestinationCannotLeaveThisSite(t *testing.T) {
	// Otherwise /auth/login?next=https://evil.example sends somebody who has just
	// authenticated straight off to somebody else's page, with this service's name in
	// the address bar a moment earlier.
	for _, bad := range []string{
		"https://evil.example",
		"//evil.example",
		"http://evil.example/path",
		"javascript:alert(1)",
		"",
	} {
		if got := safeNext(bad); got != "/" {
			t.Errorf("safeNext(%q) = %q, want /", bad, got)
		}
	}
	for _, good := range []string{"/", "/?team=x", "/api/v1/findings?actionable=true"} {
		if got := safeNext(good); got != good {
			t.Errorf("safeNext(%q) = %q, want it preserved", good, got)
		}
	}
}

func TestAStateCookieFromAnotherAttemptIsRejected(t *testing.T) {
	// The CSRF control. Without the state comparison an attacker can complete a
	// sign-in in somebody else's browser.
	a := testAuthenticator(t, OIDCConfig{})
	a.oauth = testOAuthConfig()
	s := &Server{auth: a}

	rec := httptest.NewRecorder()
	s.handleLogin(rec, httptest.NewRequest(http.MethodGet, loginPath, nil))
	var state *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == stateCookie {
			state = c
		}
	}
	if state == nil {
		t.Fatal("login set no state cookie")
	}

	// Callback carrying the cookie but the wrong state parameter.
	req := httptest.NewRequest(http.MethodGet, callbackPath+"?state=not-the-one&code=x", nil)
	req.AddCookie(state)
	rec2 := httptest.NewRecorder()
	s.handleCallback(rec2, req)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a mismatched state", rec2.Code)
	}

	// And with no state cookie at all.
	rec3 := httptest.NewRecorder()
	s.handleCallback(rec3, httptest.NewRequest(http.MethodGet, callbackPath+"?state=x&code=y", nil))
	if rec3.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 when there is no state to compare", rec3.Code)
	}
}

func TestLoginUsesPKCEAndANonce(t *testing.T) {
	a := testAuthenticator(t, OIDCConfig{})
	a.oauth = testOAuthConfig()
	s := &Server{auth: a}
	rec := httptest.NewRecorder()
	s.handleLogin(rec, httptest.NewRequest(http.MethodGet, loginPath, nil))
	loc := rec.Header().Get("Location")
	for _, want := range []string{"code_challenge=", "code_challenge_method=S256", "nonce=", "state="} {
		if !strings.Contains(loc, want) {
			t.Errorf("authorization URL missing %s: %s", want, loc)
		}
	}
}

func TestARefusedGroupIsRefusedAndAMissingClaimFailsClosed(t *testing.T) {
	cfg := OIDCConfig{AllowedGroups: []string{"platform-engineering"}}

	if err := cfg.permit("a@example.com", []string{"platform-engineering"}); err != nil {
		t.Errorf("a member of the permitted group was refused: %v", err)
	}
	// Case differs between providers, and a group called Platform-Engineering is the
	// same group.
	if err := cfg.permit("a@example.com", []string{"Platform-Engineering"}); err != nil {
		t.Errorf("group matching should be case-insensitive: %v", err)
	}
	if err := cfg.permit("a@example.com", []string{"someone-else"}); err == nil {
		t.Error("a non-member was permitted")
	}
	// The important one: groups required, provider sent none. Letting this through
	// would satisfy the config file and defeat its entire purpose, silently.
	if err := cfg.permit("a@example.com", nil); err == nil {
		t.Error("a missing groups claim was treated as permission")
	}
}

func TestEveryConfiguredRestrictionHasToPass(t *testing.T) {
	cfg := OIDCConfig{
		AllowedGroups:  []string{"eng"},
		AllowedDomains: []string{"example.com"},
	}
	if err := cfg.permit("a@example.com", []string{"eng"}); err != nil {
		t.Errorf("both satisfied but refused: %v", err)
	}
	// Right group, wrong domain: a guest account added to the correct group must not
	// be enough on its own.
	if err := cfg.permit("a@contractor.test", []string{"eng"}); err == nil {
		t.Error("domain restriction was not applied")
	}
	// No restrictions configured means anybody the provider authenticates.
	if err := (OIDCConfig{}).permit("anyone@anywhere.test", nil); err != nil {
		t.Errorf("unrestricted config refused a sign-in: %v", err)
	}
}

func TestTheGateSendsBrowsersToSignInAndScriptsA401(t *testing.T) {
	// A redirect to an HTML page is useless to a script: it turns a clear 401 into a
	// 200 full of markup that fails to parse as JSON.
	s := &Server{auth: testAuthenticator(t, OIDCConfig{})}
	h := s.authorize(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	browser := httptest.NewRequest(http.MethodGet, "/?team=x", nil)
	browser.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, browser)
	if rec.Code != http.StatusFound {
		t.Errorf("browser: status = %d, want a redirect to sign in", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, loginPath) || !strings.Contains(loc, "next=") {
		t.Errorf("browser: Location = %q, want the sign-in path carrying where they were going", loc)
	}

	script := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	script.Header.Set("Accept", "application/json")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, script)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("script: status = %d, want 401", rec2.Code)
	}
}

func TestProbesAndTheSignInFlowItselfStayReachable(t *testing.T) {
	// A gate that requires a session to reach the sign-in page is a locked door with
	// the key inside; probes that need a credential make a pod fail its own liveness.
	s := &Server{auth: testAuthenticator(t, OIDCConfig{})}
	h := s.authorize(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, path := range []string{"/healthz", "/readyz", loginPath, callbackPath, logoutPath} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusFound {
			t.Errorf("%s: status = %d, must be reachable without a session", path, rec.Code)
		}
	}
}

func TestATokenAndASessionAreBothSufficient(t *testing.T) {
	// Machine clients cannot complete a redirect, so the token path has to survive
	// sign-in being turned on. Both are checked; neither is required.
	s := (&Server{auth: testAuthenticator(t, OIDCConfig{})}).WithAuth("s3cret")
	h := s.authorize(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	withToken := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	withToken.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withToken)
	if rec.Code != http.StatusOK {
		t.Errorf("token: status = %d, want 200", rec.Code)
	}

	sess := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := s.auth.issue(sess, req, session{Subject: "abc"}); err != nil {
		t.Fatal(err)
	}
	withSession := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	withSession.AddCookie(sess.Result().Cookies()[0])
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, withSession)
	if rec2.Code != http.StatusOK {
		t.Errorf("session: status = %d, want 200", rec2.Code)
	}

	wrong := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	wrong.Header.Set("Authorization", "Bearer nope")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, wrong)
	if rec3.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", rec3.Code)
	}
}

func TestSignOutClearsTheSession(t *testing.T) {
	s := &Server{auth: testAuthenticator(t, OIDCConfig{})}
	rec := httptest.NewRecorder()
	s.handleLogout(rec, httptest.NewRequest(http.MethodGet, logoutPath, nil))
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("sign-out did not clear the session cookie")
	}
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want a redirect after sign-out", rec.Code)
	}
}

func TestNothingIsGatedWhenNeitherMechanismIsConfigured(t *testing.T) {
	// The existing behaviour: an unconfigured server is open, loudly, rather than
	// pretending to be protected.
	s := &Server{}
	h := s.authorize(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with no auth configured", rec.Code)
	}
}
