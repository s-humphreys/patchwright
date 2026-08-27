package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Sign-in with OpenID Connect.
//
// The shared token in auth.go is authentication with no identity: everyone who can read
// it is the same person, and nothing it protects can be attributed. That is defensible
// on a trusted network and indefensible once somebody asks who looked at what, which is
// the question this answers.
//
// Deliberately plain OIDC rather than anything provider-specific. The issuer, client and
// scopes are configuration, so Entra, Okta, Keycloak and Dex are the same code path; the
// only Entra-shaped decision anywhere is a default scope list, and even that is
// overridable.
//
// Two things are NOT hand-rolled, because getting either subtly wrong is worse than
// having no sign-in at all. ID token verification (JWKS fetching, key rotation,
// signature, issuer, audience and expiry) is go-oidc's, which is the implementation
// kube-apiserver uses. The authorization code exchange is x/oauth2's. What is written
// here is the part that is genuinely this application's: which requests need a session,
// how the session is carried, and who is allowed one.

const (
	sessionCookie = "patchwright_session"
	// stateCookie carries the CSRF state, the ID token nonce and the PKCE verifier
	// between the redirect out and the callback back. Short-lived: it is only needed
	// for the duration of one sign-in.
	stateCookie   = "patchwright_authstate"
	stateTTL      = 10 * time.Minute
	loginPath     = "/auth/login"
	callbackPath  = "/auth/callback"
	logoutPath    = "/auth/logout"
	defaultTTL    = 12 * time.Hour
	sessionSlack  = 30 * time.Second
	authStateSize = 32
)

// OIDCConfig is what a deployment supplies to enable sign-in.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	// RedirectURL is the absolute callback the provider sends the browser back to. It
	// must match a redirect URI registered on the application, so it is configured
	// rather than derived: deriving it from the request's Host header would let a
	// forged Host redirect a sign-in somewhere else.
	RedirectURL string
	Scopes      []string
	// AllowedGroups, AllowedEmails and AllowedDomains restrict who may sign in. Empty
	// means anybody the provider authenticates, which is the right default for an
	// internal tool behind a provider that only knows employees, and the wrong one
	// everywhere else - so it is reported at startup rather than left implicit.
	AllowedGroups  []string
	AllowedEmails  []string
	AllowedDomains []string
	// SessionTTL is how long a sign-in lasts. Zero means the default.
	SessionTTL time.Duration
	// SessionKey signs session cookies. When empty a random key is generated, which
	// is safe but invalidates every session on restart; supply one to survive a
	// rollout, and the same one to every replica.
	SessionKey []byte
}

// authenticator holds the provider metadata and the signing key.
type authenticator struct {
	cfg      OIDCConfig
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	key      []byte
	ttl      time.Duration
	now      func() time.Time
}

// WithOIDC enables sign-in. Discovery happens here, so a misconfigured issuer fails at
// startup rather than on somebody's first attempt to sign in.
func (s *Server) WithOIDC(ctx context.Context, cfg OIDCConfig) (*Server, error) {
	if cfg.IssuerURL == "" {
		return s, nil
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("oidc: issuer configured without a client id and secret")
	}
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("oidc: issuer configured without a redirect url")
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover %s: %w", cfg.IssuerURL, err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	key := cfg.SessionKey
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("oidc: generate session key: %w", err)
		}
		slog.WarnContext(ctx, "no session key configured: sessions will not survive a restart or span replicas")
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	s.auth = &authenticator{
		cfg:      cfg,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		key: key,
		ttl: ttl,
		now: time.Now,
	}
	if len(cfg.AllowedGroups)+len(cfg.AllowedEmails)+len(cfg.AllowedDomains) == 0 {
		slog.WarnContext(ctx, "sign-in accepts anyone the provider authenticates; set allowed groups, emails or domains to narrow it")
	}
	return s, nil
}

// signInEnabled reports whether OIDC is configured.
func (s *Server) signInEnabled() bool { return s.auth != nil }

// session is what a signed cookie carries.
//
// Small on purpose: a subject, a display name and an expiry. Group membership is checked
// once at sign-in and not stored, so a cookie cannot be replayed to assert a group, and a
// user whose access is withdrawn loses it when their session expires rather than
// immediately - which is the honest trade a stateless session makes, and the reason the
// default lifetime is hours rather than weeks.
type session struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Expires int64  `json:"exp"`
}

// issue writes a signed session cookie.
func (a *authenticator) issue(w http.ResponseWriter, r *http.Request, s session) error {
	s.Expires = a.now().Add(a.ttl).Unix()
	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	value := encode(payload) + "." + encode(a.sign(payload))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureRequest(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(s.Expires, 0),
	})
	return nil
}

// current returns the signed-in user, if the request carries a valid session.
func (a *authenticator) current(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return session{}, false
	}
	raw, err := decode(payload)
	if err != nil {
		return session{}, false
	}
	got, err := decode(sig)
	if err != nil {
		return session{}, false
	}
	// Constant time, and the signature is checked BEFORE the payload is parsed: the
	// contents of an unverified cookie are an attacker's input, not data.
	if !hmac.Equal(got, a.sign(raw)) {
		return session{}, false
	}
	var s session
	if err := json.Unmarshal(raw, &s); err != nil {
		return session{}, false
	}
	if a.now().After(time.Unix(s.Expires, 0)) {
		return session{}, false
	}
	return s, true
}

func (a *authenticator) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, a.key)
	mac.Write(payload)
	return mac.Sum(nil)
}

// authState is the per-attempt data the callback needs, carried in its own cookie.
type authState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Next     string `json:"next"`
	Expires  int64  `json:"exp"`
}

// handleLogin starts the flow.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	a := s.auth
	st := authState{
		State:    randomString(),
		Nonce:    randomString(),
		Verifier: oauth2.GenerateVerifier(),
		Next:     safeNext(r.URL.Query().Get("next")),
		Expires:  a.now().Add(stateTTL).Unix(),
	}
	payload, err := json.Marshal(st)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sign-in failed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    encode(payload) + "." + encode(a.sign(payload)),
		Path:     "/auth/",
		HttpOnly: true,
		Secure:   secureRequest(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(st.Expires, 0),
	})
	// PKCE as well as a client secret. Belt and braces: it costs nothing and removes
	// a whole class of interception attack on the authorization code.
	url := a.oauth.AuthCodeURL(st.State,
		oidc.Nonce(st.Nonce),
		oauth2.S256ChallengeOption(st.Verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

// handleCallback completes the flow.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	a := s.auth
	st, ok := a.readState(r)
	// Cleared whatever happens: a state cookie that outlives its attempt is a replay
	// waiting to be used.
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth/", MaxAge: -1})
	if !ok {
		s.denySignIn(w, r, "sign-in could not be verified, please try again", nil)
		return
	}
	// The state comparison is the CSRF control: without it, an attacker can complete
	// a sign-in in somebody else's browser.
	if q := r.URL.Query().Get("state"); subtle.ConstantTimeCompare([]byte(q), []byte(st.State)) != 1 {
		s.denySignIn(w, r, "sign-in could not be verified, please try again", nil)
		return
	}
	if desc := r.URL.Query().Get("error"); desc != "" {
		s.denySignIn(w, r, "the identity provider declined the sign-in", fmt.Errorf("%s: %s",
			desc, r.URL.Query().Get("error_description")))
		return
	}
	tok, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"),
		oauth2.VerifierOption(st.Verifier))
	if err != nil {
		s.denySignIn(w, r, "sign-in failed at the identity provider", err)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		s.denySignIn(w, r, "the identity provider returned no id token", nil)
		return
	}
	id, err := a.verifier.Verify(r.Context(), rawID)
	if err != nil {
		s.denySignIn(w, r, "the id token could not be verified", err)
		return
	}
	// Nonce binds this token to this attempt, so a token obtained elsewhere cannot be
	// injected into somebody else's sign-in.
	if subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(st.Nonce)) != 1 {
		s.denySignIn(w, r, "sign-in could not be verified, please try again", nil)
		return
	}

	var claims struct {
		Email             string   `json:"email"`
		PreferredUsername string   `json:"preferred_username"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"`
	}
	if err := id.Claims(&claims); err != nil {
		s.denySignIn(w, r, "the id token could not be read", err)
		return
	}
	who := firstNonEmpty(claims.Email, claims.PreferredUsername, claims.Name, id.Subject)
	if err := a.cfg.permit(who, claims.Groups); err != nil {
		// Logged with the identity, because a refused sign-in is the one event an
		// operator will be asked about.
		slog.WarnContext(r.Context(), "sign-in refused", "user", who, "error", err)
		s.denySignIn(w, r, "your account is not permitted to use this service", err)
		return
	}
	if err := a.issue(w, r, session{Subject: id.Subject, Email: who}); err != nil {
		s.denySignIn(w, r, "sign-in failed", err)
		return
	}
	slog.InfoContext(r.Context(), "signed in", "user", who)
	http.Redirect(w, r, st.Next, http.StatusFound)
}

// handleLogout ends the session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secureRequest(r), SameSite: http.SameSiteLaxMode,
	})
	// Only this service's session. The provider's session is deliberately untouched:
	// signing somebody out of Entra because they closed one internal dashboard would
	// be a surprising thing for a dashboard to do.
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *authenticator) readState(r *http.Request) (authState, bool) {
	c, err := r.Cookie(stateCookie)
	if err != nil {
		return authState{}, false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return authState{}, false
	}
	raw, err := decode(payload)
	if err != nil {
		return authState{}, false
	}
	got, err := decode(sig)
	if err != nil {
		return authState{}, false
	}
	if !hmac.Equal(got, a.sign(raw)) {
		return authState{}, false
	}
	var st authState
	if err := json.Unmarshal(raw, &st); err != nil {
		return authState{}, false
	}
	if a.now().After(time.Unix(st.Expires, 0)) {
		return authState{}, false
	}
	st.Next = safeNext(st.Next)
	return st, true
}

// denySignIn reports a failed sign-in without leaking why to the browser.
//
// The visitor gets a plain sentence; the operator gets the cause in the log. The
// distinction matters: "the id token could not be verified" in a page body tells an
// attacker which control stopped them.
func (s *Server) denySignIn(w http.ResponseWriter, r *http.Request, msg string, err error) {
	if err != nil {
		slog.WarnContext(r.Context(), "sign-in failed", "reason", msg, "error", err)
	}
	writeError(w, http.StatusForbidden, msg)
}

// permit reports whether this identity may sign in.
//
// Every configured restriction must pass, and a restriction that cannot be evaluated
// fails closed. If a deployment asks for a group and the provider sends no groups claim,
// nobody gets in until that is fixed - which is loud, correctable, and the right way
// round. Letting everybody in because the claim was missing would satisfy the
// configuration file and defeat its purpose.
func (c OIDCConfig) permit(who string, groups []string) error {
	if len(c.AllowedGroups) > 0 {
		if len(groups) == 0 {
			return fmt.Errorf("groups are required but the provider sent no groups claim")
		}
		if !anyMatch(groups, c.AllowedGroups) {
			return fmt.Errorf("not a member of any permitted group")
		}
	}
	if len(c.AllowedEmails) > 0 && !anyMatch([]string{who}, c.AllowedEmails) {
		return fmt.Errorf("address is not on the permitted list")
	}
	if len(c.AllowedDomains) > 0 {
		_, domain, ok := strings.Cut(who, "@")
		if !ok || !anyMatch([]string{domain}, c.AllowedDomains) {
			return fmt.Errorf("address is not in a permitted domain")
		}
	}
	return nil
}

// anyMatch reports whether any value appears in the allow list, case-insensitively:
// providers differ on the casing of both group names and addresses.
func anyMatch(values, allowed []string) bool {
	for _, v := range values {
		for _, a := range allowed {
			if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(a)) {
				return true
			}
		}
	}
	return false
}

// safeNext sanitises the post-sign-in destination.
//
// Only a path on this host, so the sign-in cannot be used as an open redirect: a link to
// /auth/login?next=https://evil.example would otherwise send somebody who just
// authenticated straight to somebody else's page. "//host" is rejected too, because a
// browser reads it as protocol-relative and therefore as another origin.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return next
}

func randomString() string {
	b := make([]byte, authStateSize)
	if _, err := rand.Read(b); err != nil {
		// A failure here means the system's randomness is unavailable, which is not
		// something to paper over with a predictable value.
		panic("patchwright: crypto/rand unavailable: " + err.Error())
	}
	return encode(b)
}

// secureRequest reports whether the browser is talking to us over TLS, including via a
// proxy that terminated it. Without the header check every cookie would lose its Secure
// flag behind an ingress, which is exactly where it matters most.
func secureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
