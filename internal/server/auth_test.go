package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

const testToken = "s3cret-token"

func authedServer(t *testing.T) http.Handler {
	t.Helper()
	s := New(stubAssessor{findings: []model.Finding{
		finding("acr.io/app:1", "engineering", "orders", true, false),
	}}).WithAuth(testToken)
	s.Refresh(context.Background())
	return s.Handler()
}

func do(t *testing.T, h http.Handler, path, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func basic(token string) string {
	// The username is ignored; the token is the password.
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("patchwright:"+token))
}

// Everything that carries data must require the token, including the page: the
// page is a data view, so gating the API while leaving it open would protect
// nothing.
func TestAuthRequiredOnDataPaths(t *testing.T) {
	h := authedServer(t)
	for _, path := range []string{
		"/", "/api/v1/findings", "/api/v1/finding?image=acr.io/app:1",
		"/api/v1/owners", "/api/v1/summary",
	} {
		if code := do(t, h, path, "").Code; code != http.StatusUnauthorized {
			t.Errorf("%s without a token: got %d, want 401", path, code)
		}
		if code := do(t, h, path, "Bearer "+testToken).Code; code == http.StatusUnauthorized {
			t.Errorf("%s with a valid bearer token: got 401", path)
		}
	}
}

// A browser cannot attach a bearer token when navigating, so Basic has to work or
// the page is unusable behind auth.
func TestAuthAcceptsBasicWithTokenAsPassword(t *testing.T) {
	h := authedServer(t)
	if code := do(t, h, "/", basic(testToken)).Code; code != http.StatusOK {
		t.Errorf("page with Basic credentials: got %d, want 200", code)
	}
	if code := do(t, h, "/api/v1/summary", basic("wrong")).Code; code != http.StatusUnauthorized {
		t.Errorf("Basic with the wrong password: got %d, want 401", code)
	}
}

// Without the challenge a browser shows a bare error instead of prompting.
func TestAuthChallengesSoBrowsersPrompt(t *testing.T) {
	rec := do(t, authedServer(t), "/", "")
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("WWW-Authenticate = %q, want a Basic challenge", got)
	}
}

// Probes must never need a credential, or a deployment fails its health checks the
// moment authentication is switched on.
func TestAuthLeavesProbesAndFaviconOpen(t *testing.T) {
	h := authedServer(t)
	for _, path := range []string{"/healthz", "/readyz", "/favicon.png"} {
		if code := do(t, h, path, "").Code; code == http.StatusUnauthorized {
			t.Errorf("%s requires a token; probes and the icon must stay open", path)
		}
	}
}

// The historical behaviour has to remain available: no token configured, no
// authentication. `serve` warns loudly instead of quietly refusing to start.
func TestNoTokenLeavesEverythingOpen(t *testing.T) {
	h := newTestServer(t)
	for _, path := range []string{"/", "/api/v1/findings", "/api/v1/summary"} {
		if code := do(t, h, path, "").Code; code != http.StatusOK {
			t.Errorf("%s with auth disabled: got %d, want 200", path, code)
		}
	}
}

// Rejections must not depend on how much of the token is right.
func TestTokenComparisonRejectsNearMisses(t *testing.T) {
	s := New(stubAssessor{}).WithAuth(testToken)
	for _, presented := range []string{
		"", " ", testToken + "x", strings.ToUpper(testToken),
		testToken[:len(testToken)-1], "s3cret-tokeN",
	} {
		if s.tokenValid(presented) {
			t.Errorf("tokenValid(%q) = true, want false", presented)
		}
	}
	if !s.tokenValid(testToken) {
		t.Error("the correct token was rejected")
	}
}

// Malformed or unknown schemes must fail closed rather than being ignored.
func TestMalformedAuthorizationHeadersFailClosed(t *testing.T) {
	h := authedServer(t)
	for _, header := range []string{
		"Bearer", "Bearer ", "Basic", "Basic !!!notbase64",
		"Token " + testToken, testToken, "Negotiate abc",
	} {
		if code := do(t, h, "/api/v1/summary", header).Code; code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: got %d, want 401", header, code)
		}
	}
}

// Scheme names are case-insensitive per RFC 7235, and some clients send "bearer".
func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	h := authedServer(t)
	for _, header := range []string{"bearer " + testToken, "BEARER " + testToken} {
		if code := do(t, h, "/api/v1/summary", header).Code; code != http.StatusOK {
			t.Errorf("Authorization %q: got %d, want 200", header, code)
		}
	}
}

// A refresh creates work and, once auto-ticketing exists, Jira issues. It must not
// be reachable unauthenticated.
func TestRefreshRequiresAuth(t *testing.T) {
	h := authedServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assessments", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /api/v1/assessments without a token: got %d, want 401", rec.Code)
	}
}
