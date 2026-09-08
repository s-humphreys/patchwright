package ticket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
)

// tokenServer stands in for auth.atlassian.com, counting exchanges and rotating
// the refresh token the way Atlassian does.
func tokenServer(t *testing.T, expiresIn int, calls *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode token request: %v", err)
		}
		if body["grant_type"] != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", body["grant_type"])
		}
		*calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-` + body["refresh_token"] +
			`","refresh_token":"rotated","expires_in":` + strconv.Itoa(expiresIn) + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOAuthSendsBearerAndReusesTokenUntilExpiry(t *testing.T) {
	var refreshes int
	tok := tokenServer(t, 3600, &refreshes)

	var auths []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issues":[],"isLast":true}`))
	}))
	defer api.Close()

	o := &oauthAuth{
		clientID: "id", clientSecret: "secret", refreshToken: "r0",
		tokenURL: tok.URL, cloudID: "cloud-1", client: tok.Client(),
	}
	// The API host is fixed by the cloud ID in production; here it is the stub.
	o.apiBase = api.URL

	j := &Jira{auth: o, Client: api.Client(),
		cfg: config.JiraConfig{Project: "PROJ", ImageField: "customfield_1"}}
	if _, err := j.OpenByImage(context.Background()); err != nil {
		t.Fatalf("OpenByImage: %v", err)
	}
	if _, err := j.OpenByImage(context.Background()); err != nil {
		t.Fatalf("OpenByImage (second): %v", err)
	}

	if refreshes != 1 {
		t.Errorf("refreshed %d times, want 1: a valid token must be reused", refreshes)
	}
	for _, a := range auths {
		if a != "Bearer at-r0" {
			t.Errorf("Authorization = %q, want Bearer at-r0", a)
		}
	}
	// Rotation matters: replaying the old refresh token would fail after the
	// first exchange.
	if o.refreshToken != "rotated" {
		t.Errorf("refresh token = %q, want the rotated one", o.refreshToken)
	}
}

func TestOAuthRefreshesWhenTheTokenIsNearExpiry(t *testing.T) {
	var refreshes int
	tok := tokenServer(t, 3600, &refreshes)
	o := &oauthAuth{clientID: "id", clientSecret: "s", refreshToken: "r0",
		tokenURL: tok.URL, client: tok.Client(),
		accessToken: "stale", expiry: time.Now().Add(tokenSkew / 2)}

	got, err := o.token(context.Background())
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got == "stale" {
		t.Error("returned a token inside the skew window; it could expire mid-request")
	}
	if refreshes != 1 {
		t.Errorf("refreshed %d times, want 1", refreshes)
	}
}

func TestOAuthBaseDiscoversTheCloudID(t *testing.T) {
	var refreshes int
	tok := tokenServer(t, 3600, &refreshes)
	o := &oauthAuth{clientID: "id", clientSecret: "s", refreshToken: "r0",
		tokenURL: tok.URL, client: tok.Client()}

	resources := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer at-r0" {
			t.Errorf("Authorization = %q, want a bearer token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"cloud-9","url":"https://one.atlassian.net"}]`))
	}))
	defer resources.Close()

	id, err := o.discoverCloudIDAt(context.Background(), resources.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if id != "cloud-9" {
		t.Errorf("cloud id = %q, want cloud-9", id)
	}
}

func TestOAuthDiscoveryPicksTheConfiguredSite(t *testing.T) {
	var refreshes int
	tok := tokenServer(t, 3600, &refreshes)
	o := &oauthAuth{clientID: "id", clientSecret: "s", refreshToken: "r0",
		tokenURL: tok.URL, client: tok.Client(), siteURL: "https://two.atlassian.net"}

	resources := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"a","url":"https://one.atlassian.net"},
		                        {"id":"b","url":"https://two.atlassian.net"}]`))
	}))
	defer resources.Close()

	id, err := o.discoverCloudIDAt(context.Background(), resources.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if id != "b" {
		t.Errorf("cloud id = %q, want b: the configured site must win", id)
	}
}

// Guessing between sites would file tickets on the wrong tracker.
func TestOAuthDiscoveryRefusesToGuessBetweenSites(t *testing.T) {
	var refreshes int
	tok := tokenServer(t, 3600, &refreshes)
	o := &oauthAuth{clientID: "id", clientSecret: "s", refreshToken: "r0",
		tokenURL: tok.URL, client: tok.Client()}

	resources := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"a","url":"https://one.atlassian.net"},
		                        {"id":"b","url":"https://two.atlassian.net"}]`))
	}))
	defer resources.Close()

	_, err := o.discoverCloudIDAt(context.Background(), resources.URL)
	if err == nil {
		t.Fatal("discovered a cloud id from two candidates; want an error naming both")
	}
	if !strings.Contains(err.Error(), EnvCloudID) {
		t.Errorf("error %q does not say how to resolve the ambiguity", err)
	}
}

func TestOAuthSurfacesARejectedRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	o := &oauthAuth{clientID: "id", clientSecret: "s", refreshToken: "expired",
		tokenURL: srv.URL, client: srv.Client()}
	_, err := o.token(context.Background())
	if err == nil {
		t.Fatal("expected an error for a rejected refresh token")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error %q drops the reason Atlassian gave", err)
	}
}

func TestNewJiraSelectsOAuthWhenTheClientIDIsSet(t *testing.T) {
	t.Setenv(EnvBaseURL, "https://one.atlassian.net")
	t.Setenv(EnvOAuthClientID, "id")
	t.Setenv(EnvOAuthClientSecret, "secret")
	t.Setenv(EnvOAuthRefreshToken, "r0")

	j, err := NewJira(config.JiraConfig{Project: "PROJ"})
	if err != nil {
		t.Fatalf("NewJira: %v", err)
	}
	o, ok := j.auth.(*oauthAuth)
	if !ok {
		t.Fatalf("auth is %T, want *oauthAuth", j.auth)
	}
	if o.siteURL != "https://one.atlassian.net" {
		t.Errorf("siteURL = %q", o.siteURL)
	}
	if j.Token != "" {
		t.Error("an API token was populated in OAuth mode")
	}
}

// A half-configured OAuth app should say what is missing, not 401 later.
func TestNewJiraNamesMissingOAuthPieces(t *testing.T) {
	t.Setenv(EnvBaseURL, "https://one.atlassian.net")
	t.Setenv(EnvOAuthClientID, "id")
	t.Setenv(EnvOAuthClientSecret, "")
	t.Setenv(EnvOAuthRefreshToken, "")

	_, err := NewJira(config.JiraConfig{Project: "PROJ"})
	if err == nil {
		t.Fatal("expected an error naming the missing OAuth variables")
	}
	for _, want := range []string{EnvOAuthClientSecret, EnvOAuthRefreshToken} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
}

func TestNewJiraStillAcceptsAnAPIToken(t *testing.T) {
	t.Setenv(EnvBaseURL, "https://one.atlassian.net/")
	t.Setenv(EnvEmail, "you@example.com")
	t.Setenv(EnvToken, "tok")

	j, err := NewJira(config.JiraConfig{Project: "PROJ"})
	if err != nil {
		t.Fatalf("NewJira: %v", err)
	}
	b, ok := j.auth.(basicAuth)
	if !ok {
		t.Fatalf("auth is %T, want basicAuth", j.auth)
	}
	// The trailing slash must go, or every path becomes a double slash.
	if b.baseURL != "https://one.atlassian.net" {
		t.Errorf("baseURL = %q", b.baseURL)
	}
	if j.Email != "you@example.com" || j.Token != "tok" {
		t.Errorf("credentials not carried onto the client: %q %q", j.Email, j.Token)
	}
}
