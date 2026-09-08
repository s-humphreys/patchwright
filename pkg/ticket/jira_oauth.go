package ticket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jiraAuth authorises an outbound Jira request. Two shapes exist: an Atlassian
// API token over Basic auth, and OAuth 2.0 (3LO), which also changes the host
// requests go to — hence base, resolved separately from the credential itself.
type jiraAuth interface {
	apply(ctx context.Context, req *http.Request) error
	base(ctx context.Context) (string, error)
}

// basicAuth is an Atlassian account email plus an API token. Static: nothing to
// refresh, and the site URL is the API host.
type basicAuth struct {
	email, token, baseURL string
}

func (b basicAuth) apply(_ context.Context, req *http.Request) error {
	req.SetBasicAuth(b.email, b.token)
	return nil
}

func (b basicAuth) base(context.Context) (string, error) { return b.baseURL, nil }

// OAuth credential environment variables. Presence of the client ID is what
// selects OAuth over an API token.
const (
	EnvOAuthClientID     = "JIRA_OAUTH_CLIENT_ID"
	EnvOAuthClientSecret = "JIRA_OAUTH_CLIENT_SECRET"
	EnvOAuthRefreshToken = "JIRA_OAUTH_REFRESH_TOKEN"
	EnvCloudID           = "JIRA_CLOUD_ID"
)

const (
	atlassianTokenURL = "https://auth.atlassian.com/oauth/token"
	atlassianAPIHost  = "https://api.atlassian.com"
	// Refresh this far before expiry, so a token does not lapse mid-request.
	tokenSkew = 60 * time.Second
)

// oauthAuth exchanges an OAuth credential for short-lived access tokens, in
// either of the two grants Atlassian offers.
//
// With a refresh token (3LO, a user authorised the app) the grant is
// refresh_token. Atlassian rotates refresh tokens on every exchange, so the
// current one lives in memory only: a restart falls back to the token from the
// environment, which stays valid until the next successful refresh replaces it.
//
// Without one (2LO, the app acts as itself) the grant is client_credentials,
// which needs no user and can be re-minted from the ID and secret at any time.
type oauthAuth struct {
	clientID     string
	clientSecret string
	tokenURL     string
	client       *http.Client

	// siteURL is the configured JIRA_BASE_URL, used only to pick the right site
	// when the app is authorised against more than one. Optional.
	siteURL string
	cloudID string

	mu           sync.Mutex
	refreshToken string
	accessToken  string
	expiry       time.Time
	apiBase      string
}

// grant builds the token request. The audience is required for client
// credentials and harmless on a refresh, so it is always sent.
func (o *oauthAuth) grant(refresh string) map[string]string {
	body := map[string]string{
		"client_id":     o.clientID,
		"client_secret": o.clientSecret,
		"audience":      "api.atlassian.com",
	}
	if refresh == "" {
		body["grant_type"] = "client_credentials"
		return body
	}
	body["grant_type"] = "refresh_token"
	body["refresh_token"] = refresh
	return body
}

func (o *oauthAuth) grantName(refresh string) string {
	if refresh == "" {
		return "mint jira oauth token (client credentials)"
	}
	return "refresh jira oauth token"
}

func (o *oauthAuth) apply(ctx context.Context, req *http.Request) error {
	tok, err := o.token(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return nil
}

// base is https://api.atlassian.com/ex/jira/{cloudId}: OAuth apps do not talk to
// the site host. The cloud ID is discovered once if it was not configured.
func (o *oauthAuth) base(ctx context.Context) (string, error) {
	o.mu.Lock()
	if o.apiBase != "" {
		defer o.mu.Unlock()
		return o.apiBase, nil
	}
	cloud := o.cloudID
	o.mu.Unlock()

	if cloud == "" {
		var err error
		if cloud, err = o.discoverCloudID(ctx); err != nil {
			return "", err
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cloudID = cloud
	o.apiBase = atlassianAPIHost + "/ex/jira/" + cloud
	return o.apiBase, nil
}

// token returns a valid access token, refreshing when the current one is absent
// or close to expiry.
func (o *oauthAuth) token(ctx context.Context) (string, error) {
	o.mu.Lock()
	if o.accessToken != "" && time.Now().Add(tokenSkew).Before(o.expiry) {
		defer o.mu.Unlock()
		return o.accessToken, nil
	}
	refresh := o.refreshToken
	o.mu.Unlock()

	b, err := json.Marshal(o.grant(refresh))
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.tokenURL, strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: %w", o.grantName(refresh), err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close, nothing to do on failure
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Worth the body: under client_credentials this is usually a bad secret,
		// while a refresh token is rotated on use and expires after inactivity, and
		// that needs a human to re-authorise rather than a retry.
		return "", fmt.Errorf("%s: %s: %s", o.grantName(refresh), resp.Status, strings.TrimSpace(string(data)))
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("decode jira oauth token response: %w", err)
	}
	// A client_credentials response carries no refresh token, by design: the next
	// token is minted the same way this one was.
	if out.AccessToken == "" {
		return "", fmt.Errorf("jira oauth token response contained no access token")
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	o.accessToken = out.AccessToken
	if out.RefreshToken != "" {
		o.refreshToken = out.RefreshToken
	}
	if out.ExpiresIn > 0 {
		o.expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	} else {
		o.expiry = time.Now().Add(tokenSkew)
	}
	return o.accessToken, nil
}

// discoverCloudID asks which sites the credential can reach. With one site the
// answer is unambiguous; with several, JIRA_BASE_URL picks between them, and
// without it the error names the choice rather than guessing.
func (o *oauthAuth) discoverCloudID(ctx context.Context) (string, error) {
	return o.discoverCloudIDAt(ctx, atlassianAPIHost)
}

func (o *oauthAuth) discoverCloudIDAt(ctx context.Context, host string) (string, error) {
	tok, err := o.token(ctx)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+"/oauth/token/accessible-resources", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("list accessible jira sites: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close, nothing to do on failure
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("list accessible jira sites: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var sites []struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(data, &sites); err != nil {
		return "", fmt.Errorf("decode accessible jira sites: %w", err)
	}
	switch {
	case len(sites) == 0:
		return "", fmt.Errorf("the jira oauth credential has access to no sites: grant the app access to your site, or set %s", EnvCloudID)
	case o.siteURL != "":
		for _, s := range sites {
			if strings.EqualFold(strings.TrimSuffix(s.URL, "/"), o.siteURL) {
				return s.ID, nil
			}
		}
		urls := make([]string, 0, len(sites))
		for _, s := range sites {
			urls = append(urls, s.URL)
		}
		return "", fmt.Errorf("%s (%s) is not one of the sites the jira oauth credential can reach: %s",
			EnvBaseURL, o.siteURL, strings.Join(urls, ", "))
	case len(sites) == 1:
		return sites[0].ID, nil
	}
	urls := make([]string, 0, len(sites))
	for _, s := range sites {
		urls = append(urls, s.URL)
	}
	return "", fmt.Errorf("the jira oauth credential can reach %d sites (%s): set %s or %s to choose one",
		len(sites), strings.Join(urls, ", "), EnvBaseURL, EnvCloudID)
}
