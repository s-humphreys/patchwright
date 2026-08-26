package registryauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/go-containerregistry/pkg/authn"
)

// Azure Container Registry.
//
// The exchange is written out here rather than taken from a credential helper. The
// obvious helper — the one Trivy and Kaniko use — carries GO-2026-6225, credential
// leakage to untrusted hosts, with no fixed version. A tool whose whole purpose is
// telling people their dependencies are vulnerable cannot ship a known-vulnerable
// credential path, and "our host scoping mostly prevents it" is not an argument this
// project gets to make.
//
// What it does instead is the documented ACR flow, on Microsoft's own maintained SDK:
//
//  1. Get an AAD token for whatever identity the process has — a workload identity's
//     projected federated token, a managed identity, a service principal, or a
//     developer's az login. DefaultAzureCredential covers all of them.
//  2. Exchange it at the registry's /oauth2/exchange for an ACR refresh token.
//  3. Present that as the password, with the null GUID as the username, which is what
//     ACR expects.
//
// The exchange only ever talks to the registry host it was asked about, which is
// precisely the leak the advisory above describes.

// acrNullGUID is the username ACR expects alongside a refresh token.
const acrNullGUID = "00000000-0000-0000-0000-000000000000"

// armScope is the resource an ACR exchange requires the AAD token to be issued for.
const armScope = "https://management.azure.com/.default"

func init() {
	Register("azure",
		// The clouds ACR runs in. Anything else — mcr.microsoft.com included, which is
		// Microsoft's public registry and needs no credentials at all — belongs to
		// somebody else, and a credential path should never be asked about a host it
		// does not serve.
		[]string{"*.azurecr.io", "*.azurecr.cn", "*.azurecr.us"},
		&acrKeychain{})
}

// acrKeychain resolves ACR credentials, caching a registry's refresh token until it
// nears expiry. An assessment reads hundreds of images from one registry, and each
// exchange is two network round trips.
type acrKeychain struct {
	mu     sync.Mutex
	cached map[string]cachedToken
	// credential is created once, lazily: constructing it looks for an identity, and a
	// run against public registries only should not pay for that or fail because of it.
	credential azcore
	credErr    error
	credOnce   sync.Once
}

// azcore is the slice of the credential this needs, so a test can stand in for it.
type azcore interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcoreToken, error)
}

type azcoreToken = struct {
	Token     string
	ExpiresOn time.Time
}

type cachedToken struct {
	token   string
	expires time.Time
}

// defaultCredential adapts azidentity to the narrow interface above.
type defaultCredential struct {
	inner *azidentity.DefaultAzureCredential
}

func (d defaultCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcoreToken, error) {
	t, err := d.inner.GetToken(ctx, opts)
	if err != nil {
		return azcoreToken{}, err
	}
	return azcoreToken{Token: t.Token, ExpiresOn: t.ExpiresOn}, nil
}

func (a *acrKeychain) cred() (azcore, error) {
	a.credOnce.Do(func() {
		c, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			a.credErr = err
			return
		}
		a.credential = defaultCredential{inner: c}
	})
	return a.credential, a.credErr
}

// Resolve implements authn.Keychain.
//
// A failure resolves anonymously rather than erroring. An anonymous read of a private
// registry fails with a 401 that names the registry, which the report shows as a
// remediation blocker; an error here would fail the whole lookup and lose that.
func (a *acrKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	registry := target.RegistryStr()
	if tok, ok := a.fromCache(registry); ok {
		return &authn.Basic{Username: acrNullGUID, Password: tok}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cred, err := a.cred()
	if err != nil {
		return authn.Anonymous, nil
	}
	aad, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{armScope}})
	if err != nil {
		return authn.Anonymous, nil
	}
	refresh, err := exchange(ctx, registry, aad.Token)
	if err != nil {
		return authn.Anonymous, nil
	}
	// ACR refresh tokens last around three hours; expire early so a long assessment
	// never presents one that has just lapsed.
	a.store(registry, refresh, time.Now().Add(2*time.Hour))
	return &authn.Basic{Username: acrNullGUID, Password: refresh}, nil
}

func (a *acrKeychain) fromCache(registry string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.cached[registry]
	if !ok || time.Now().After(c.expires) {
		return "", false
	}
	return c.token, true
}

func (a *acrKeychain) store(registry, token string, expires time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cached == nil {
		a.cached = map[string]cachedToken{}
	}
	a.cached[registry] = cachedToken{token: token, expires: expires}
}

// errNoIdentity marks a process with no Azure identity at all, which is the normal
// case for a laptop or a cluster with no workload identity configured.
var errNoIdentity = errors.New("no azure identity available")

// exchange trades an AAD token for an ACR refresh token, at the registry itself.
func exchange(ctx context.Context, registry, aadToken string) (string, error) {
	return exchangeWith(ctx, http.DefaultClient, registry, aadToken)
}

// exchangeWith is exchange with the HTTP client supplied, so a test can serve the
// registry's side of the flow instead of asserting on a mock of our own code.
func exchangeWith(ctx context.Context, client *http.Client, registry, aadToken string) (string, error) {
	form := url.Values{
		"grant_type":   {"access_token"},
		"service":      {registry},
		"access_token": {aadToken},
	}
	endpoint := "https://" + registry + "/oauth2/exchange"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("acr token exchange for %s: unexpected status %s", registry, resp.Status)
	}
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("acr token exchange for %s: decode response: %w", registry, err)
	}
	if body.RefreshToken == "" {
		return "", fmt.Errorf("acr token exchange for %s returned no refresh token", registry)
	}
	return body.RefreshToken, nil
}
