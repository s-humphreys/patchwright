package kube

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"k8s.io/client-go/rest"
)

// Azure AD authentication for AKS API servers.
//
// Reading eleven clusters needs a credential per cluster, and the obvious way — a
// ServiceAccount token per cluster in one kubeconfig Secret — means minting ten
// long-lived cluster credentials and storing them together. In a tool whose argument is
// that workload identity beats managed credentials, that is not a trade worth making.
//
// So the kubeconfig carries only what is not secret — each cluster's API server URL and
// CA certificate — and the token comes from the identity the pod already has. There is
// nothing in that Secret worth stealing, which is the point.
//
// The token is an ordinary AAD access token for the AKS server application, the same one
// kubelogin obtains in workload-identity mode. Doing it here rather than shelling out to
// kubelogin keeps the image distroless and puts no credential plugin in the runtime.

// aksServerAppID is Azure's AKS AAD server application. Every AAD-integrated AKS cluster
// accepts tokens issued for it; it is a well-known constant, not a per-tenant value.
const aksServerAppID = "6dae42f8-4368-4678-94ff-3960e28e3630"

// azureTokenSource mints and caches AAD tokens for AKS API servers.
//
// One token serves every cluster in the tenant, so this caches a single token rather than
// one per cluster. An assessment reads eleven clusters in a few minutes and a token lasts
// about an hour; refreshing early avoids presenting one that lapses mid-run, which would
// fail a cluster read and report the whole fleet as unreadable.
type azureTokenSource struct {
	mu      sync.Mutex
	cred    azureCredential
	token   string
	expires time.Time
}

// azureCredential is the slice of azidentity this needs, so a test can stand in for it.
type azureCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azureToken, error)
}

type azureToken struct {
	Token     string
	ExpiresOn time.Time
}

type defaultAzureCredential struct {
	inner *azidentity.DefaultAzureCredential
}

func (d defaultAzureCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azureToken, error) {
	t, err := d.inner.GetToken(ctx, opts)
	if err != nil {
		return azureToken{}, err
	}
	return azureToken{Token: t.Token, ExpiresOn: t.ExpiresOn}, nil
}

func newAzureTokenSource() (*azureTokenSource, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	return &azureTokenSource{cred: defaultAzureCredential{inner: cred}}, nil
}

// Token returns a valid AAD token for AKS, minting one when the cached token is missing
// or close to expiry.
func (a *azureTokenSource) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Five minutes of headroom: a read that starts before expiry and lands after it
	// fails as an authentication error, which reads like a permissions problem rather
	// than a clock one.
	if a.token != "" && time.Now().Add(5*time.Minute).Before(a.expires) {
		return a.token, nil
	}
	t, err := a.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{aksServerAppID + "/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("acquire aks token: %w", err)
	}
	a.token, a.expires = t.Token, t.ExpiresOn
	return a.token, nil
}

// apply puts the token source behind a rest.Config, replacing whatever credentials the
// kubeconfig carried.
//
// WrapTransport rather than setting BearerToken once: an assessment can outlive a token,
// and a wrapped transport fetches per request through the cache above. Any exec plugin or
// user credential from the kubeconfig is cleared — a kubeconfig for this mode is expected
// to carry none, and silently honouring one would mean authenticating as something other
// than the identity the operator configured.
func (a *azureTokenSource) apply(cfg *rest.Config) {
	cfg.BearerToken = ""
	cfg.BearerTokenFile = ""
	cfg.Username, cfg.Password = "", ""
	cfg.ExecProvider = nil
	cfg.AuthProvider = nil
	cfg.CertFile, cfg.KeyFile = "", ""
	cfg.CertData, cfg.KeyData = nil, nil

	cfg.Wrap(func(next http.RoundTripper) http.RoundTripper {
		return &azureRoundTripper{source: a, next: next}
	})
}

type azureRoundTripper struct {
	source *azureTokenSource
	next   http.RoundTripper
}

func (t *azureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.source.Token(req.Context())
	if err != nil {
		return nil, err
	}
	// Cloned: a RoundTripper must not modify the request it is given.
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	return t.next.RoundTrip(r)
}
