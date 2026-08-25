// Package registryauth resolves credentials for reading image metadata.
//
// Patchwright reads registries constantly — listing tags to find a newer version,
// reading image configs to find the base an image was built on — and reads nothing
// else. It never pulls a layer, never pushes and never deletes, so read credentials
// are all it ever wants.
//
// The difficulty is that "read credentials" means something different per cloud. The
// default keychain understands docker config files, which is what a developer has after
// `docker login` or `az acr login`. In a cluster there is no docker config: there is a
// projected identity token and an expectation that the process knows how to exchange
// it. That exchange is cloud-specific, so it lives behind a provider here rather than
// being assumed anywhere in the calling code.
//
// Providers are consulted in registration order after the docker config, so a
// developer's explicit `docker login` always wins over an ambient cloud identity —
// surprising them with a different account than the one they logged into would be
// worse than failing.
//
// Each provider declares the hosts it serves and is not asked about anything else. A
// credential helper asked about a foreign host does not decline politely, it goes
// looking: the ACR helper spends thirty seconds on instance metadata before giving up,
// which turned every read of mcr.microsoft.com into half a minute.
//
// Adding a provider is one file with an init(), the way vulnerability and exploit
// sources work. See azure.go and google.go; AWS ECR would wrap
// github.com/awslabs/amazon-ecr-credential-helper the same way azure.go wraps the ACR
// helper.
package registryauth

import (
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
)

var (
	mu        sync.Mutex
	providers []provider
)

type provider struct {
	name     string
	hosts    []string
	keychain authn.Keychain
}

// Register adds a cloud credential provider for the registry hosts it serves. Called
// from a provider's init().
//
// Hosts are exact or a leading "*." wildcard, and they are not decoration: a helper
// asked about a host it cannot serve does not politely decline, it goes looking for
// credentials. The ACR helper spends thirty seconds on an instance-metadata lookup
// before giving up, so consulting it for mcr.microsoft.com — the base registry for
// every .NET image here — made each read cost half a minute.
func Register(name string, hosts []string, keychain authn.Keychain) {
	mu.Lock()
	defer mu.Unlock()
	providers = append(providers, provider{name: name, hosts: hosts, keychain: keychain})
}

// serves reports whether a provider claims a registry host.
func (p provider) serves(host string) bool {
	host = strings.ToLower(host)
	for _, h := range p.hosts {
		h = strings.ToLower(h)
		if strings.HasPrefix(h, "*.") {
			if strings.HasSuffix(host, h[1:]) {
				return true
			}
			continue
		}
		if host == h {
			return true
		}
	}
	return false
}

// scoped consults a provider only for the hosts it claims, and answers anonymously for
// everything else.
type scoped struct{ p provider }

func (s scoped) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if !s.p.serves(target.RegistryStr()) {
		return authn.Anonymous, nil
	}
	return s.p.keychain.Resolve(target)
}

// Names lists the registered providers, for logging what a run could authenticate to.
func Names() []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, 0, len(providers))
	for _, p := range providers {
		out = append(out, p.name)
	}
	return out
}

// Keychain returns the credentials to read registries with: the docker config first,
// then each registered cloud provider.
//
// Order is the whole design. A developer who has run `docker login` or `az acr login`
// gets exactly the account they logged in as, and the ambient cloud identity is the
// fallback rather than the override.
func Keychain() authn.Keychain {
	mu.Lock()
	defer mu.Unlock()
	chain := make([]authn.Keychain, 0, len(providers)+1)
	chain = append(chain, authn.DefaultKeychain)
	for _, p := range providers {
		chain = append(chain, scoped{p: p})
	}
	return authn.NewMultiKeychain(chain...)
}
