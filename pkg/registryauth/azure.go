package registryauth

import (
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
)

// Azure Container Registry.
//
// The helper exchanges whatever Azure identity the process has for an ACR refresh
// token: a workload identity's projected federated token (AZURE_FEDERATED_TOKEN_FILE,
// which the AKS webhook injects), a managed identity, or a service principal from the
// environment. That exchange is why this is needed at all — the default keychain reads
// docker config files, and a workload identity is not one.
//
// This is the same helper Trivy and Kaniko use, rather than a token exchange written
// here. A tool whose value is being right about credentials should not hand-roll the
// bit where it authenticates.
//
// It answers for *.azurecr.io and resolves anonymous for everything else, so it is safe
// to have registered on a cluster with no Azure identity at all.
func init() {
	Register("azure",
		// The clouds ACR runs in. Anything else — mcr.microsoft.com included, which is
		// Microsoft's public registry and needs no credentials — is somebody else's
		// problem, and asking this helper about it costs thirty seconds.
		[]string{"*.azurecr.io", "*.azurecr.cn", "*.azurecr.us"},
		authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()))
}
