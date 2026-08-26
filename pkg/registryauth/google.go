package registryauth

import (
	"github.com/google/go-containerregistry/pkg/v1/google"
)

// Google Artifact Registry and Container Registry.
//
// Registered because it costs nothing: the keychain ships inside
// go-containerregistry, which is already a dependency, so a GKE deployment reading
// gcr.io or *-docker.pkg.dev works without a second credential helper.
//
// It resolves anonymous for hosts it does not serve and for a process with no Google
// credentials, so having it registered on a cluster with no Google identity is inert.
// It is also the working example of what a provider looks like: the Azure one wraps a
// third-party helper, this one wraps a library keychain, and both are one file and one
// Register call.
func init() {
	Register("google",
		[]string{"gcr.io", "*.gcr.io", "*.pkg.dev"},
		google.Keychain)
}
