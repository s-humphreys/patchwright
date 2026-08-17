package upgrade

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
)

// craneInspector reads an image's own description of itself from the registry,
// authenticating with the ambient docker/cloud keychain — the same credentials the
// tag lister and the scanner use, so there is one thing to grant.
//
// Only the image *config* is fetched, a few KB, never the layers. An estate of a
// thousand images is a thousand small requests rather than a thousand image pulls.
type craneInspector struct{}

// NewRegistryInspector returns an inspector backed by the registry.
func NewRegistryInspector() ImageInspector { return craneInspector{} }

func (craneInspector) Labels(ctx context.Context, ref string) (map[string]string, error) {
	cfg, err := crane.Config(ref, crane.WithContext(ctx), crane.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("read image config for %s: %w", ref, err)
	}
	// crane.Config returns the raw config JSON; decode only what is needed.
	var parsed struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		return nil, fmt.Errorf("decode image config for %s: %w", ref, err)
	}
	return parsed.Config.Labels, nil
}

func (craneInspector) Digest(ctx context.Context, ref string) (string, error) {
	d, err := crane.Digest(ref, crane.WithContext(ctx), crane.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	return d, nil
}

// craneTagLister lists tags with the same ambient credentials.
type craneTagLister struct{}

// NewTagLister returns a registry-backed tag lister.
func NewTagLister() TagLister { return craneTagLister{} }

func (craneTagLister) Tags(ctx context.Context, repo string) ([]string, error) {
	return crane.ListTags(repo, crane.WithContext(ctx), crane.WithAuthFromKeychain(authn.DefaultKeychain))
}
