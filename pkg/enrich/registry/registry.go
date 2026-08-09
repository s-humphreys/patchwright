// Package registry implements an UpgradeSource that checks a container
// registry for a newer image tag than the one currently deployed — the
// remediation path for images not managed by a higher-level artifact (plain
// manifests, Kustomize). It complements the Flux chart source.
package registry

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// strictSemver parses a tag as strict MAJOR.MINOR.PATCH (a leading "v" is
// tolerated), so build-number and moving tags ("918319", "latest") are rejected
// rather than coerced into versions.
func strictSemver(tag string) (*semver.Version, error) {
	return semver.StrictNewVersion(strings.TrimPrefix(tag, "v"))
}

// TagLister lists the tags available for a repository ("registry/repository").
type TagLister interface {
	Tags(ctx context.Context, repo string) ([]string, error)
}

// craneLister lists tags via the registry API, authenticating with the ambient
// credentials (docker config / cloud keychains), like Trivy.
type craneLister struct{}

func (craneLister) Tags(ctx context.Context, repo string) ([]string, error) {
	return crane.ListTags(repo, crane.WithContext(ctx), crane.WithAuthFromKeychain(authn.DefaultKeychain))
}

// Resolver reports a newer semver image tag per image.
type Resolver struct {
	Lister TagLister
	// Managed, when set, returns image NameTag -> controlling mechanism
	// ("helm"/"operator") for images whose version is controlled by a chart or
	// operator. Such images are reported as Available (a newer tag exists) but
	// NOT Actionable — bumping the tag directly would be reverted. Called once.
	Managed func(ctx context.Context) (map[string]string, error)
}

// New returns a Resolver backed by the real registry.
func New() *Resolver { return &Resolver{Lister: craneLister{}} }

// Upgrades checks each image's repository for a newer semver tag. Images whose
// current tag is not semver (e.g. a build number or "latest") are skipped, as
// are repositories that can't be listed (logged, not fatal). Each repository is
// listed once.
func (r *Resolver) Upgrades(ctx context.Context, images []model.AssessedImage) (map[string]model.Upgrade, error) {
	var managed map[string]string
	if r.Managed != nil {
		m, err := r.Managed(ctx)
		if err != nil {
			return nil, fmt.Errorf("managed images: %w", err)
		}
		managed = m
	}

	tagCache := map[string][]string{}
	result := map[string]model.Upgrade{}

	for i := range images {
		img := images[i].Image
		current, err := strictSemver(img.Tag)
		if err != nil {
			continue // non-semver tag: nothing to compare
		}
		repo := img.Registry + "/" + img.Repository

		tags, ok := tagCache[repo]
		if !ok {
			tags, err = r.Lister.Tags(ctx, repo)
			if err != nil {
				slog.DebugContext(ctx, "could not list registry tags", "repo", repo, "error", err)
				tags = nil
			}
			tagCache[repo] = tags
		}

		latest := latestNewer(current, tags)
		up := model.Upgrade{Kind: "image", Name: repo, Current: img.Tag, Source: repo}
		if latest != nil {
			up.Latest = latest.Original()
			up.Available = true
			// A newer tag is directly actionable only when the image's version
			// isn't controlled by a chart or operator.
			if by := managed[img.NameTag()]; by != "" {
				up.Managed = by
			} else {
				up.Actionable = true
			}
		}
		result[img.NameTag()] = up
	}
	return result, nil
}

// latestNewer returns the highest semver tag strictly greater than current, or
// nil if none. Pre-releases are ignored unless current is itself a pre-release.
func latestNewer(current *semver.Version, tags []string) *semver.Version {
	allowPre := current.Prerelease() != ""
	var latest *semver.Version
	for _, t := range tags {
		v, err := strictSemver(t)
		if err != nil {
			continue
		}
		if v.Prerelease() != "" && !allowPre {
			continue
		}
		if !v.GreaterThan(current) {
			continue
		}
		if latest == nil || v.GreaterThan(latest) {
			latest = v
		}
	}
	return latest
}
