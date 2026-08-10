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

	"github.com/s-humphreys/patchwright/pkg/enrich"
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
	// Contexts, when set, returns the deployment context per image NameTag so a
	// newer tag can be judged actionable and pointed at the right change target
	// (a chart/operator-controlled image is available-but-not-actionable; a
	// Kustomize/operator-set image is actionable with a source). Called once.
	Contexts func(ctx context.Context) (map[string]enrich.DeployContext, error)
}

// New returns a Resolver backed by the real registry.
func New() *Resolver { return &Resolver{Lister: craneLister{}} }

// Upgrades checks each image's repository for a newer semver tag. Images whose
// current tag is not semver (e.g. a build number or "latest") are skipped, as
// are repositories that can't be listed (logged, not fatal). Each repository is
// listed once.
func (r *Resolver) Upgrades(ctx context.Context, images []model.AssessedImage) (map[string]model.Upgrade, error) {
	var contexts map[string]enrich.DeployContext
	if r.Contexts != nil {
		c, err := r.Contexts(ctx)
		if err != nil {
			return nil, fmt.Errorf("deployment contexts: %w", err)
		}
		contexts = c
	}

	tagCache := map[string][]string{}
	// Whether the tag listing for a repo succeeded, cached alongside the tags so
	// a failed lookup is never mistaken for "no newer versions exist".
	resolvedCache := map[string]bool{}
	result := map[string]model.Upgrade{}

	for i := range images {
		img := images[i].Image
		current, err := strictSemver(img.Tag)
		if err != nil {
			continue // non-semver tag: nothing to compare
		}
		repo := img.Registry + "/" + img.Repository

		tags, ok := tagCache[repo]
		resolved, okResolved := resolvedCache[repo]
		if !ok || !okResolved {
			tags, err = r.Lister.Tags(ctx, repo)
			resolved = err == nil
			if err != nil {
				slog.DebugContext(ctx, "could not list registry tags", "repo", repo, "error", err)
				tags = nil
			}
			tagCache[repo] = tags
			resolvedCache[repo] = resolved
		}

		latest := latestNewer(current, tags)
		up := model.Upgrade{Kind: "image", Name: repo, Current: img.Tag, Source: repo, Resolved: resolved}

		// Always record how/where the image is deployed, so the report shows
		// the change target (git repo, CR, ...) even when it's on the latest tag.
		dc, hasCtx := contexts[img.NameTag()]
		if hasCtx && dc.Source != "" {
			up.Source = dc.Source
			up.SourcePath = dc.SourcePath
		}

		if latest != nil {
			up.Latest = latest.Original()
			up.Available = true
			// Judge actionability from the deployment context. No context (e.g.
			// a CSV-only run) => assume a directly deployed image, bumpable.
			if hasCtx {
				up.Actionable = dc.Actionable
				if !dc.Actionable {
					up.Managed = dc.Mechanism
				}
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
