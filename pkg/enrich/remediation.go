package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"maps"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// UpgradeSource reports the newer version available for how each image is
// deployed, keyed by image "registry/repository:tag" (model.Image.NameTag).
// Implementations cover a remediation path — the Flux HelmRelease chart source
// (cluster-derived) and the registry image-tag source (image-derived) today,
// with Flux Git/OCI sources to follow. The images being assessed are passed in
// so image-derived sources know what to look up; cluster-derived sources may
// ignore them.
type UpgradeSource interface {
	Upgrades(ctx context.Context, images []model.AssessedImage) (map[string]model.Upgrade, error)
}

// DeployContext describes how an image is deployed, so a registry image-tag
// upgrade can be judged actionable and pointed at the right place to change.
type DeployContext struct {
	// Mechanism is how the workload is deployed: helm, operator, kustomize, or
	// manifest.
	Mechanism string
	// Actionable reports whether the image tag can be bumped directly at this
	// level — true for manifest/Kustomize images and for operator images whose
	// tag is a field in the owning custom resource; false for chart-managed or
	// operator-derived images (bump the chart/operator instead).
	Actionable bool
	// Source is where the change lands: a git repository URL (Kustomize), the
	// owning custom resource ref (operator, e.g. "Api/ns/name"), or empty.
	Source string
	// Manager is the bare name of the component that controls this workload's
	// version, when known (e.g. "flux-operator", "kiali-operator"). It answers a
	// different question from Source: Source is WHERE a change lands, Manager is
	// WHAT owns the version. For a controller-managed workload the version cannot
	// be changed in place at all, so the remediation is to upgrade the manager —
	// which is usually its own finding.
	Manager string
	// SourcePath is the directory within Source, when Source is a repository.
	// Kept separate from the URL rather than joined with kustomize's "//"
	// notation: the joined form is not a resolvable link, and anything that
	// renders a change target (a ticket, a report) wants a URL someone can click
	// plus the path stated alongside it.
	SourcePath string
	// ManagerImage is the Manager's own image (a NameTag), when a workload running
	// it was found in the same cluster. For an operator-derived image it is how the
	// operator's upgrade is found: that upgrade is the only change that moves it.
	ManagerImage string
	// OwnerUnread reports that the owning custom resource could not be read (its
	// API group is not granted, or the fetch failed), so whether it sets the image
	// is unknown rather than known to be false.
	OwnerUnread bool
}

// DeploymentContextSource reports the deployment context per image NameTag, so
// the registry upgrade source can set actionability and the change target.
type DeploymentContextSource interface {
	ImageDeployments(ctx context.Context) (map[string]DeployContext, error)
}

// RemediationEnricher annotates each image with an available upgrade — the
// concrete remediation path (e.g. "bump chart 1.2 -> 1.5", or a newer image
// tag). It runs its sources in order and, per image, the first source to report
// an upgrade wins (so deployment-aware sources should be listed before the
// registry fallback). Image-level enricher (runs after dedupe).
type RemediationEnricher struct {
	Sources []UpgradeSource
}

// NewRemediationEnricher builds a RemediationEnricher from ordered sources.
func NewRemediationEnricher(sources ...UpgradeSource) RemediationEnricher {
	return RemediationEnricher{Sources: sources}
}

// EnrichImages sets Upgrade on each image an upgrade was found for.
func (r RemediationEnricher) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	merged := map[string]model.Upgrade{}
	for _, src := range r.Sources {
		ups, err := src.Upgrades(ctx, images)
		if err != nil {
			return fmt.Errorf("upgrade source: %w", err)
		}
		for image, up := range ups {
			if _, exists := merged[image]; !exists {
				merged[image] = up
			}
		}
	}
	resolveOperatorUpgrades(merged)

	matched, available := 0, 0
	for i := range images {
		// Record that detection ran for every image, whether or not a version
		// was resolved. Without this, an unset Upgrade means both "we never
		// looked" and "we looked and could not tell" — and the second is a gap
		// to chase (e.g. a private registry whose tags we cannot list), not a
		// clean "nothing to upgrade".
		images[i].RemediationChecked = true

		up, ok := merged[images[i].Image.NameTag()]
		if !ok {
			continue
		}
		u := up
		images[i].Upgrade = &u
		matched++
		if u.Available {
			available++
		}
	}
	slog.DebugContext(ctx, "detected deployment upgrades", "matched", matched, "upgradable", available)
	return nil
}

// resolveOperatorUpgrades turns each operator-chosen image into the upgrade of the
// operator that chooses it, or says why there is none.
//
// Done here because this is the one place every source's answers meet: the image
// sources report that the image has no version of its own, and the operator's
// upgrade comes from whichever source understands how the operator is installed.
//
// A Flux-managed chart upgrade of the operator becomes this image's upgrade. Any
// other available operator upgrade makes this image a managed upgrade with no
// target tag, folded into the operator's own ticket: presenting the operator's
// tags as this image's would be the same false statement this exists to stop.
func resolveOperatorUpgrades(merged map[string]model.Upgrade) {
	// Read the operators' upgrades as the sources reported them, so the outcome
	// does not depend on map order when an operator is itself operator-chosen.
	reported := maps.Clone(merged)
	for image, u := range reported {
		if !u.OperatorChosen || u.OperatorImage == "" {
			continue
		}
		op, ok := reported[u.OperatorImage]
		name := OperatorName(u.Manager, u.Source)
		switch {
		case ok && op.Kind == "chart" && op.Available && op.Actionable:
			p := op
			p.ImageCurrent, p.ImageLatest, p.ImagePinned = u.Current, "", false
			p.ImageLatestFrom, p.ImageLatestRepo = "", ""
			p.Managed, p.Manager = "operator", u.Manager
			p.OperatorChosen, p.OperatorImage = true, u.OperatorImage
			p.Reason = ""
			merged[image] = p
		case ok && op.Resolved && !op.Available:
			// The one case where "no upgrade" is established rather than assumed.
			u.Resolved = true
			u.Reason = "version chosen by the operator " + name + "; the operator is on its latest version"
			merged[image] = u
		case ok && op.Available:
			// Any other operator upgrade: a newer operator image, whether bumped
			// directly or through a Helm release no HelmRelease describes (the
			// flux-operator case). This image is available as a managed upgrade with
			// no target tag of its own, so the planner folds it into the operator's
			// ticket rather than dropping it or inventing a tag for it.
			u.Available, u.Resolved, u.Latest = true, true, ""
			u.Reason = fmt.Sprintf("version chosen by the operator %s; upgrading it (%s %s -> %s) is the only "+
				"change that moves this image", name, op.Name, op.Current, op.Latest)
			merged[image] = u
		default:
			u.Reason = "version chosen by the operator " + name + "; the operator's own upgrade could not be resolved"
			merged[image] = u
		}
	}
}

// OperatorName names the operator that chooses an image's version for a reader:
// by name when its custom resource or labels say, else by the resource it
// reconciles, which is at least somewhere to start.
func OperatorName(manager, source string) string {
	if manager != "" {
		return manager
	}
	if source != "" {
		return "that reconciles " + source
	}
	return "that owns this workload"
}
