// Package pipeline wires the assessment stages together: attribute each
// occurrence, dedupe into images, split into per-owner findings, and evaluate
// policy. It is the reusable core that both the CLI and any future controller
// drive.
package pipeline

import (
	"context"
	"log/slog"
	"sort"

	"github.com/s-humphreys/patchwright/pkg/attribute"
	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/dedupe"
	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/policy"
)

// Pipeline holds the compiled ownership and policy engines and optional
// image-level enrichment.
type Pipeline struct {
	attributor  *attribute.Attributor
	evaluator   *policy.Evaluator
	scanner     *enrich.ImageScanner        // optional: per-CVE scan after dedupe
	exploit     *enrich.ExploitEnricher     // optional: EPSS/KEV enrichment after scan
	remediation *enrich.RemediationEnricher // optional: deployment upgrade detection
}

// Option customizes a Pipeline.
type Option func(*Pipeline)

// WithImageScanner enables per-CVE image scanning (e.g. Trivy) after dedupe,
// populating each image's vulnerabilities before policy runs.
func WithImageScanner(s *enrich.ImageScanner) Option {
	return func(p *Pipeline) { p.scanner = s }
}

// WithExploitEnricher enables exploit-intelligence (EPSS/KEV) enrichment of the
// scanned vulnerabilities, after image scanning and before policy.
func WithExploitEnricher(e *enrich.ExploitEnricher) Option {
	return func(p *Pipeline) { p.exploit = e }
}

// WithRemediationEnricher enables detection of available upgrades (e.g. a newer
// Helm chart) for how each image is deployed, after dedupe and before policy.
func WithRemediationEnricher(r *enrich.RemediationEnricher) Option {
	return func(p *Pipeline) { p.remediation = r }
}

// New builds a Pipeline from configuration, compiling all rules up front.
func New(cfg *config.Config, opts ...Option) (*Pipeline, error) {
	a, err := attribute.New(cfg.Owners)
	if err != nil {
		return nil, err
	}
	e, err := policy.New(cfg.Actionable, cfg.Suppress)
	if err != nil {
		return nil, err
	}
	p := &Pipeline{attributor: a, evaluator: e}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Run executes the full assessment over raw occurrences and returns findings.
// The input slice is mutated in place by the attribution stage.
func (p *Pipeline) Run(ctx context.Context, occurrences []model.Occurrence) ([]model.Finding, error) {
	if _, err := p.attributor.AttributeAll(occurrences); err != nil {
		return nil, err
	}
	slog.DebugContext(ctx, "attributed occurrences", "occurrences", len(occurrences))

	images := dedupe.ByImage(occurrences)
	slog.InfoContext(ctx, "deduplicated to images", "occurrences", len(occurrences), "images", len(images))

	if p.scanner != nil {
		if err := p.scanner.EnrichImages(ctx, images); err != nil {
			return nil, err
		}
	}
	if p.exploit != nil {
		if err := p.exploit.EnrichImages(ctx, images); err != nil {
			return nil, err
		}
	}
	if p.remediation != nil {
		if err := p.remediation.EnrichImages(ctx, images); err != nil {
			return nil, err
		}
	}

	findings := buildFindings(images)
	if err := p.evaluator.EvaluateAll(findings); err != nil {
		return nil, err
	}

	actionable := 0
	for i := range findings {
		if findings[i].Actionable {
			actionable++
		}
	}
	slog.InfoContext(ctx, "evaluated findings", "findings", len(findings), "actionable", actionable)
	return findings, nil
}

// buildFindings splits each assessed image into one finding per distinct owner,
// preserving deterministic order (image first-seen, then owner first-seen).
func buildFindings(images []model.AssessedImage) []model.Finding {
	var findings []model.Finding
	for _, ai := range images {
		type group struct {
			owner       model.Owner
			occurrences []model.Occurrence
		}
		groups := map[string]*group{}
		var order []string
		for _, o := range ai.Occurrences {
			key := o.Owner.Class + "\x00" + o.Owner.Team
			g := groups[key]
			if g == nil {
				g = &group{owner: o.Owner}
				groups[key] = g
				order = append(order, key)
			}
			g.occurrences = append(g.occurrences, o)
		}
		for _, key := range order {
			g := groups[key]
			reconciled, live := aggregateLiveness(g.occurrences)
			findings = append(findings, model.Finding{
				Image:              ai.Image,
				Counts:             ai.Counts,
				Vulns:              ai.Vulns,
				RiskScore:          ai.RiskScore,
				Owner:              g.owner,
				Occurrences:        g.occurrences,
				Dimensions:         aggregate(g.occurrences, func(o model.Occurrence) map[string]string { return o.Resource.Dimensions }),
				Labels:             aggregate(g.occurrences, func(o model.Occurrence) map[string]string { return o.Resource.Labels }),
				Reconciled:         reconciled,
				Live:               live,
				Scanned:            ai.Scanned,
				ScanError:          ai.ScanError,
				ExploitChecked:     ai.ExploitChecked,
				Upgrade:            ai.Upgrade,
				RemediationChecked: ai.RemediationChecked,
			})
		}
	}
	return findings
}

// aggregateLiveness reports whether liveness data was available for any
// occurrence (reconciled) and whether any occurrence is running (live).
func aggregateLiveness(occ []model.Occurrence) (reconciled, live bool) {
	for _, o := range occ {
		if o.Reconciled {
			reconciled = true
		}
		if o.Live {
			live = true
		}
	}
	return reconciled, live
}

// aggregate unions the string maps selected by get across occurrences into a
// map of key -> sorted distinct values.
func aggregate(occ []model.Occurrence, get func(model.Occurrence) map[string]string) map[string][]string {
	sets := map[string]map[string]struct{}{}
	for _, o := range occ {
		for k, v := range get(o) {
			if sets[k] == nil {
				sets[k] = map[string]struct{}{}
			}
			sets[k][v] = struct{}{}
		}
	}
	out := make(map[string][]string, len(sets))
	for k, set := range sets {
		vals := make([]string, 0, len(set))
		for v := range set {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		out[k] = vals
	}
	return out
}
