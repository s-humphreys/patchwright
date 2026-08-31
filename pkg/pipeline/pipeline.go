// Package pipeline wires the assessment stages together: attribute each
// occurrence, dedupe into images, split into per-owner findings, and evaluate
// policy. It is the reusable core that both the CLI and any future controller
// drive.
package pipeline

import (
	"context"
	"log/slog"
	"sort"
	"time"

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
	age         *enrich.AgeEnricher         // optional: CVE first-seen enrichment after scan
	remediation *enrich.RemediationEnricher // optional: deployment upgrade detection
	baseDiff    *enrich.BaseDiffEnricher    // optional: base-image attribution, after remediation
	imageFacts  ImageEnricher               // optional: when each image was built
	inFlight    ImageEnricher               // optional: open pull requests applying those upgrades

	// failures are the enrichments that could not run. An enrichment is not the
	// assessment: losing one must not lose the other, but it must be reported — a
	// missing signal that nobody can see looks exactly like a signal that found
	// nothing.
	failures []model.SourceFailure
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

// WithAgeEnricher enables CVE first-seen enrichment, after image scanning: it
// stamps ages onto vulnerabilities that already exist.
func WithAgeEnricher(a *enrich.AgeEnricher) Option {
	return func(p *Pipeline) { p.age = a }
}

// WithImageFactsEnricher records when each image was built, which is what separates
// "you ignored this" from "this has not shipped since March".
func WithImageFactsEnricher(e ImageEnricher) Option {
	return func(p *Pipeline) { p.imageFacts = e }
}

// WithBaseDiffEnricher enables base-image attribution: which of an image's CVEs
// came from its base, and which of them the recommended base upgrade would fix.
//
// After remediation, because it needs the base references that base-image
// resolution produces.
func WithBaseDiffEnricher(b *enrich.BaseDiffEnricher) Option {
	return func(p *Pipeline) { p.baseDiff = b }
}

// ImageEnricher annotates assessed images in place. Satisfied by the in-flight
// enricher, which has to run after remediation because it needs the upgrade it
// is looking for a pull request for.
type ImageEnricher interface {
	EnrichImages(ctx context.Context, images []model.AssessedImage) error
}

// WithInFlightEnricher enables detection of remediation already under way, after
// upgrade detection.
func WithInFlightEnricher(e ImageEnricher) Option {
	return func(p *Pipeline) { p.inFlight = e }
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
// Failures reports the enrichments that could not run in the last Run.
func (p *Pipeline) Failures() []model.SourceFailure { return p.failures }

// recordFailure notes an enrichment that could not run, and says so in the log.
func (p *Pipeline) recordFailure(ctx context.Context, stage string, err error) {
	slog.WarnContext(ctx, "enrichment failed; the assessment continues without it",
		"stage", stage, "error", err)
	p.failures = append(p.failures, model.SourceFailure{Stage: stage, Error: err.Error()})
}

func (p *Pipeline) Run(ctx context.Context, occurrences []model.Occurrence) ([]model.Finding, error) {
	// Per run: a failure from an hour ago is not a failure now, and reporting it as one
	// would be the same lie in the other direction.
	p.failures = nil

	// A memo for this run, so two stages that need the same expensive fetch pay for it
	// once. The age and exploit sources both sweep the scan platform's whole
	// vulnerability catalogue, which measured two minutes each of a ten-minute run.
	// Scoped to the run, so nothing carries over into the next one.
	ctx = enrich.WithRunCache(ctx)

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
	if p.age != nil {
		if err := p.age.EnrichImages(ctx, images); err != nil {
			// Ageing is decoration on top of the queue, not the queue: losing it must
			// not lose the assessment. Recorded rather than only logged, so the page can
			// say the ages are missing instead of showing them as unknown for a reason
			// nobody can see.
			p.recordFailure(ctx, "age", err)
		}
	}
	if p.exploit != nil {
		if err := p.exploit.EnrichImages(ctx, images); err != nil {
			// Exploit intel gates whole priority tiers, so losing it matters more than
			// losing ages — and failing the run over it matters more still. One 502
			// from a public feed, one request in a hundred, used to discard a completed
			// scan of every image in the estate.
			//
			// The assessment continues without it. ExploitChecked stays false, so every
			// EPSS and KEV cell reads "not checked" rather than "none found", and the
			// failure is reported rather than inferred from a queue that has gone quiet.
			p.recordFailure(ctx, "exploit", err)
		}
	}
	if p.remediation != nil {
		if err := p.remediation.EnrichImages(ctx, images); err != nil {
			return nil, err
		}
	}
	if p.imageFacts != nil {
		// Never fatal: a build date explains a finding rather than deciding it.
		if err := p.imageFacts.EnrichImages(ctx, images); err != nil {
			p.recordFailure(ctx, "image-age", err)
		}
	}
	if p.baseDiff != nil {
		// Never fatal. Base attribution is an improvement on the queue, not a
		// prerequisite for it: without it every CVE reports an unknown origin,
		// which is exactly what it was before this existed.
		if err := p.baseDiff.EnrichImages(ctx, images); err != nil {
			p.recordFailure(ctx, "base-diff", err)
		}
	}
	if p.inFlight != nil {
		if err := p.inFlight.EnrichImages(ctx, images); err != nil {
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
	// Said loudly, and once per run. A lapsed suppression returns work to the queue,
	// so without this the queue simply grows and reads as the estate getting worse.
	for _, r := range p.evaluator.Expired(time.Now()) {
		slog.WarnContext(ctx, "suppression rule has expired and no longer applies; "+
			"findings it was hiding are back in the queue",
			"rule", r.Name, "until", r.Until)
	}
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
				InFlight:           ai.InFlight,
				InFlightChecked:    ai.InFlightChecked,
				InFlightReason:     ai.InFlightReason,
				BaseDiff:           ai.BaseDiff,
				ImageBuilt:         ai.ImageBuilt,
				BuildRepo:          ai.BuildRepo,
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
