package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/internal/metrics"
	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/enrich/registry"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/pipeline"
	"github.com/s-humphreys/patchwright/pkg/provider"
	"github.com/s-humphreys/patchwright/pkg/upgrade"
)

// assessInputs are the flags describing how to run an assessment. They are
// shared by the `assess` and `serve` commands so both build the pipeline the
// same way.
type assessInputs struct {
	provider       providerFlags
	configPaths    []string
	liveSource     string
	liveOptions    []string
	vulnSource     string
	vulnOptions    []string
	exploitSource  string
	exploitOptions []string
	ageSource      string
	ageOptions     []string
	remediation    bool
}

// assessor is a built, reusable assessment: a provider, the live enrichers, and
// the compiled pipeline. Its run method can be called repeatedly (e.g. by the
// server on a schedule).
type assessor struct {
	provider      provider.Provider
	liveEnrichers []enrich.Enricher
	pipeline      *pipeline.Pipeline

	providerName  string
	liveSource    string
	vulnSource    string
	exploitSource string
	ageSource     string
}

// newAssessor loads config and constructs the provider, enrichers, and pipeline
// from the inputs.
func newAssessor(in assessInputs) (*assessor, error) {
	paths, err := expandConfigPaths(in.configPaths)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no config provided: pass --config with one or more YAML files or directories")
	}
	cfg, err := config.Load(paths...)
	if err != nil {
		return nil, err
	}

	var popts []pipeline.Option
	var liveEnrichers []enrich.Enricher
	var upgradeSources []enrich.UpgradeSource
	var deployContexts func(context.Context) (map[string]enrich.DeployContext, error)

	if in.liveSource != "" {
		src, err := newLiveSource(in.liveSource, in.liveOptions)
		if err != nil {
			return nil, err
		}
		liveEnrichers = append(liveEnrichers, enrich.NewLiveness(src))
		if ls, ok := src.(enrich.LabelSource); ok {
			liveEnrichers = append(liveEnrichers, enrich.NewNamespaceLabeler(ls))
		}
		if in.remediation {
			if us, ok := src.(enrich.UpgradeSource); ok {
				upgradeSources = append(upgradeSources, us)
			}
			if dc, ok := src.(enrich.DeploymentContextSource); ok {
				deployContexts = dc.ImageDeployments
			}
		}
	}
	if in.remediation {
		// Base images first: for an image you build yourself, a newer tag of your own
		// image is a release number rather than a fix, so the base has to be asked
		// about before the tag source gets a chance to answer.
		if len(cfg.Remediation.FirstPartyRegistries) > 0 {
			base := upgrade.NewBaseResolver(cfg.Remediation, upgrade.NewRegistryInspector(), upgrade.NewTagLister())
			upgradeSources = append(upgradeSources, base)
		}
		reg := registry.New()
		reg.Contexts = deployContexts
		reg.SkipRegistries = cfg.Remediation.FirstPartyRegistries
		upgradeSources = append(upgradeSources, reg)
		r := enrich.NewRemediationEnricher(upgradeSources...)
		popts = append(popts, pipeline.WithRemediationEnricher(&r))

		// Remediation already under way, so an upgrade with an open pull request
		// can be told apart from one nobody has started.
		if cfg.Remediation.InFlight.Enabled() {
			src, err := newPullRequestSource(cfg.Remediation.InFlight)
			if err != nil {
				return nil, err
			}
			popts = append(popts, pipeline.WithInFlightEnricher(&upgrade.InFlightEnricher{
				Cfg: cfg.Remediation, Source: src, Inspector: upgrade.NewRegistryInspector(),
			}))
		}
	}

	if in.vulnSource != "" && cfg.Scan.Disabled {
		slog.Warn("image scanning disabled by config (scan.disabled); vulnerability data will be absent",
			"vuln_source", in.vulnSource)
	}
	if in.vulnSource != "" && !cfg.Scan.Disabled {
		scanner, err := buildScanner(in.vulnSource, in.vulnOptions,
			cfg.Scan.EffectiveSkipOwnerClasses(), cfg.Scan.SkipRegistries)
		if err != nil {
			return nil, err
		}
		popts = append(popts, pipeline.WithImageScanner(scanner))
	}
	if in.ageSource != "" {
		if in.vulnSource == "" {
			return nil, fmt.Errorf("--age-source requires --vuln-source: there are no vulnerabilities to date otherwise")
		}
		enricher, err := buildAgeEnricher(in.ageSource, in.ageOptions)
		if err != nil {
			return nil, err
		}
		popts = append(popts, pipeline.WithAgeEnricher(enricher))
	}
	if in.exploitSource != "" {
		if in.vulnSource == "" {
			return nil, fmt.Errorf("--exploit-source requires --vuln-source: there are no vulnerabilities to annotate with EPSS/KEV otherwise")
		}
		enricher, err := buildExploitEnricher(in.exploitSource, in.exploitOptions)
		if err != nil {
			return nil, err
		}
		popts = append(popts, pipeline.WithExploitEnricher(enricher))
	}

	pl, err := pipeline.New(cfg, popts...)
	if err != nil {
		return nil, err
	}
	p, err := in.provider.build()
	if err != nil {
		return nil, err
	}

	return &assessor{
		provider:      p,
		liveEnrichers: liveEnrichers,
		pipeline:      pl,
		providerName:  in.provider.name,
		liveSource:    in.liveSource,
		vulnSource:    in.vulnSource,
		exploitSource: in.exploitSource,
		ageSource:     in.ageSource,
	}, nil
}

// run executes the assessment: fetch, reconcile, and evaluate. It returns the
// full finding set (no display filtering).
func (a *assessor) Run(ctx context.Context) ([]model.Finding, error) {
	slog.InfoContext(ctx, "starting assessment",
		"provider", a.providerName, "vuln_source", a.vulnSource, "exploit_source", a.exploitSource, "age_source", a.ageSource, "live_source", a.liveSource)

	occ, err := a.provider.Fetch(ctx)
	if err != nil {
		// Separate from the assessment counter: a provider that has started
		// refusing us (an expired API key, a moved export) is a different fault
		// from an assessment that failed later on, and needs a different response.
		metrics.ProviderFetch("failure")
		return nil, err
	}
	metrics.ProviderFetch("success")
	slog.InfoContext(ctx, "fetched scan data", "provider", a.providerName, "occurrences", len(occ))

	if len(a.liveEnrichers) > 0 {
		slog.InfoContext(ctx, "reconciling against live clusters", "source", a.liveSource, "enrichers", len(a.liveEnrichers))
		for _, e := range a.liveEnrichers {
			if err := e.Enrich(ctx, occ); err != nil {
				return nil, err
			}
		}
	}
	findings, err := a.pipeline.Run(ctx, occ)
	if err != nil {
		return nil, err
	}
	warnUnassessed(ctx, findings)
	warnStaleProviderData(ctx, findings)
	return findings, nil
}

// warnStaleProviderData reports how old the provider's own assessment data is.
//
// Distinct from when this run happened: a scheduled run over a stale export
// produces a current-looking assessment of week-old data, and nothing else in the
// output would say so.
func warnStaleProviderData(ctx context.Context, findings []model.Finding) {
	var newest time.Time
	for i := range findings {
		for _, o := range findings[i].Occurrences {
			if o.LastSeen.After(newest) {
				newest = o.LastSeen
			}
		}
	}
	if newest.IsZero() {
		return // nothing carried a timestamp; the coverage warning covers this
	}
	age := time.Since(newest)
	msg := "scan provider data age"
	if age > 48*time.Hour {
		slog.WarnContext(ctx, msg+": the export is not recent, so findings describe an older estate",
			"newest_assessment", newest.Format(time.RFC3339), "age_hours", int(age.Hours()))
		return
	}
	slog.InfoContext(ctx, msg, "newest_assessment", newest.Format(time.RFC3339), "age_hours", int(age.Hours()))
}

// warnUnassessed reports images the scan provider never assessed. Their zero
// counts are ignorance, not health, so a silent report would overstate coverage
// — and since they can never match a count-based policy rule, they are absent
// from the actionable queue for a reason that has nothing to do with risk.
func warnUnassessed(ctx context.Context, findings []model.Finding) {
	unassessed := map[string]bool{}
	total := map[string]bool{}
	for _, f := range findings {
		total[f.Image.Key()] = true
		if !f.ProviderAssessed() {
			unassessed[f.Image.Key()] = true
		}
	}
	if len(unassessed) == 0 {
		return
	}
	attrs := []any{"unassessed_images", len(unassessed), "total_images", len(total)}
	// When the provider says why, lead with the largest cause. A coverage number
	// invites resignation; a named cause is a job someone can pick up, and in
	// practice one cause has accounted for nearly all of it.
	if reason, images := topAssessmentIssue(findings); reason != "" {
		attrs = append(attrs, "top_reason", reason, "images_affected", images)
	}
	slog.WarnContext(ctx, "provider never assessed some images — their zero counts are absence of data, not a clean result",
		attrs...)
}

// topAssessmentIssue returns the provider's most common stated reason for not
// assessing an image, and how many images it accounts for. Counted per image
// rather than per finding so the number is comparable with unassessed_images
// above; the same image under two owners is one gap, not two.
func topAssessmentIssue(findings []model.Finding) (string, int) {
	byImage := map[string]string{}
	for _, f := range findings {
		if f.ProviderAssessed() {
			continue
		}
		if issues := f.AssessmentIssues(); len(issues) > 0 {
			byImage[f.Image.Key()] = issues[0]
		}
	}
	counts := map[string]int{}
	for _, reason := range byImage {
		counts[reason]++
	}
	var topReason string
	var topCount int
	for reason, n := range counts {
		// Ties broken by reason text so the log line is stable run to run.
		if n > topCount || (n == topCount && reason < topReason) {
			topReason, topCount = reason, n
		}
	}
	return topReason, topCount
}

// newPullRequestSource builds the in-flight provider named in config. Unknown
// providers are an error rather than a no-op: a typo would otherwise silently
// mean "nothing is in flight".
func newPullRequestSource(cfg config.InFlightConfig) (upgrade.PullRequestSource, error) {
	switch strings.ToLower(cfg.Provider) {
	case "azuredevops":
		return upgrade.NewAzureDevOps(cfg)
	default:
		return nil, fmt.Errorf("unknown in-flight provider %q: supported providers are azuredevops", cfg.Provider)
	}
}
