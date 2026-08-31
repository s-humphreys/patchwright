package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/internal/metrics"
	"github.com/s-humphreys/patchwright/pkg/basescan"
	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/enrich/registry"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/pipeline"
	"github.com/s-humphreys/patchwright/pkg/provider"
	"github.com/s-humphreys/patchwright/pkg/support"
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
	// supportSource names where maintenance windows come from ("endoflife" or empty
	// for none). Empty means support status is not checked at all, and every finding
	// says so rather than implying its base is maintained.
	supportSource  string
	supportOptions []string
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

	// sources is what this run was configured to do, reported so a consumer can tell
	// a stage that found nothing from one that never ran.
	sources model.Sources
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

	sources := model.Sources{
		Provider: in.provider.name, VulnSource: in.vulnSource,
		ExploitSource: in.exploitSource, AgeSource: in.ageSource,
		LiveSource: in.liveSource, SupportSource: in.supportSource,
		Remediation: in.remediation, ScanDisabled: cfg.Scan.Disabled,
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
		// Internet exposure, when the source can measure it. Without this the scan
		// provider's own field stands, and on at least one platform that field is
		// constant false - so everything reads as internal and an urgency tier
		// keyed on exposure can never fire.
		if es, ok := src.(enrich.ExposureSource); ok {
			liveEnrichers = append(liveEnrichers, enrich.Exposure{Source: es, SourceName: src.Name()})
			sources.Exposure = true
		}
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
		// One inspector shared by both stages: the base resolver and the in-flight
		// matcher read the same image configs for different labels, so without this
		// every first-party image is fetched twice per run.
		inspector := upgrade.NewCachingInspector(upgrade.NewRegistryInspector())
		if len(cfg.Remediation.FirstPartyRegistries) > 0 {
			base := upgrade.NewBaseResolver(cfg.Remediation, inspector, upgrade.NewTagLister())
			// Compile the upgrade rules' scopes now: a rule that cannot compile should
			// stop the process here, not produce an assessment that quietly recommends
			// the version somebody's ceiling exists to prevent.
			if err := base.Validate(); err != nil {
				return nil, err
			}
			// Support windows, when a source is configured. Without one, an image on a
			// dead runtime is indistinguishable from one that is simply up to date.
			if in.supportSource != "" {
				src, err := newSupportSource(in.supportSource, in.supportOptions)
				if err != nil {
					return nil, err
				}
				base.Support = src
			}
			upgradeSources = append(upgradeSources, base)

			// Base scanning, which turns "a newer base exists" into "this clears
			// 3,664 of your 4,890". Only meaningful alongside base resolution: it
			// needs the base references that produces.
			if cfg.Remediation.BaseDiff.On() {
				sources.BaseDiff = true
				bd := cfg.Remediation.BaseDiff
				popts = append(popts, pipeline.WithBaseDiffEnricher(&enrich.BaseDiffEnricher{
					Resolver: &basescan.Resolver{
						Scanner:     &basescan.TrivyScanner{Binary: bd.Binary, Timeout: bd.Timeout},
						Concurrency: bd.EffectiveConcurrency(),
						// Bounded, because the server holds this resolver for the life of
						// the process and an unexpiring base scan misattributes new CVEs
						// to the application. See basescan.Resolver.MaxAge.
						MaxAge: bd.EffectiveMaxAge(),
					},
				}))
			}
		}
		reg := registry.New()
		reg.Contexts = deployContexts
		reg.SkipRegistries = cfg.Remediation.FirstPartyRegistries
		upgradeSources = append(upgradeSources, reg)
		r := enrich.NewRemediationEnricher(upgradeSources...)
		popts = append(popts, pipeline.WithRemediationEnricher(&r))

		// How long since each first-party image was built. Reads the same cached
		// image config the base resolver just read, so it adds no registry calls.
		popts = append(popts, pipeline.WithImageAgeEnricher(&upgrade.ImageAgeEnricher{
			Cfg: cfg.Remediation, Inspector: inspector,
		}))

		// Remediation already under way, so an upgrade with an open pull request
		// can be told apart from one nobody has started.
		if cfg.Remediation.InFlight.Enabled() {
			sources.InFlight = true
			src, err := newPullRequestSource(cfg.Remediation.InFlight)
			if err != nil {
				return nil, err
			}
			popts = append(popts, pipeline.WithInFlightEnricher(&upgrade.InFlightEnricher{
				Cfg: cfg.Remediation, Source: src, Inspector: inspector,
			}))
		}
	}

	if in.vulnSource != "" && cfg.Scan.Disabled {
		slog.Warn("image scanning disabled by config (scan.disabled); vulnerability data will be absent",
			"vuln_source", in.vulnSource)
	}
	if in.vulnSource != "" && !cfg.Scan.Disabled {
		scanner, err := buildScanner(in.vulnSource, in.provider.inherited(in.vulnSource, in.vulnOptions),
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
		enricher, err := buildAgeEnricher(in.ageSource, in.provider.inherited(in.ageSource, in.ageOptions))
		if err != nil {
			return nil, err
		}
		popts = append(popts, pipeline.WithAgeEnricher(enricher))
	}
	if in.exploitSource != "" {
		if in.vulnSource == "" {
			return nil, fmt.Errorf("--exploit-source requires --vuln-source: there are no vulnerabilities to annotate with EPSS/KEV otherwise")
		}
		enricher, err := buildExploitEnricher(in.exploitSource, in.provider.inherited(in.exploitSource, in.exploitOptions))
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
		sources:       sources,
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

// Failures reports the enrichments that could not run in the last assessment, so the
// server can state the gap rather than serving a queue whose missing signals look like
// absent findings.
func (a *assessor) Failures() []model.SourceFailure { return a.pipeline.Failures() }

// Sources reports what this assessment was configured to do. See model.Sources for
// why "not configured" has to be distinguishable from "found nothing".
func (a *assessor) Sources() model.Sources { return a.sources }

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

// newSupportSource constructs the named support-window source.
//
// An unknown name is an error rather than a silent no-op: somebody who asked for support
// checking and got none would read every end-of-life base as maintained, which is the
// exact misreading this feature exists to remove.
func newSupportSource(name string, options []string) (support.Source, error) {
	opts := map[string]string{}
	for _, kv := range options {
		k, v, ok := splitKV(kv)
		if !ok {
			return nil, fmt.Errorf("invalid --support-option %q, want key=value", kv)
		}
		opts[k] = v
	}
	switch strings.ToLower(name) {
	case "endoflife", "endoflife.date":
		return support.NewEndOfLife(opts["base-url"], nil), nil
	default:
		return nil, fmt.Errorf("unknown --support-source %q (supported: endoflife)", name)
	}
}
