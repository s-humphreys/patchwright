package cli

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/enrich/registry"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/pipeline"
	"github.com/s-humphreys/patchwright/pkg/provider"
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
		reg := registry.New()
		reg.Contexts = deployContexts
		upgradeSources = append(upgradeSources, reg)
		r := enrich.NewRemediationEnricher(upgradeSources...)
		popts = append(popts, pipeline.WithRemediationEnricher(&r))
	}

	if in.vulnSource != "" {
		scanner, err := buildScanner(in.vulnSource, in.vulnOptions,
			cfg.Scan.EffectiveSkipOwnerClasses(), cfg.Scan.SkipRegistries)
		if err != nil {
			return nil, err
		}
		popts = append(popts, pipeline.WithImageScanner(scanner))
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
	}, nil
}

// run executes the assessment: fetch, reconcile, and evaluate. It returns the
// full finding set (no display filtering).
func (a *assessor) Run(ctx context.Context) ([]model.Finding, error) {
	slog.InfoContext(ctx, "starting assessment",
		"provider", a.providerName, "vuln_source", a.vulnSource, "exploit_source", a.exploitSource, "live_source", a.liveSource)

	occ, err := a.provider.Fetch(ctx)
	if err != nil {
		return nil, err
	}
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
	return findings, nil
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
	slog.WarnContext(ctx, "provider never assessed some images — their zero counts are absence of data, not a clean result",
		"unassessed_images", len(unassessed), "total_images", len(total))
}
