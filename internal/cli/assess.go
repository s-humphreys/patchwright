package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/enrich/registry"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/pipeline"
	"github.com/s-humphreys/patchwright/pkg/sink"

	// Register the built-in live, vuln, and exploit sources.
	_ "github.com/s-humphreys/patchwright/pkg/enrich/file"
	_ "github.com/s-humphreys/patchwright/pkg/enrich/intel"
	_ "github.com/s-humphreys/patchwright/pkg/enrich/kube"
	_ "github.com/s-humphreys/patchwright/pkg/enrich/trivy"
)

func newAssessCmd() *cobra.Command {
	var (
		pf             providerFlags
		configPaths    []string
		format         string
		ownerClass     string
		includeAll     bool
		showSuppressed bool
		liveSource     string
		liveOptions    []string
		vulnSource     string
		vulnOptions    []string
		exploitSource  string
		exploitOptions []string
		remediation    bool
	)

	cmd := &cobra.Command{
		Use:   "assess",
		Short: "Assess scan data into a deduplicated, owner-attributed, actionable report",
		Long: "assess ingests scan data from a provider, deduplicates it by image, attributes each\n" +
			"workload to an owner, and applies policy rules to decide what is actionable. By default\n" +
			"it prints only actionable findings; use --all to see everything.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths, err := expandConfigPaths(configPaths)
			if err != nil {
				return err
			}
			if len(paths) == 0 {
				return fmt.Errorf("no config provided: pass --config with one or more YAML files or directories")
			}
			cfg, err := config.Load(paths...)
			if err != nil {
				return err
			}

			var popts []pipeline.Option

			// Live source: drives reconciliation (pre-dedupe) and, with
			// --remediation, contributes a deployment-aware upgrade source.
			var liveEnrichers []enrich.Enricher
			var upgradeSources []enrich.UpgradeSource
			if liveSource != "" {
				src, err := newLiveSource(liveSource, liveOptions)
				if err != nil {
					return err
				}
				liveEnrichers = append(liveEnrichers, enrich.NewLiveness(src))
				if ls, ok := src.(enrich.LabelSource); ok {
					liveEnrichers = append(liveEnrichers, enrich.NewNamespaceLabeler(ls))
				}
				// A deployment-aware source (e.g. kube: Flux HelmReleases) takes
				// precedence over the registry image-tag fallback.
				if us, ok := src.(enrich.UpgradeSource); ok && remediation {
					upgradeSources = append(upgradeSources, us)
				}
			}
			if remediation {
				upgradeSources = append(upgradeSources, registry.New())
				r := enrich.NewRemediationEnricher(upgradeSources...)
				popts = append(popts, pipeline.WithRemediationEnricher(&r))
			}

			if vulnSource != "" {
				scanner, err := buildScanner(vulnSource, vulnOptions, cfg.Scan.EffectiveSkipOwnerClasses())
				if err != nil {
					return err
				}
				popts = append(popts, pipeline.WithImageScanner(scanner))
			}
			if exploitSource != "" {
				if vulnSource == "" {
					return fmt.Errorf("--exploit-source requires --vuln-source: there are no vulnerabilities to annotate with EPSS/KEV otherwise")
				}
				enricher, err := buildExploitEnricher(exploitSource, exploitOptions)
				if err != nil {
					return err
				}
				popts = append(popts, pipeline.WithExploitEnricher(enricher))
			}
			pl, err := pipeline.New(cfg, popts...)
			if err != nil {
				return err
			}

			p, err := pf.build()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			slog.InfoContext(ctx, "starting assessment",
				"provider", pf.name, "vuln_source", vulnSource, "exploit_source", exploitSource, "live_source", liveSource)

			occ, err := p.Fetch(ctx)
			if err != nil {
				return err
			}
			slog.InfoContext(ctx, "fetched scan data", "provider", pf.name, "occurrences", len(occ))

			if len(liveEnrichers) > 0 {
				slog.InfoContext(ctx, "reconciling against live clusters", "source", liveSource, "enrichers", len(liveEnrichers))
				for _, e := range liveEnrichers {
					if err := e.Enrich(ctx, occ); err != nil {
						return err
					}
				}
			}

			findings, err := pl.Run(ctx, occ)
			if err != nil {
				return err
			}

			findings = filterFindings(findings, ownerClass, includeAll, showSuppressed)
			slog.InfoContext(ctx, "assessment complete", "shown", len(findings), "format", format)

			s, err := selectSink(format, showSuppressed)
			if err != nil {
				return err
			}
			return s.Emit(cmd.OutOrStdout(), findings)
		},
	}
	pf.bind(cmd)
	cmd.Flags().StringArrayVarP(&configPaths, "config", "c", nil, "config YAML file or directory (repeatable)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table or json")
	cmd.Flags().StringVar(&ownerClass, "owner", "", "only show findings for this owner class (e.g. platform, engineering)")
	cmd.Flags().BoolVar(&includeAll, "all", false, "include non-actionable findings")
	cmd.Flags().BoolVar(&showSuppressed, "show-suppressed", false, "include suppressed findings")
	cmd.Flags().StringVar(&liveSource, "live-source", "", "reconcile against live clusters using a source ("+joinLiveSources()+")")
	cmd.Flags().StringArrayVar(&liveOptions, "live-option", nil, "live source option as key=value (repeatable), e.g. path=live.txt or contexts=c1,c2")
	cmd.Flags().StringVar(&vulnSource, "vuln-source", "", "scan images for per-CVE fix availability ("+joinVulnSources()+")")
	cmd.Flags().StringArrayVar(&vulnOptions, "vuln-option", nil, "vuln source option as key=value (repeatable), e.g. severity=CRITICAL,HIGH")
	cmd.Flags().StringVar(&exploitSource, "exploit-source", "", "enrich CVEs with exploit intel — EPSS + CISA KEV ("+joinExploitSources()+"); requires --vuln-source")
	cmd.Flags().StringArrayVar(&exploitOptions, "exploit-option", nil, "exploit source option as key=value (repeatable)")
	cmd.Flags().BoolVar(&remediation, "remediation", false, "detect available upgrades for how images are deployed: a newer Helm chart (Flux, with --live-source kube) or a newer image tag (registry)")
	return cmd
}

// buildExploitEnricher constructs the exploit enricher for the named source.
func buildExploitEnricher(name string, options []string) (*enrich.ExploitEnricher, error) {
	opts := enrich.Options{}
	for _, kv := range options {
		k, v, ok := splitKV(kv)
		if !ok {
			return nil, fmt.Errorf("invalid --exploit-option %q, want key=value", kv)
		}
		opts[k] = v
	}
	src, err := enrich.NewExploitSource(name, opts)
	if err != nil {
		return nil, err
	}
	enricher := enrich.NewExploitEnricher(src)
	return &enricher, nil
}

func joinExploitSources() string {
	names := enrich.ExploitSourceNames()
	if len(names) == 0 {
		return "none registered"
	}
	return strings.Join(names, ", ")
}

// buildScanner constructs the image scanner for the named vuln source. Images
// owned entirely by one of skipClasses are not scanned (config-driven; defaults
// to cloud-provider).
func buildScanner(name string, options []string, skipClasses []string) (*enrich.ImageScanner, error) {
	opts := enrich.Options{}
	for _, kv := range options {
		k, v, ok := splitKV(kv)
		if !ok {
			return nil, fmt.Errorf("invalid --vuln-option %q, want key=value", kv)
		}
		opts[k] = v
	}
	src, err := enrich.NewVulnSource(name, opts)
	if err != nil {
		return nil, err
	}
	scanner := enrich.NewImageScanner(src)
	if len(skipClasses) > 0 {
		scanner.Skip = skipByOwnerClass(skipClasses)
	}
	return &scanner, nil
}

// skipByOwnerClass returns a predicate that skips an image only when every one
// of its workloads is owned by a class in skip.
func skipByOwnerClass(skip []string) func(model.AssessedImage) bool {
	set := make(map[string]bool, len(skip))
	for _, c := range skip {
		set[c] = true
	}
	return func(img model.AssessedImage) bool {
		if len(img.Occurrences) == 0 {
			return false
		}
		for _, o := range img.Occurrences {
			if !set[o.Owner.Class] {
				return false
			}
		}
		return true
	}
}

func joinVulnSources() string {
	names := enrich.VulnSourceNames()
	if len(names) == 0 {
		return "none registered"
	}
	return strings.Join(names, ", ")
}

// newLiveSource constructs the named live source from --live-option key=values.
func newLiveSource(name string, options []string) (enrich.LiveSource, error) {
	opts := enrich.Options{}
	for _, kv := range options {
		k, v, ok := splitKV(kv)
		if !ok {
			return nil, fmt.Errorf("invalid --live-option %q, want key=value", kv)
		}
		opts[k] = v
	}
	return enrich.NewLiveSource(name, opts)
}

func joinLiveSources() string {
	names := enrich.LiveSourceNames()
	if len(names) == 0 {
		return "none registered"
	}
	out := names[0]
	for _, n := range names[1:] {
		out += ", " + n
	}
	return out
}

// filterFindings applies the display filters. Suppressed findings are excluded
// unless showSuppressed; non-actionable findings are excluded unless includeAll.
func filterFindings(findings []model.Finding, ownerClass string, includeAll, showSuppressed bool) []model.Finding {
	out := findings[:0:0]
	for _, f := range findings {
		if ownerClass != "" && f.Owner.Class != ownerClass {
			continue
		}
		if f.Suppressed && !showSuppressed {
			continue
		}
		if !f.Actionable && !f.Suppressed && !includeAll {
			continue
		}
		out = append(out, f)
	}
	return out
}

func selectSink(format string, showSuppressed bool) (sink.Sink, error) {
	switch format {
	case "table", "":
		return sink.Table{ShowSuppressed: showSuppressed}, nil
	case "json":
		return sink.JSON{ShowSuppressed: showSuppressed, Indent: true}, nil
	default:
		return nil, fmt.Errorf("unknown format %q (want table or json)", format)
	}
}

// expandConfigPaths resolves each path: directories contribute their *.yaml and
// *.yml files (sorted); files are taken as-is.
func expandConfigPaths(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("config path %s: %w", p, err)
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		var inDir []string
		for _, pattern := range []string{"*.yaml", "*.yml"} {
			matches, err := filepath.Glob(filepath.Join(p, pattern))
			if err != nil {
				return nil, err
			}
			inDir = append(inDir, matches...)
		}
		sort.Strings(inDir)
		out = append(out, inDir...)
	}
	return out, nil
}
