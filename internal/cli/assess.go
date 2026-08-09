package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/enrich"
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
			if vulnSource != "" {
				scanner, err := buildScanner(vulnSource, vulnOptions)
				if err != nil {
					return err
				}
				popts = append(popts, pipeline.WithImageScanner(scanner))
			}
			if exploitSource != "" {
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
			ctx := context.Background()
			occ, err := p.Fetch(ctx)
			if err != nil {
				return err
			}

			if liveSource != "" {
				enrichers, err := buildEnrichers(liveSource, liveOptions)
				if err != nil {
					return err
				}
				for _, e := range enrichers {
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

// buildScanner constructs the image scanner for the named vuln source.
func buildScanner(name string, options []string) (*enrich.ImageScanner, error) {
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
	return &scanner, nil
}

func joinVulnSources() string {
	names := enrich.VulnSourceNames()
	if len(names) == 0 {
		return "none registered"
	}
	return strings.Join(names, ", ")
}

// buildEnrichers constructs the reconciliation enrichers for the named live
// source: always liveness, plus namespace-label ownership when the source can
// provide labels (the kube source can; the file source cannot).
func buildEnrichers(name string, options []string) ([]enrich.Enricher, error) {
	opts := enrich.Options{}
	for _, kv := range options {
		k, v, ok := splitKV(kv)
		if !ok {
			return nil, fmt.Errorf("invalid --live-option %q, want key=value", kv)
		}
		opts[k] = v
	}
	src, err := enrich.NewLiveSource(name, opts)
	if err != nil {
		return nil, err
	}
	enrichers := []enrich.Enricher{enrich.NewLiveness(src)}
	if ls, ok := src.(enrich.LabelSource); ok {
		enrichers = append(enrichers, enrich.NewNamespaceLabeler(ls))
	}
	return enrichers, nil
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
