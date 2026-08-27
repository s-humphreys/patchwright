package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
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
		outputs        []string
		ownerClass     string
		includeAll     bool
		showSuppressed bool
		liveSource     string
		liveOptions    []string
		supportSource  string
		supportOptions []string
		vulnSource     string
		vulnOptions    []string
		exploitSource  string
		exploitOptions []string
		ageSource      string
		ageOptions     []string
		remediation    bool
	)

	cmd := &cobra.Command{
		Use:   "assess",
		Short: "Assess scan data into a deduplicated, owner-attributed, actionable report",
		Long: "assess ingests scan data from a provider, deduplicates it by image, attributes each\n" +
			"workload to an owner, and applies policy rules to decide what is actionable. By default\n" +
			"it prints only actionable findings; use --all to see everything.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Parse outputs before any work so a bad spec fails immediately
			// rather than after a long scan.
			specs, err := parseOutputs(outputs)
			if err != nil {
				return err
			}
			if len(specs) > 0 && cmd.Flags().Changed("format") {
				return fmt.Errorf("--format and --output are mutually exclusive: --output already names a format per destination")
			}

			a, err := newAssessor(assessInputs{
				provider:       pf,
				configPaths:    configPaths,
				liveSource:     liveSource,
				liveOptions:    liveOptions,
				vulnSource:     vulnSource,
				vulnOptions:    vulnOptions,
				exploitSource:  exploitSource,
				exploitOptions: exploitOptions,
				ageSource:      ageSource,
				ageOptions:     ageOptions,
				remediation:    remediation,
				supportSource:  supportSource,
				supportOptions: supportOptions,
			})
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			findings, err := a.Run(ctx)
			if err != nil {
				return err
			}

			// One assessment, many destinations: --output renders the same run
			// into each, so the queue view and the full record don't cost two
			// full passes over the clusters and scanner.
			if len(specs) > 0 {
				slog.InfoContext(ctx, "assessment complete", "findings", len(findings), "outputs", len(specs))
				return emitOutputs(specs, findings, cmd.OutOrStdout(), ownerClass, includeAll, showSuppressed)
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
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json (pretty), or ndjson (one finding per line, log-friendly)")
	cmd.Flags().StringArrayVar(&outputs, "output", nil,
		"write a result to a file as format[:view]=path (repeatable, '-' for stdout); view is queue (actionable only) or full (everything, suppressed included), defaulting to --all/--show-suppressed. One run, many outputs — e.g. --output json:full=findings.json --output table:queue=actionable.txt")
	cmd.Flags().StringVar(&ownerClass, "owner", "", "only show findings for this owner class (e.g. platform, engineering)")
	cmd.Flags().BoolVar(&includeAll, "all", false, "include non-actionable findings")
	cmd.Flags().BoolVar(&showSuppressed, "show-suppressed", false, "include suppressed findings")
	cmd.Flags().StringVar(&liveSource, "live-source", "", "reconcile against live clusters using a source ("+joinLiveSources()+")")
	cmd.Flags().StringArrayVar(&liveOptions, "live-option", nil, "live source option as key=value (repeatable), e.g. path=live.txt or contexts=c1,c2")
	cmd.Flags().StringVar(&vulnSource, "vuln-source", "", "scan images for per-CVE fix availability ("+joinVulnSources()+")")
	cmd.Flags().StringArrayVar(&vulnOptions, "vuln-option", nil, "vuln source option as key=value (repeatable), e.g. severity=CRITICAL,HIGH")
	cmd.Flags().StringVar(&exploitSource, "exploit-source", "", "enrich CVEs with exploit intel — EPSS + CISA KEV ("+joinExploitSources()+"); requires --vuln-source")
	cmd.Flags().StringVar(&ageSource, "age-source", "",
		"date CVEs from the scan provider's own first-seen times ("+joinAgeSources()+"); requires --vuln-source")
	cmd.Flags().StringArrayVar(&ageOptions, "age-option", nil, "age source option as key=value (repeatable)")
	cmd.Flags().StringArrayVar(&exploitOptions, "exploit-option", nil, "exploit source option as key=value (repeatable)")
	cmd.Flags().BoolVar(&remediation, "remediation", false, "detect available upgrades for how images are deployed: a newer Helm chart (Flux, with --live-source kube) or a newer image tag (registry)")
	cmd.Flags().StringVar(&supportSource, "support-source", "", "check whether base image lines are still maintained using a source (endoflife); without it an end-of-life base is indistinguishable from an up-to-date one")
	cmd.Flags().StringArrayVar(&supportOptions, "support-option", nil, "support source option as key=value (repeatable), e.g. base-url=https://endoflife.date/api")
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
	// Comma-separated: EPSS and KEV come from the public feeds, a scanner's own
	// risk score from the scanner, and neither substitutes for the other.
	var sources []enrich.ExploitSource
	for _, n := range strings.Split(name, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		src, err := enrich.NewExploitSource(n, opts)
		if err != nil {
			return nil, err
		}
		sources = append(sources, src)
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("--exploit-source names no source")
	}
	if len(sources) == 1 {
		enricher := enrich.NewExploitEnricher(sources[0])
		return &enricher, nil
	}
	enricher := enrich.NewExploitEnricher(enrich.MultiExploitSource{Sources: sources})
	return &enricher, nil
}

// buildAgeEnricher constructs the CVE-ageing enricher for the named source.
func buildAgeEnricher(name string, options []string) (*enrich.AgeEnricher, error) {
	opts := enrich.Options{}
	for _, kv := range options {
		k, v, ok := splitKV(kv)
		if !ok {
			return nil, fmt.Errorf("invalid --age-option %q, want key=value", kv)
		}
		opts[k] = v
	}
	src, err := enrich.NewAgeSource(name, opts)
	if err != nil {
		return nil, err
	}
	enricher := enrich.NewAgeEnricher(src)
	return &enricher, nil
}

func joinAgeSources() string {
	names := enrich.AgeSourceNames()
	if len(names) == 0 {
		return "none registered"
	}
	return strings.Join(names, "|")
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
// to cloud-provider), as are images from any registry in skipRegistries.
func buildScanner(name string, options []string, skipClasses, skipRegistries []string) (*enrich.ImageScanner, error) {
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
	if skip := anySkip(skipByOwnerClass(skipClasses), skipByRegistry(skipRegistries)); skip != nil {
		scanner.Skip = skip
	}
	return &scanner, nil
}

// anySkip combines skip predicates, ignoring nil ones, and returns nil when
// none are active so the scanner keeps its default (scan everything).
func anySkip(preds ...func(model.AssessedImage) bool) func(model.AssessedImage) bool {
	active := preds[:0]
	for _, p := range preds {
		if p != nil {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return nil
	}
	return func(img model.AssessedImage) bool {
		for _, p := range active {
			if p(img) {
				return true
			}
		}
		return false
	}
}

// skipByRegistry returns a predicate that skips images from any of the named
// registry hosts, or nil when the list is empty.
func skipByRegistry(skip []string) func(model.AssessedImage) bool {
	if len(skip) == 0 {
		return nil
	}
	set := make(map[string]bool, len(skip))
	for _, r := range skip {
		set[r] = true
	}
	return func(img model.AssessedImage) bool {
		return set[img.Image.Registry]
	}
}

// skipByOwnerClass returns a predicate that skips an image only when every one
// of its workloads is owned by a class in skip, or nil when the list is empty.
func skipByOwnerClass(skip []string) func(model.AssessedImage) bool {
	if len(skip) == 0 {
		return nil
	}
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
	case "ndjson":
		// One compact JSON object per line — log/monitoring friendly for
		// deployed runs (no multi-line records).
		return sink.NDJSON{ShowSuppressed: showSuppressed}, nil
	default:
		return nil, fmt.Errorf("unknown format %q (want table, json, or ndjson)", format)
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
