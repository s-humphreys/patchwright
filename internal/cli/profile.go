package cli

import (
	"fmt"
	"log/slog"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/s-humphreys/patchwright/pkg/model"
)

func newProfileCmd() *cobra.Command {
	var pf providerFlags
	var dims []string
	var topN int

	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Summarize the raw scan data: volume, dedupe headroom, and dimension breakdowns",
		Long: "profile ingests scan data from a provider and prints how much of it is noise —\n" +
			"how many raw occurrences collapse to unique images, how many carry criticals, and\n" +
			"how the data breaks down across dimensions such as account, namespace or resource_type.\n" +
			"It is a read-only sanity check to run before writing ownership and policy rules.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := pf.build()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			occ, err := p.Fetch(ctx)
			if err != nil {
				return err
			}
			slog.InfoContext(ctx, "profiling scan data", "provider", pf.name, "occurrences", len(occ))
			printProfile(cmd, occ, dims, topN)
			return nil
		},
	}
	pf.bind(cmd)
	cmd.Flags().StringSliceVar(&dims, "by", []string{"resource_type", "account", "namespace"},
		"dimensions to break occurrences down by")
	cmd.Flags().IntVar(&topN, "top", 15, "max rows to show per dimension breakdown")
	return cmd
}

func printProfile(cmd *cobra.Command, occ []model.Occurrence, dims []string, topN int) {
	out := cmd.OutOrStdout()

	uniqImages := map[string]struct{}{}
	uniqRepos := map[string]struct{}{}
	imagesWithCritical := map[string]struct{}{}
	occWithCritical := 0
	total := model.Counts{}

	for _, o := range occ {
		uniqImages[o.Image.Key()] = struct{}{}
		uniqRepos[o.Image.Registry+"/"+o.Image.Repository] = struct{}{}
		crit := o.Counts.Get(model.SeverityCritical)
		if crit > 0 {
			occWithCritical++
			imagesWithCritical[o.Image.Key()] = struct{}{}
		}
		for sev, n := range o.Counts {
			total[sev] += n
		}
	}

	fmt.Fprintln(out, "== Volume ==")
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "occurrences (raw rows)\t%d\n", len(occ))
	fmt.Fprintf(tw, "unique images\t%d\n", len(uniqImages))
	fmt.Fprintf(tw, "unique repositories\t%d\n", len(uniqRepos))
	if len(occ) > 0 && len(uniqImages) > 0 {
		fmt.Fprintf(tw, "dedupe factor (rows / unique images)\t%.1fx\n", float64(len(occ))/float64(len(uniqImages)))
	}
	fmt.Fprintf(tw, "occurrences with a critical\t%d\n", occWithCritical)
	fmt.Fprintf(tw, "unique images with a critical\t%d\n", len(imagesWithCritical))
	tw.Flush()

	fmt.Fprintln(out, "\n== Vulnerabilities (aggregate) ==")
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, sev := range []string{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		fmt.Fprintf(tw, "%s\t%d\n", sev, total[sev])
	}
	tw.Flush()

	for _, dim := range dims {
		printDimensionBreakdown(out, occ, dim, topN)
	}
}

func printDimensionBreakdown(out interface{ Write([]byte) (int, error) }, occ []model.Occurrence, dim string, topN int) {
	type stat struct {
		value    string
		count    int
		critical int
	}
	byValue := map[string]*stat{}
	for _, o := range occ {
		v := o.Resource.Dimensions[dim]
		if v == "" {
			v = "(none)"
		}
		s := byValue[v]
		if s == nil {
			s = &stat{value: v}
			byValue[v] = s
		}
		s.count++
		s.critical += o.Counts.Get(model.SeverityCritical)
	}

	stats := make([]*stat, 0, len(byValue))
	for _, s := range byValue {
		stats = append(stats, s)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].count != stats[j].count {
			return stats[i].count > stats[j].count
		}
		return stats[i].value < stats[j].value
	})

	fmt.Fprintf(out, "\n== By %s (%d distinct) ==\n", dim, len(stats))
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\tOCCURRENCES\tCRITICALS\n", dim)
	for i, s := range stats {
		if i >= topN {
			fmt.Fprintf(tw, "... (%d more)\t\t\n", len(stats)-topN)
			break
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\n", s.value, s.count, s.critical)
	}
	tw.Flush()
}
