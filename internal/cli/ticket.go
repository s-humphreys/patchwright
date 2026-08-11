package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

func newTicketCmd() *cobra.Command {
	var (
		input       string
		configPaths []string
		confirm     bool
	)

	cmd := &cobra.Command{
		Use:   "ticket",
		Short: "Raise tickets for actionable findings from a saved assessment",
		Long: "ticket reads the JSON an assess run produced (--output json:full=findings.json) and\n" +
			"drafts one ticket per remediation, from a template you supply.\n\n" +
			"It reads saved findings rather than re-running the assessment on purpose: a full run\n" +
			"reconciles every cluster and rescans every image, and ticket creation should act on\n" +
			"output you have already reviewed.\n\n" +
			"Dry run by default: it prints what it would raise and changes nothing. Pass --confirm\n" +
			"to actually create the tickets.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			cfg, err := loadTicketConfig(configPaths)
			if err != nil {
				return err
			}
			findings, err := readFindings(input)
			if err != nil {
				return err
			}
			planner, err := ticket.NewPlanner(cfg.Jira)
			if err != nil {
				return err
			}
			plan, err := planner.Plan(findings)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			// Report skips before drafts. They are the findings a human still has
			// to deal with, and burying them under the tickets is how they get
			// forgotten.
			reportSkips(out, plan.Skips)

			if len(plan.Drafts) == 0 {
				fmt.Fprintln(out, "Nothing to raise.")
				return nil
			}

			if !confirm {
				return dryRun(ctx, out, cfg.Jira, plan)
			}
			return create(ctx, out, cfg.Jira, plan)
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "",
		"path to findings JSON from `assess --output json:full=...` ('-' for stdin)")
	cmd.Flags().StringArrayVarP(&configPaths, "config", "c", nil, "config YAML file or directory (repeatable)")
	cmd.Flags().BoolVar(&confirm, "confirm", false,
		"actually create the tickets. Without this, ticket only prints what it would do")
	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(err) // programmer error: the flag is defined immediately above
	}
	return cmd
}

func loadTicketConfig(paths []string) (*config.Config, error) {
	expanded, err := expandConfigPaths(paths)
	if err != nil {
		return nil, err
	}
	if len(expanded) == 0 {
		return nil, fmt.Errorf("no config provided: pass --config with one or more YAML files or directories")
	}
	cfg, err := config.Load(expanded...)
	if err != nil {
		return nil, err
	}
	if err := cfg.Jira.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// readFindings parses the JSON an assess run produced. The full view
// (--all --show-suppressed) is fine: planning filters to actionable itself.
func readFindings(path string) ([]sink.FindingView, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open findings %s: %w", path, err)
		}
		defer f.Close() //nolint:errcheck // read-only
		r = f
	}
	var findings []sink.FindingView
	if err := json.NewDecoder(r).Decode(&findings); err != nil {
		return nil, fmt.Errorf("parse findings %s (expected the array from `assess --format json`): %w", path, err)
	}
	slog.Debug("read findings", "path", path, "count", len(findings))
	return findings, nil
}

// describePriority shows the assessment priority and the Jira priority it maps to,
// so a flattened queue (every ticket at one priority) is visible before creation
// rather than after.
func describePriority(cfg config.JiraConfig, findingPriority string) string {
	assessed := findingPriority
	if assessed == "" {
		assessed = "-"
	}
	mapped := cfg.JiraPriority(findingPriority)
	if mapped == "" {
		return assessed + " -> (Jira default)"
	}
	return assessed + " -> " + mapped
}

func reportSkips(w io.Writer, skips []ticket.Skip) {
	if len(skips) == 0 {
		return
	}
	fmt.Fprintf(w, "SKIPPED (%d actionable findings, no ticket raised)\n", len(skips))
	for _, s := range skips {
		fmt.Fprintf(w, "  %s\n      %s\n", s.Image, s.Reason)
	}
	fmt.Fprintln(w)
}

// dryRun prints the tickets that would be raised. It still queries Jira for
// existing tickets when credentials are available, because "would this actually
// create anything?" is the question a dry run needs to answer; without
// credentials it says so rather than implying the answer is no.
func dryRun(ctx context.Context, w io.Writer, cfg config.JiraConfig, plan *ticket.Plan) error {
	jira, jiraErr := ticket.NewJira(cfg)
	var index map[string][]ticket.Existing
	if jiraErr == nil {
		var err error
		if index, err = jira.OpenByImage(ctx); err != nil {
			return err
		}
	}
	if jiraErr != nil {
		fmt.Fprintf(w, "NOTE: %v\n", jiraErr)
		fmt.Fprintf(w, "      Duplicate detection is part of that check, so the drafts below may\n")
		fmt.Fprintf(w, "      already exist in Jira. Set the credentials to find out.\n\n")
	}

	fmt.Fprintf(w, "DRY RUN: %d ticket(s) would be raised in project %s", len(plan.Drafts), cfg.Project)
	if cfg.Epic != "" {
		fmt.Fprintf(w, " under %s", cfg.Epic)
	}
	fmt.Fprintf(w, " as %q.\n\n", cfg.EffectiveIssueType())

	for i, d := range plan.Drafts {
		fmt.Fprintf(w, "--- ticket %d of %d ---\n", i+1, len(plan.Drafts))
		fmt.Fprintf(w, "Summary:  %s\n", d.Summary)
		fmt.Fprintf(w, "Priority: %s\n", describePriority(cfg, d.Priority))
		fmt.Fprintf(w, "Images:   %v\n", d.Images)
		fmt.Fprintf(w, "Covers:   %d finding(s), grouped by %s\n", len(d.Findings), d.Key)

		if jiraErr == nil {
			c := coverageFor(index, d)
			if c.skipped() {
				fmt.Fprintf(w, "Existing: WOULD SKIP — ")
				reportCoverage(w, c)
			} else {
				fmt.Fprintln(w, "Existing: none — would create")
			}
		}
		fmt.Fprintf(w, "\n%s\n\n", d.Description)
	}
	fmt.Fprintln(w, "Nothing was created. Re-run with --confirm to raise these.")
	return nil
}

func create(ctx context.Context, w io.Writer, cfg config.JiraConfig, plan *ticket.Plan) error {
	jira, err := ticket.NewJira(cfg)
	if err != nil {
		return err
	}

	index, err := jira.OpenByImage(ctx)
	if err != nil {
		return err
	}

	created, skipped, uncovered := 0, 0, 0
	for _, d := range plan.Drafts {
		c := coverageFor(index, d)
		if c.skipped() {
			fmt.Fprintf(w, "skip   %s\n       ", d.Summary)
			reportCoverage(w, c)
			skipped++
			uncovered += len(c.uncovered)
			continue
		}
		key, err := jira.Create(ctx, d)
		if err != nil {
			// Stop rather than continue: a failure here is usually systematic
			// (a wrong custom field, a required field on the create screen), and
			// carrying on would produce a long list of identical failures.
			return fmt.Errorf("after creating %d ticket(s): %w", created, err)
		}
		fmt.Fprintf(w, "create %s  %s\n", key, d.Summary)
		created++
	}
	slog.InfoContext(ctx, "ticket run complete",
		"created", created, "skipped_existing", skipped, "images_left_uncovered", uncovered)
	fmt.Fprintf(w, "\nCreated %d, skipped %d already open.\n", created, skipped)
	if uncovered > 0 {
		fmt.Fprintf(w, "%d image(s) in skipped groups have no ticket of their own; see above.\n", uncovered)
	}
	return nil
}

// coverage is what open tickets say about one draft: which of its images are
// already handled, and which are not.
//
// The distinction matters. An open ticket on any image suppresses the whole draft,
// which is right (they are one change), but it can leave most of the group
// unticketed: a ticket covering one of three nats images stopped the other two
// being raised at all. Reporting only "skipped, PROJ-11 is open" hides that.
type coverage struct {
	tickets   []ticket.Existing
	covered   []string
	uncovered []string
}

func (c coverage) skipped() bool { return len(c.tickets) > 0 }

// coverageFor resolves a draft against the whole project's open tickets. The index
// is fetched once per run, so this costs nothing per draft.
func coverageFor(index map[string][]ticket.Existing, d ticket.Draft) coverage {
	var out coverage
	seen := map[string]bool{}
	for _, img := range d.Images {
		found := index[img]
		if len(found) == 0 {
			out.uncovered = append(out.uncovered, img)
			continue
		}
		out.covered = append(out.covered, img)
		for _, e := range found {
			if !seen[e.Key] {
				seen[e.Key] = true
				out.tickets = append(out.tickets, e)
			}
		}
	}
	return out
}

// reportCoverage prints the tickets that caused a skip and, crucially, the images
// they do not cover. Only meaningful for a skip: uncovered images in a draft that
// is about to be created are simply the draft's own work, not a gap.
func reportCoverage(w io.Writer, c coverage) {
	if !c.skipped() {
		return
	}
	fmt.Fprintf(w, "%s covers %s\n", formatExisting(c.tickets), strings.Join(c.covered, ", "))
	if len(c.uncovered) > 0 {
		fmt.Fprintf(w, "       NOT covered by any open ticket: %s\n", strings.Join(c.uncovered, ", "))
		fmt.Fprintf(w, "       These get no ticket while the above is open. Close it, or add them to it.\n")
	}
}

func formatExisting(existing []ticket.Existing) string {
	out := ""
	for i, e := range existing {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s (%s)", e.Key, e.Status)
	}
	return out
}
