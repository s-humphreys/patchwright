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

			return run(ctx, out, cfg.Jira, plan, findings, confirm)
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
		return assessed + " → (Jira default)"
	}
	return assessed + " → " + mapped
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

// run reconciles the plan against Jira and either reports or applies the result.
//
// One code path for both, so a dry run cannot describe something different from
// what a confirmed run does.
func run(ctx context.Context, w io.Writer, cfg config.JiraConfig, plan *ticket.Plan,
	findings []sink.FindingView, confirm bool) error {
	jira, err := ticket.NewJira(cfg)
	if err != nil {
		if confirm {
			return err
		}
		fmt.Fprintf(w, "NOTE: %v\n", err)
		fmt.Fprintf(w, "      Without them this cannot tell which tickets already exist, so the\n")
		fmt.Fprintf(w, "      drafts below may already be raised. Set the credentials to find out.\n\n")
		reportDrafts(w, cfg, plan.Drafts)
		return nil
	}

	index, err := jira.OpenByImage(ctx)
	if err != nil {
		return err
	}
	actions := ticket.Reconcile(ticket.ReconcileInput{
		Drafts: plan.Drafts, OpenByImage: index, Findings: findings,
		Config: cfg,
	})

	if !confirm {
		reportActions(w, cfg, actions)
		fmt.Fprintln(w, "\nNothing was changed. Re-run with --confirm to apply this.")
		return nil
	}
	results := ticket.Apply(ctx, jira, actions)
	reportResults(w, results)
	return nil
}

// reportActions describes what reconciliation would do, in full, so the decision to
// apply is made on the actual content rather than a count.
func reportActions(w io.Writer, cfg config.JiraConfig, actions []ticket.Action) {
	if len(actions) == 0 {
		fmt.Fprintln(w, "Nothing to do: no drafts and no open tickets to reconcile.")
		return
	}
	fmt.Fprintf(w, "DRY RUN: %d action(s) across %s.\n\n", len(actions), describeTrackers(cfg))
	for i, a := range actions {
		fmt.Fprintf(w, "--- %d of %d: %s ---\n", i+1, len(actions), a.Kind)
		fmt.Fprintf(w, "Why:      %s\n", a.Why)
		// Every action names its tracker, not just creations: reviewing forty
		// actions across two boards means knowing which team each one touches.
		// For an action against an existing ticket the project comes from the
		// issue key, which is where the write will actually land.
		fmt.Fprintf(w, "Tracker:  %s\n", describeActionTracker(cfg, a))
		switch a.Kind {
		case ticket.ActionCreate:
			fmt.Fprintf(w, "Summary:  %s\n", a.Draft.Summary)
			fmt.Fprintf(w, "Priority: %s\n", describePriority(routedConfig(cfg, a.Draft.Route), a.Draft.Priority))
			fmt.Fprintf(w, "Images:   %v\n\n%s\n", a.Draft.Images, a.Draft.Description)
		case ticket.ActionSkip:
			fmt.Fprintf(w, "Ticket:   %s\n", a.TicketKey)
		case ticket.ActionClose:
			// Closing is the only action that ends a piece of work, so the dry run
			// shows the evidence rather than just the verdict.
			fmt.Fprintf(w, "Ticket:   %s\n", a.TicketKey)
			fmt.Fprintf(w, "Closing:  %s\n", a.Message)
		case ticket.ActionUpdate:
			// The rewrite is shown in full: it replaces what someone would
			// otherwise read on the board, so approving it blind is worse than
			// approving a comment blind.
			fmt.Fprintf(w, "Ticket:   %s\n", a.TicketKey)
			fmt.Fprintf(w, "New summary: %s\n", a.Draft.Summary)
			fmt.Fprintf(w, "New description:\n\n%s\n", a.Draft.Description)
		default:
			fmt.Fprintf(w, "Ticket:   %s\n", a.TicketKey)
			if len(a.Images) > 0 {
				fmt.Fprintf(w, "Add:      %v\n", a.Images)
			}
			fmt.Fprintf(w, "Comment:  %s\n", a.Message)
		}
		fmt.Fprintln(w)
	}
}

// reportDrafts is the credential-less fallback: what would be raised, with no claim
// about what already exists.
func reportDrafts(w io.Writer, cfg config.JiraConfig, drafts []ticket.Draft) {
	fmt.Fprintf(w, "DRY RUN: %d ticket(s) would be considered across %s.\n\n",
		len(drafts), describeTrackers(cfg))
	for i, d := range drafts {
		fmt.Fprintf(w, "--- draft %d of %d ---\n", i+1, len(drafts))
		fmt.Fprintf(w, "Summary:  %s\n", d.Summary)
		fmt.Fprintf(w, "Tracker:  %s\n", describeRoute(cfg, d.Route))
		fmt.Fprintf(w, "Priority: %s\n", describePriority(routedConfig(cfg, d.Route), d.Priority))
		fmt.Fprintf(w, "Images:   %v\n\n%s\n\n", d.Images, d.Description)
	}
}

// routedConfig resolves the settings a draft will actually be created with, so
// what a dry run prints is what the write will use.
func routedConfig(cfg config.JiraConfig, route string) config.JiraConfig {
	for _, r := range cfg.Routes {
		if r.Name == route {
			return cfg.Resolve(r)
		}
	}
	return cfg
}

// describeActionTracker names where an action will land.
//
// A creation goes wherever its route says. An action against an existing ticket
// goes to that ticket's project, which the issue key already states — reading the
// route for those would describe where a new ticket would go, not where this write
// is going, and the two can differ once routes change.
func describeActionTracker(cfg config.JiraConfig, a ticket.Action) string {
	if a.Kind == ticket.ActionCreate {
		return describeRoute(cfg, a.Draft.Route)
	}
	project, _, ok := strings.Cut(a.TicketKey, "-")
	if !ok || project == "" {
		return "unknown"
	}
	for _, p := range cfg.Projects() {
		if p == project {
			return project
		}
	}
	// Worth saying out loud rather than printing the key and moving on: a ticket
	// in a project this configuration does not write to usually means a route was
	// removed or renamed while its tickets are still open.
	return project + " (not a configured project)"
}

// describeRoute names the tracker a draft lands on, and the rule that chose it.
func describeRoute(cfg config.JiraConfig, route string) string {
	resolved := routedConfig(cfg, route)
	desc := fmt.Sprintf("%s / %s", resolved.Project, resolved.EffectiveIssueType())
	if route != "" && route != "(default)" {
		return fmt.Sprintf("%s (route %q)", desc, route)
	}
	return desc
}

// describeTrackers lists every project this run can write to, so "1 project" is
// never assumed when routing means otherwise.
func describeTrackers(cfg config.JiraConfig) string {
	projects := cfg.Projects()
	if len(projects) == 1 {
		return "project " + projects[0]
	}
	return fmt.Sprintf("%d projects (%s)", len(projects), strings.Join(projects, ", "))
}

func reportResults(w io.Writer, results []ticket.Result) {
	var failed int
	for _, r := range results {
		switch {
		case r.Err != nil:
			failed++
			fmt.Fprintf(w, "FAILED %-11s %s: %v\n", r.Action.Kind, r.Key, r.Err)
		case r.Action.Kind == ticket.ActionCreate:
			fmt.Fprintf(w, "create %-11s %s\n", r.Key, r.Action.Draft.Summary)
		case r.Action.Kind == ticket.ActionSkip:
			fmt.Fprintf(w, "ok     %-11s already covers this change\n", r.Key)
		default:
			fmt.Fprintf(w, "%-6s %-11s %s\n", r.Action.Kind, r.Key, r.Action.Why)
		}
	}
	counts := ticket.Summarize(results)
	parts := make([]string, 0, len(ticket.ActionKinds()))
	// Built by iteration for the same reason the server's is: a hand-written list
	// silently omits a kind added later, and the run then reads as though it did
	// less than it did.
	for _, kind := range ticket.ActionKinds() {
		parts = append(parts, fmt.Sprintf("%s %d", kind, counts[kind]))
	}
	fmt.Fprintf(w, "\n%s.\n", strings.Join(parts, ", "))
	if failed > 0 {
		fmt.Fprintf(w, "%d action(s) failed; see above.\n", failed)
	}
}
