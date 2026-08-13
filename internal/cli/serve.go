package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/s-humphreys/patchwright/internal/server"
	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

// serverTicketer joins planning and the Jira client into the one interface the
// server needs, so neither package has to know about the other.
type serverTicketer struct {
	*ticket.Planner
	*ticket.Jira
}

// routeSummary describes the configured routes for the startup log: name, the
// project it writes to, and its issue type where it differs.
func routeSummary(cfg config.JiraConfig) string {
	if len(cfg.Routes) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		resolved := cfg.Resolve(r)
		parts = append(parts, fmt.Sprintf("%s->%s/%s", r.Name, resolved.Project, resolved.EffectiveIssueType()))
	}
	return strings.Join(parts, " ")
}

// closeSummary reports where closing tickets is enabled, since it is per-tracker
// and off by default. "none" is worth printing: it is the difference between a
// deployment that can close tickets and one that cannot.
func closeSummary(cfg config.JiraConfig) string {
	var on []string
	if cfg.AutoClose {
		on = append(on, cfg.Project)
	}
	for _, r := range cfg.Routes {
		if resolved := cfg.Resolve(r); resolved.AutoClose && resolved.Project != cfg.Project {
			on = append(on, resolved.Project)
		}
	}
	if len(on) == 0 {
		return "none"
	}
	return strings.Join(on, ",")
}

// envAPIToken is the shared token required by the API and status page. Empty or
// unset leaves both unauthenticated.
const envAPIToken = "PATCHWRIGHT_API_TOKEN"

func newServeCmd() *cobra.Command {
	var (
		in          assessInputs
		addr        string
		interval    time.Duration
		autoTicket  bool
		metricsAuth bool
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run patchwright as a service exposing a read-only assessment API",
		Long: "serve runs the same assessment as `assess` on a schedule, caches the latest result,\n" +
			"and exposes it over a read-only HTTP/JSON API (findings, owners, summary) plus a\n" +
			"live-status page. It is the deployment mode: run it as a Deployment instead of a\n" +
			"CronJob so people and tools can query current findings.\n\n" +
			"Set " + envAPIToken + " to require a token on every request except the health probes.\n" +
			"Programmatic clients send it as `Authorization: Bearer <token>`; browsers are prompted\n" +
			"for HTTP Basic with the token as the password. Without it, the API and the page are\n" +
			"unauthenticated, which is only appropriate locally.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := newAssessor(in)
			if err != nil {
				return err
			}
			srv := server.New(a)

			// Authentication. The token comes from the environment rather than a
			// flag so it does not land in a process list or a shell history.
			token := os.Getenv(envAPIToken)
			srv = srv.WithAuth(token).WithMetricsAuth(metricsAuth)
			if token == "" {
				// Deliberately a warning on every start: an unauthenticated API
				// that serves an estate's unpatched criticals is fine on a laptop
				// and is not fine anywhere else, and silence would let that pass
				// unnoticed into a deployment.
				slog.WarnContext(cmd.Context(),
					"API and status page are UNAUTHENTICATED; set "+envAPIToken+" to require a token",
					"addr", addr)
			}

			// Attach the open-ticket index when Jira is configured and credentials
			// are present, so the API and page can show whether someone is already
			// on a finding. Both are optional: without them the server simply has
			// nothing to say about tickets, which is different from saying there
			// are none. Only search is used here, never creation.
			if cfg, err := loadTicketConfig(in.configPaths); err == nil {
				jira, jerr := ticket.NewJira(cfg.Jira)
				switch {
				case jerr != nil:
					slog.WarnContext(cmd.Context(),
						"jira configured but credentials missing; ticket links disabled", "error", jerr)
					if autoTicket {
						return fmt.Errorf("--auto-ticket needs Jira credentials: %w", jerr)
					}
				default:
					srv = srv.WithTickets(jira, jira.BaseURL)
					planner, perr := ticket.NewPlanner(cfg.Jira)
					if perr != nil {
						return perr
					}
					srv = srv.WithTicketing(&serverTicketer{Planner: planner, Jira: jira}, autoTicket)
					// Every tracker, not just the default: with routes configured, naming
					// one project understates what this deployment can write to, and
					// startup is where an operator checks that.
					slog.InfoContext(cmd.Context(), "ticketing enabled",
						"projects", strings.Join(cfg.Jira.Projects(), ","),
						"default_project", cfg.Jira.Project,
						"issue_type", cfg.Jira.EffectiveIssueType(),
						"routes", routeSummary(cfg.Jira),
						"require_route", cfg.Jira.RequireRoute,
						"auto_close", closeSummary(cfg.Jira),
						"auto_ticket", autoTicket)
					if autoTicket {
						// Loud on purpose: from here the service writes to Jira on a
						// schedule with no further prompting.
						slog.WarnContext(cmd.Context(),
							"AUTO-TICKETING IS ON: every scheduled refresh will create and update Jira issues",
							"interval", interval.String())
					}
				}
			} else if autoTicket {
				return fmt.Errorf("--auto-ticket needs a jira config block: %w", err)
			}

			ctx := cmd.Context()
			// Run assessments (initial + on interval) in the background.
			go srv.Start(ctx, interval)

			httpServer := &http.Server{
				Addr:              addr,
				Handler:           srv.Handler(),
				ReadHeaderTimeout: 10 * time.Second,
			}
			// Shut down gracefully when the command context is cancelled.
			go func() {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = httpServer.Shutdown(shutdownCtx)
			}()

			slog.InfoContext(ctx, "serving assessment API", "addr", addr, "refresh_interval", interval.String())
			if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}

	in.provider.bind(cmd)
	cmd.Flags().StringArrayVarP(&in.configPaths, "config", "c", nil, "config YAML file or directory (repeatable)")
	cmd.Flags().StringVar(&in.liveSource, "live-source", "", "reconcile against live clusters using a source ("+joinLiveSources()+")")
	cmd.Flags().StringArrayVar(&in.liveOptions, "live-option", nil, "live source option as key=value (repeatable)")
	cmd.Flags().StringVar(&in.vulnSource, "vuln-source", "", "scan images for per-CVE fix availability ("+joinVulnSources()+")")
	cmd.Flags().StringArrayVar(&in.vulnOptions, "vuln-option", nil, "vuln source option as key=value (repeatable)")
	cmd.Flags().StringVar(&in.exploitSource, "exploit-source", "", "enrich CVEs with exploit intel ("+joinExploitSources()+"); requires --vuln-source")
	cmd.Flags().StringArrayVar(&in.exploitOptions, "exploit-option", nil, "exploit source option as key=value (repeatable)")
	cmd.Flags().BoolVar(&in.remediation, "remediation", false, "detect available upgrades for how images are deployed")
	cmd.Flags().StringVar(&addr, "addr", ":8080", "address to serve the API on")
	cmd.Flags().BoolVar(&metricsAuth, "metrics-require-auth", false,
		"require the API token on /metrics too. Off by default: a scrape config needing a "+
			"credential is friction where it is least tolerated. On means anything scraping "+
			"must present the token, which is worth it if coverage counts are treated as "+
			"sensitive in your environment.")
	cmd.Flags().BoolVar(&autoTicket, "auto-ticket", false,
		"create and reconcile Jira tickets on every scheduled refresh. Off by default: a "+
			"service that starts raising tickets the moment it deploys is not a good surprise. "+
			"The API endpoints work either way.")
	cmd.Flags().DurationVar(&interval, "interval", time.Hour, "how often to re-run the assessment (0 to run once)")
	return cmd
}
