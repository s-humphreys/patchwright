package cli

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/s-humphreys/patchwright/internal/server"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

func newServeCmd() *cobra.Command {
	var (
		in       assessInputs
		addr     string
		interval time.Duration
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run patchwright as a service exposing a read-only assessment API",
		Long: "serve runs the same assessment as `assess` on a schedule, caches the latest result,\n" +
			"and exposes it over a read-only HTTP/JSON API (findings, owners, summary). It is the\n" +
			"deployment mode: run it as a Deployment instead of a CronJob so people and tools can\n" +
			"query current findings.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := newAssessor(in)
			if err != nil {
				return err
			}
			srv := server.New(a)

			// Attach the open-ticket index when Jira is configured and credentials
			// are present, so the API and page can show whether someone is already
			// on a finding. Both are optional: without them the server simply has
			// nothing to say about tickets, which is different from saying there
			// are none. Only search is used here, never creation.
			if cfg, err := loadTicketConfig(in.configPaths); err == nil {
				jira, jerr := ticket.NewJira(cfg.Jira)
				if jerr != nil {
					slog.WarnContext(cmd.Context(),
						"jira configured but credentials missing; ticket links disabled", "error", jerr)
				} else {
					srv = srv.WithTickets(jira, jira.BaseURL)
					slog.InfoContext(cmd.Context(), "ticket lookup enabled",
						"project", cfg.Jira.Project, "issue_type", cfg.Jira.EffectiveIssueType())
				}
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
	cmd.Flags().DurationVar(&interval, "interval", time.Hour, "how often to re-run the assessment (0 to run once)")
	return cmd
}
