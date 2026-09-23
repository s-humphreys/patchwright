package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/s-humphreys/patchwright/internal/server"
	"github.com/s-humphreys/patchwright/pkg/history/postgres"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

func newHistoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Maintain the history record",
	}
	cmd.AddCommand(newBackfillTicketsCmd())
	return cmd
}

// newBackfillTicketsCmd rereads every ticket from the tracker. serve already does
// this on its first run against an empty index and incrementally after; this is
// for after a change the incremental window cannot see, such as a new route or a
// project whose history was edited in bulk.
func newBackfillTicketsCmd() *cobra.Command {
	var configPaths []string
	cmd := &cobra.Command{
		Use:   "backfill-tickets",
		Short: "Read every ticket on the configured trackers into the history record",
		Long: "backfill-tickets reads every ticket on the configured projects and issue type, closed ones\n" +
			"included, with the tracker's created, first In Progress and resolution dates, and writes\n" +
			"them to the history store named by " + envHistoryDSN + ". Tickets are upserted by key, so it\n" +
			"is safe to run while serve is running and safe to run twice.\n\n" +
			"Tickets are matched to the work items open now by image. A ticket on an item that closed\n" +
			"before it was first read stays unmatched: it is reported as a ticket, never as a resolution.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			dsn := os.Getenv(envHistoryDSN)
			if dsn == "" {
				return fmt.Errorf("%s is not set: there is no history store to backfill", envHistoryDSN)
			}
			cfg, err := loadTicketConfig(configPaths)
			if err != nil {
				return err
			}
			jira, err := ticket.NewJira(cfg.Jira)
			if err != nil {
				return err
			}
			store, err := postgres.Open(ctx, postgres.Options{
				DSN: dsn, Auth: postgres.Auth(cfg.History.Auth), Password: os.Getenv(envHistoryPassword),
				// A full read with change history is many pages; the per-query default
				// is sized for a report, not for this.
				Timeout: 5 * time.Minute,
			})
			if err != nil {
				return err
			}
			defer store.Close()
			res, err := server.SyncTrackerTickets(ctx, store, jira, true)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Read %d tickets from the tracker; %d matched to an open work item.\n", res.Fetched, res.Matched)
			return nil
		},
	}
	cmd.Flags().StringArrayVarP(&configPaths, "config", "c", nil, "config YAML file or directory (repeatable)")
	return cmd
}
