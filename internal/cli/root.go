// Package cli wires patchwright's command-line interface.
package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/s-humphreys/patchwright/internal/logging"
	"github.com/s-humphreys/patchwright/pkg/provider"

	// Register the built-in providers.
	_ "github.com/s-humphreys/patchwright/pkg/provider/rapid7"
)

// providerFlags are the flags shared by any command that ingests scan data.
type providerFlags struct {
	name    string
	input   string
	mode    string
	options []string // additional provider options as key=value
}

func (pf *providerFlags) bind(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&pf.name, "provider", "rapid7", "provider to ingest scan data from ("+joinProviders()+")")
	f.StringVarP(&pf.input, "input", "i", "", "input path for the provider (e.g. exported CSV)")
	f.StringVar(&pf.mode, "mode", "", "provider mode (e.g. csv, api)")
	f.StringArrayVarP(&pf.options, "option", "o", nil, "additional provider option as key=value (repeatable)")
}

// build constructs the configured provider.
func (pf *providerFlags) build() (provider.Provider, error) {
	opts := provider.Options{}
	if pf.input != "" {
		opts["input"] = pf.input
	}
	if pf.mode != "" {
		opts["mode"] = pf.mode
	}
	for _, kv := range pf.options {
		k, v, ok := splitKV(kv)
		if !ok {
			return nil, fmt.Errorf("invalid --option %q, want key=value", kv)
		}
		opts[k] = v
	}
	return provider.New(pf.name, opts)
}

func joinProviders() string {
	names := provider.Names()
	if len(names) == 0 {
		return "none registered"
	}
	out := names[0]
	for _, n := range names[1:] {
		out += ", " + n
	}
	return out
}

func splitKV(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func newRootCmd() *cobra.Command {
	var logLevel, logFormat string

	root := &cobra.Command{
		Use:   "patchwright",
		Short: "Turn noisy container-vulnerability scanner output into an actionable, owner-attributed list",
		// Errors are logged (structured) in Execute rather than printed by cobra.
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return logging.Configure(logLevel, logFormat)
		},
	}
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, or error")
	root.PersistentFlags().StringVar(&logFormat, "log-format", "text", "log format: text or json (logs go to stderr)")

	root.AddCommand(newProfileCmd())
	root.AddCommand(newAssessCmd())
	return root
}

// Execute runs the root command, logging any error before returning it. It
// installs a signal-cancellable context so SIGINT/SIGTERM propagate into
// provider fetches, scans, and reconciliation via cmd.Context().
func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := newRootCmd().ExecuteContext(ctx)
	if err != nil {
		slog.Error("command failed", "error", err)
	}
	return err
}
