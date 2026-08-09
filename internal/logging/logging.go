// Package logging configures the process-wide slog logger for patchwright.
//
// Logs always go to STDERR so they never corrupt the assessment report, which
// is written to STDOUT (this matters for `--format json`). Packages log via the
// standard slog package-level functions against the default logger this
// configures.
package logging

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Configure sets the default slog logger from a level and format string, both
// case-insensitive. Level is one of debug|info|warn|error; format is text|json.
func Configure(level, format string) error {
	lvl, err := parseLevel(level)
	if err != nil {
		return err
	}
	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		handler = slog.NewTextHandler(os.Stderr, opts)
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		return fmt.Errorf("invalid log format %q (want text or json)", format)
	}

	slog.SetDefault(slog.New(handler))
	return nil
}

func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (want debug, info, warn, or error)", level)
	}
}
