package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// HistoryConfig is the settings for the record of movement. The connection string
// is not here: it carries a credential, so it comes from the environment
// (PATCHWRIGHT_HISTORY_DSN), and its presence is what switches history on.
type HistoryConfig struct {
	// Retention is how long events and closed items are kept, as a number of days
	// ("400d") or a Go duration. Required when history is enabled and deliberately
	// not defaulted: the record is a history of which services carried exploitable
	// vulnerabilities and for how long, and how long to keep that is a policy for
	// whoever owns security records to set, not for a config file to assume.
	Retention string `yaml:"retention"`
	// Auth is how the connection authenticates: "password" (the default, whatever
	// the DSN carries) or "azure" (an Entra token minted per connection for Azure
	// Database for PostgreSQL, with no password anywhere).
	Auth string `yaml:"auth"`
}

// RetentionDuration parses Retention. Zero with no error when unset.
func (h HistoryConfig) RetentionDuration() (time.Duration, error) {
	return parseRetention(h.Retention)
}

func (h HistoryConfig) validate() error {
	if _, err := parseRetention(h.Retention); err != nil {
		return fmt.Errorf("history.retention: %w", err)
	}
	switch h.Auth {
	case "", "password", "azure":
		return nil
	}
	return fmt.Errorf("history.auth: %q is not one of password, azure", h.Auth)
}

// parseRetention accepts "<n>d" for days, since a retention policy is written in
// days and Go durations stop at hours, or any Go duration.
func parseRetention(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("%q must be a positive number of days, like 400d", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number of days (400d) or a duration", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%q must be positive", s)
	}
	return d, nil
}
