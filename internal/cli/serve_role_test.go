package cli

import (
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/internal/server"
)

func TestCheckRole(t *testing.T) {
	const dsn = "postgres://patchwright@db/patchwright"
	for _, tc := range []struct {
		name       string
		role       server.Role
		dsn        string
		autoTicket bool
		issuer     string
		sessionKey string
		want       string
	}{
		{name: "all without a database is today's default", role: server.RoleAll},
		{name: "all with auto-ticketing", role: server.RoleAll, autoTicket: true},
		{name: "web without a database", role: server.RoleWeb, want: "--role=web needs PATCHWRIGHT_HISTORY_DSN"},
		{name: "worker without a database", role: server.RoleWorker, want: "--role=worker needs PATCHWRIGHT_HISTORY_DSN"},
		{name: "web with a database", role: server.RoleWeb, dsn: dsn},
		{name: "worker with auto-ticketing", role: server.RoleWorker, dsn: dsn, autoTicket: true},
		{name: "web with auto-ticketing", role: server.RoleWeb, dsn: dsn, autoTicket: true, want: "never writes to a tracker"},
		{name: "web sign-in without a shared key", role: server.RoleWeb, dsn: dsn, issuer: "https://idp", want: "PATCHWRIGHT_SESSION_KEY"},
		{name: "web sign-in with a shared key", role: server.RoleWeb, dsn: dsn, issuer: "https://idp", sessionKey: "k"},
		{name: "worker sign-in without a key serves no page", role: server.RoleWorker, dsn: dsn, issuer: "https://idp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRole(tc.role, tc.dsn, tc.autoTicket, tc.issuer, tc.sessionKey)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("err = %v, want one naming %q", err, tc.want)
			}
		})
	}
}

// The serve command itself refuses web without a database, before it builds anything.
func TestServeRefusesWebWithoutAStore(t *testing.T) {
	t.Setenv(envHistoryDSN, "")
	cmd := newServeCmd()
	cmd.SetArgs([]string{"--role=web"})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "needs "+envHistoryDSN) {
		t.Fatalf("serve --role=web without a DSN = %v", err)
	}
}

func TestServeRejectsAnUnknownRole(t *testing.T) {
	cmd := newServeCmd()
	cmd.SetArgs([]string{"--role=both"})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unknown role") {
		t.Fatalf("serve --role=both = %v", err)
	}
}
