package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRetention(t *testing.T) {
	cases := map[string]time.Duration{
		"":     0,
		"400d": 400 * 24 * time.Hour,
		"1d":   24 * time.Hour,
		"720h": 720 * time.Hour,
	}
	for in, want := range cases {
		got, err := parseRetention(in)
		if err != nil || got != want {
			t.Errorf("parseRetention(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"0d", "-3d", "d", "13 months", "1y", "-1h"} {
		if _, err := parseRetention(bad); err == nil {
			t.Errorf("parseRetention(%q) should fail", bad)
		}
	}
}

func TestHistoryConfigLoadsAndValidates(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg, err := Load(write("ok.yaml", "history:\n  retention: 400d\n  auth: azure\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	d, err := cfg.History.RetentionDuration()
	if err != nil || d != 400*24*time.Hour || cfg.History.Auth != "azure" {
		t.Errorf("history = %+v (%v)", cfg.History, err)
	}

	if _, err := Load(write("auth.yaml", "history:\n  auth: kerberos\n")); err == nil || !strings.Contains(err.Error(), "history.auth") {
		t.Errorf("unknown auth should fail at load, got %v", err)
	}
	if _, err := Load(write("ret.yaml", "history:\n  retention: soon\n")); err == nil || !strings.Contains(err.Error(), "history.retention") {
		t.Errorf("bad retention should fail at load, got %v", err)
	}
	// Unset is allowed: history is off unless a DSN is present, and the check that
	// retention is set when it is on belongs to the command that has the DSN.
	if _, err := Load(write("none.yaml", "owners: []\n")); err != nil {
		t.Errorf("no history block should be fine: %v", err)
	}
}
