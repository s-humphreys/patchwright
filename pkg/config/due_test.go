package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJiraDueDate(t *testing.T) {
	cfg := JiraConfig{DueDays: map[string]int{"urgent": 7, "high": 30}}
	noon := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	// 23:30 in UTC-5 is already the next day in UTC, which is the date that counts.
	lateWest := time.Date(2026, 9, 22, 23, 30, 0, 0, time.FixedZone("UTC-5", -5*60*60))
	// 00:30 in UTC+2 is still the previous day in UTC.
	earlyEast := time.Date(2026, 9, 23, 0, 30, 0, 0, time.FixedZone("UTC+2", 2*60*60))

	cases := []struct {
		name     string
		cfg      JiraConfig
		priority string
		now      time.Time
		want     string
		wantOK   bool
	}{
		{name: "configured", cfg: cfg, priority: "urgent", now: noon, want: "2026-09-29", wantOK: true},
		{name: "crosses a month", cfg: cfg, priority: "high", now: noon, want: "2026-10-22", wantOK: true},
		{name: "unconfigured priority", cfg: cfg, priority: "low", now: noon},
		{name: "no priority", cfg: cfg, priority: "", now: noon},
		{name: "no map", cfg: JiraConfig{}, priority: "urgent", now: noon},
		{name: "local evening is the next UTC day", cfg: cfg, priority: "urgent", now: lateWest, want: "2026-09-30", wantOK: true},
		{name: "local early morning is the previous UTC day", cfg: cfg, priority: "urgent", now: earlyEast, want: "2026-09-29", wantOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.cfg.DueDate(tc.priority, tc.now)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("DueDate(%q, %v) = (%q, %v), want (%q, %v)", tc.priority, tc.now, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// A route's map replaces the default whole, as priorityMap does: merging would
// leave a team that set only urgent inheriting everyone else's low window.
func TestDueDaysRouteOverride(t *testing.T) {
	base := JiraConfig{DefaultTemplate: "t.tmpl", DueDays: map[string]int{"urgent": 7, "low": 90}}
	cases := []struct {
		name  string
		route TicketRoute
		want  map[string]int
	}{
		{name: "inherits the default", route: TicketRoute{Name: "a"}, want: map[string]int{"urgent": 7, "low": 90}},
		{name: "replaces it whole", route: TicketRoute{Name: "b", DueDays: map[string]int{"urgent": 3}}, want: map[string]int{"urgent": 3}},
		{name: "empty map inherits", route: TicketRoute{Name: "c", DueDays: map[string]int{}}, want: map[string]int{"urgent": 7, "low": 90}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := base.Resolve(tc.route).DueDays
			if len(got) != len(tc.want) {
				t.Fatalf("DueDays = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("DueDays = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestDueDaysLoadsAndValidates(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const route = `
  routes:
    - name: a
      when: "true"
      project: A
      board: 1
      imageLabel: true
`
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "unset", yaml: "jira:\n  defaultTicketTemplate: t.tmpl" + route},
		{name: "positive", yaml: "jira:\n  defaultTicketTemplate: t.tmpl\n  dueDays: {urgent: 7, high: 30}" + route},
		{name: "zero", yaml: "jira:\n  defaultTicketTemplate: t.tmpl\n  dueDays: {urgent: 0}" + route,
			wantErr: `jira dueDays["urgent"] is 0`},
		{name: "negative", yaml: "jira:\n  defaultTicketTemplate: t.tmpl\n  dueDays: {high: -3}" + route,
			wantErr: `jira dueDays["high"] is -3`},
		{name: "negative on a route", yaml: "jira:\n  defaultTicketTemplate: t.tmpl" + route + "      dueDays: {urgent: -1}\n",
			wantErr: `jira route "a": jira dueDays["urgent"] is -1`},
		// A route replacing the map must not let a bad default through unchecked.
		{name: "bad default behind an overriding route", yaml: "jira:\n  defaultTicketTemplate: t.tmpl\n  dueDays: {low: 0}" + route + "      dueDays: {urgent: 7}\n",
			wantErr: `jira dueDays["low"] is 0`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(write(filepath.Base(t.Name())+".yaml", tc.yaml))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			err = cfg.Jira.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("Validate: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("Validate = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// A file whose jira section sets only dueDays is still a jira section, and has to
// count as one when files are merged.
func TestDueDaysAloneSurvivesTheMerge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("jira:\n  dueDays: {urgent: 7}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Jira.DueDays["urgent"] != 7 {
		t.Errorf("DueDays = %v, want urgent: 7", cfg.Jira.DueDays)
	}
}
