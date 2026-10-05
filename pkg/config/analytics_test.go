package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAnalyticsExclusions(t *testing.T) {
	no := false
	yes := true
	route := func(name, project, epic string, count *bool) TicketRoute {
		return TicketRoute{Name: name, When: "true", Board: 1, Project: project, Epic: epic, ImageLabel: &yes, CountInAnalytics: count}
	}
	cases := []struct {
		name   string
		routes []TicketRoute
		want   []AnalyticsScope
		err    string
	}{
		{name: "nothing excluded by default", routes: []TicketRoute{route("a", "PROJ", "PROJ-1", nil), route("b", "PROJ", "PROJ-2", &yes)}},
		{name: "a test epic on a shared project", routes: []TicketRoute{route("real", "PROJ", "PROJ-1", nil), route("test", "PROJ", "PROJ-9", &no)},
			want: []AnalyticsScope{{Route: "test", Project: "PROJ", Epic: "PROJ-9"}}},
		{name: "a project of its own needs no epic", routes: []TicketRoute{route("real", "PROJ", "", nil), route("sandbox", "SAND", "", &no)},
			want: []AnalyticsScope{{Route: "sandbox", Project: "SAND"}}},
		{name: "no epic on a shared project", routes: []TicketRoute{route("real", "PROJ", "PROJ-1", nil), route("test", "PROJ", "", &no)},
			err: `jira route "test": countInAnalytics false needs an epic`},
		{name: "the same epic as a counted route", routes: []TicketRoute{route("real", "PROJ", "PROJ-1", nil), route("test", "PROJ", "PROJ-1", &no)},
			err: "files under the same epic PROJ-1"},
		{name: "two excluded routes may share", routes: []TicketRoute{route("t1", "SAND", "", &no), route("t2", "SAND", "", &no)},
			want: []AnalyticsScope{{Route: "t1", Project: "SAND"}, {Route: "t2", Project: "SAND"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := JiraConfig{DefaultTemplate: "t", Routes: c.routes}
			err := cfg.ValidateRead()
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			if got := cfg.AnalyticsExclusions(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("exclusions = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestCountInAnalyticsLoads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "jira.yaml")
	body := `jira:
  routes:
    - name: real
      when: "true"
      project: PROJ
      board: 1
      imageLabel: true
      epic: PROJ-1
    - name: test
      when: "false"
      project: PROJ
      board: 1
      imageLabel: true
      epic: PROJ-9
      countInAnalytics: false
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []AnalyticsScope{{Route: "test", Project: "PROJ", Epic: "PROJ-9"}}
	if got := cfg.Jira.AnalyticsExclusions(); !reflect.DeepEqual(got, want) {
		t.Errorf("exclusions = %+v, want %+v", got, want)
	}
}
