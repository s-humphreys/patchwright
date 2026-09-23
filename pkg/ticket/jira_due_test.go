package ticket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
)

func TestCreateSetsTheDueDateFromPriority(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Fields map[string]any `json:"fields"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode create request: %v", err)
		}
		got = body.Fields
		_, _ = w.Write([]byte(`{"key":"PROJ-7"}`))
	}))
	defer srv.Close()

	base := config.JiraConfig{Project: "PROJ", ImageField: "customfield_1"}
	withDue := base
	withDue.DueDays = map[string]int{"urgent": 7}
	route := config.TicketRoute{Name: "sre", When: "true", Project: "PROJ",
		ImageField: "customfield_1", DueDays: map[string]int{"urgent": 2}}

	cases := []struct {
		name     string
		cfg      config.JiraConfig
		route    string
		priority string
		wantDays int
	}{
		{name: "configured", cfg: withDue, priority: "urgent", wantDays: 7},
		{name: "priority with no window", cfg: withDue, priority: "low"},
		{name: "unconfigured", cfg: base, priority: "urgent"},
		{name: "route override", cfg: withDue, route: route.Name, priority: "urgent", wantDays: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got = nil
			j := &Jira{BaseURL: srv.URL, Client: srv.Client(), cfg: tc.cfg,
				byRoute: map[string]config.JiraConfig{route.Name: tc.cfg.Resolve(route)}}
			before := time.Now()
			created, err := j.Create(context.Background(), Draft{
				Summary: "x", Description: "y", Images: []string{"a/b"}, Priority: tc.priority, Route: tc.route,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			after := time.Now()

			due, present := got["duedate"]
			if tc.wantDays == 0 {
				if present {
					t.Errorf("duedate = %v, want it absent so existing deployments are unaffected", due)
				}
				if created.DueDate != nil {
					t.Errorf("Created.DueDate = %v, want nil", created.DueDate)
				}
				return
			}
			// Either side of the call, in case it straddled midnight UTC.
			day := 24 * time.Hour * time.Duration(tc.wantDays)
			lo := before.UTC().Add(day).Format(time.DateOnly)
			hi := after.UTC().Add(day).Format(time.DateOnly)
			if due != lo && due != hi {
				t.Errorf("duedate = %v, want %s", due, hi)
			}
			// What Create reports is what it sent, so history and Jira agree.
			if created.DueDate == nil || created.DueDate.Format(time.DateOnly) != due {
				t.Errorf("Created.DueDate = %v, want %v", created.DueDate, due)
			}
		})
	}
}
