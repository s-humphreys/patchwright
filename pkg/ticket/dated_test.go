package ticket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
)

// datedServer fakes the three endpoints DatedTickets reads: the status list, the
// search with its expanded history, and the per-issue history for a ticket whose
// history is longer than the search expands.
type datedServer struct {
	statusFails bool
	jqls        []string
	fields      string
	expand      []string
	pagedFor    []string
}

func (ds *datedServer) jira(t *testing.T, routes []config.TicketRoute) *Jira {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/rest/api/3/status":
			if ds.statusFails {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`[
			  {"id":"1","statusCategory":{"key":"new"}},
			  {"id":"3","statusCategory":{"key":"indeterminate"}},
			  {"id":"4","statusCategory":{"key":"indeterminate"}},
			  {"id":"6","statusCategory":{"key":"done"}}]`))
		case strings.HasSuffix(r.URL.Path, "/changelog"):
			ds.pagedFor = append(ds.pagedFor, r.URL.Path)
			// Oldest first, as this endpoint returns it.
			_, _ = w.Write([]byte(`{"startAt":0,"maxResults":100,"total":2,"isLast":true,"values":[
			  {"created":"2026-07-03T09:00:00.000+0000","items":[{"field":"status","to":"4"}]},
			  {"created":"2026-07-20T09:00:00.000+0000","items":[{"field":"status","to":"6"}]}]}`))
		case r.URL.Path == "/rest/api/3/search/jql":
			ds.jqls = append(ds.jqls, r.URL.Query().Get("jql"))
			ds.fields = r.URL.Query().Get("fields")
			ds.expand = append(ds.expand, r.URL.Query().Get("expand"))
			if r.URL.Query().Get("nextPageToken") == "" {
				_, _ = w.Write([]byte(`{"issues":[
				  {"key":"PROJ-1","fields":{
				     "summary":"Upgrade app to 1.1",
				     "created":"2026-07-01T10:00:00.000+0100",
				     "resolutiondate":"2026-07-10T16:30:00.000+0000",
				     "duedate":"2026-07-15",
				     "statuscategorychangedate":"2026-07-10T16:30:00.000+0000",
				     "status":{"name":"Done","statusCategory":{"key":"done"}},
				     "customfield_1":["acr.io/app","acr.io/lib"]},
				   "changelog":{"total":3,"histories":[
				     {"created":"2026-07-10T16:30:00.000+0000","items":[{"field":"status","to":"6"}]},
				     {"created":"2026-07-06T09:00:00.000+0000","items":[{"field":"status","to":"4"}]},
				     {"created":"2026-07-02T09:00:00.000+0000","items":[{"field":"assignee","to":"abc"},{"field":"status","to":"3"}]}]}},
				  {"key":"PROJ-2","fields":{
				     "created":"2026-07-01T10:00:00.000+0000",
				     "resolutiondate":null,
				     "statuscategorychangedate":"2026-07-04T11:00:00.000+0000",
				     "status":{"name":"In Progress","statusCategory":{"key":"indeterminate"}},
				     "customfield_1":["acr.io/other"]},
				   "changelog":{"total":1,"histories":[
				     {"created":"2026-07-04T11:00:00.000+0000","items":[{"field":"status","to":"3"}]}]}}
				],"nextPageToken":"more","isLast":false}`))
				return
			}
			_, _ = w.Write([]byte(`{"issues":[
			  {"key":"PROJ-3","fields":{
			     "created":"2026-07-01T10:00:00.000+0000",
			     "resolutiondate":null,
			     "statuscategorychangedate":"2026-07-20T09:00:00.000+0000",
			     "status":{"name":"Won't Do","statusCategory":{"key":"done"}},
			     "customfield_1":["acr.io/gone"]},
			   "changelog":{"total":150,"histories":[
			     {"created":"2026-07-20T09:00:00.000+0000","items":[{"field":"status","to":"6"}]}]}},
			  {"key":"PROJ-4","fields":{
			     "created":"2026-07-01T10:00:00.000+0000",
			     "resolutiondate":"2026-06-01T10:00:00.000+0000",
			     "statuscategorychangedate":"2026-07-01T10:00:00.000+0000",
			     "status":{"name":"To Do","statusCategory":{"key":"new"}},
			     "customfield_1":["acr.io/reopened"]},
			   "changelog":{"total":0,"histories":[]}}
			],"isLast":true}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return &Jira{BaseURL: srv.URL, Email: "e", Token: "t", Client: srv.Client(),
		cfg: config.JiraConfig{IssueType: "Container Vulnerability", Routes: routes}}
}

func sharedRoutes() []config.TicketRoute {
	// Two routes on one board: one search, not two.
	return []config.TicketRoute{
		{Name: "a", When: "true", Board: 1, Project: "PROJ", ImageField: "customfield_1"},
		{Name: "b", When: "true", Board: 1, Project: "PROJ", ImageField: "customfield_1"},
	}
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestDatedTicketsReadsTheTrackersDates(t *testing.T) {
	ds := &datedServer{}
	got, err := ds.jira(t, sharedRoutes()).DatedTickets(context.Background(), 0)
	if err != nil {
		t.Fatalf("DatedTickets: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want four tickets across two pages, got %d: %+v", len(got), got)
	}
	if len(ds.jqls) != 2 {
		t.Errorf("want one search of two pages, got %d requests: routes sharing a board must not search twice", len(ds.jqls))
	}
	for _, jql := range ds.jqls {
		if strings.Contains(jql, "statusCategory") {
			t.Errorf("the backfill must include closed tickets: %s", jql)
		}
		if strings.Contains(jql, "updated") {
			t.Errorf("a backfill has no updated window: %s", jql)
		}
	}
	for _, want := range []string{"summary", "created", "resolutiondate", "duedate", "status", "statuscategorychangedate", "customfield_1"} {
		if !strings.Contains(ds.fields, want) {
			t.Errorf("fields %q do not request %s", ds.fields, want)
		}
	}
	if ds.expand[0] != "changelog" {
		t.Errorf("expand = %q, want changelog", ds.expand[0])
	}

	byKey := map[string]Dated{}
	for _, d := range got {
		byKey[d.Key] = d
	}

	p1 := byKey["PROJ-1"]
	if p1.Project != "PROJ" || !p1.Created.Equal(at("2026-07-01T09:00:00Z")) {
		t.Errorf("PROJ-1 project/created = %q %v", p1.Project, p1.Created)
	}
	if p1.Summary != "Upgrade app to 1.1" {
		t.Errorf("PROJ-1 summary = %q", p1.Summary)
	}
	// The earliest move into any indeterminate status, not the latest and not the
	// first entry in the list.
	if p1.Started == nil || !p1.Started.Equal(at("2026-07-02T09:00:00Z")) || p1.StartedFrom != StartedFromChangelog {
		t.Errorf("PROJ-1 started = %v from %q, want 2026-07-02 from the changelog", p1.Started, p1.StartedFrom)
	}
	if p1.Resolved == nil || !p1.Resolved.Equal(at("2026-07-10T16:30:00Z")) {
		t.Errorf("PROJ-1 resolved = %v", p1.Resolved)
	}
	if p1.Due == nil || p1.Due.Format(time.DateOnly) != "2026-07-15" {
		t.Errorf("PROJ-1 due = %v", p1.Due)
	}
	if len(p1.Images) != 2 || p1.Images[0] != "acr.io/app" {
		t.Errorf("PROJ-1 images = %v", p1.Images)
	}
	if !strings.Contains(string(p1.Fields), "customfield_1") {
		t.Errorf("raw fields not kept: %s", p1.Fields)
	}

	p2 := byKey["PROJ-2"]
	if p2.Resolved != nil || p2.Started == nil || !p2.Started.Equal(at("2026-07-04T11:00:00Z")) || p2.Category != "indeterminate" {
		t.Errorf("PROJ-2 = %+v", p2)
	}

	// Done without a resolution: the move into done dates it. Its history is longer
	// than the search expanded, so the full history is read, oldest first.
	p3 := byKey["PROJ-3"]
	if p3.Resolved == nil || !p3.Resolved.Equal(at("2026-07-20T09:00:00Z")) {
		t.Errorf("PROJ-3 resolved = %v, want the status category change date", p3.Resolved)
	}
	if p3.Started == nil || !p3.Started.Equal(at("2026-07-03T09:00:00Z")) {
		t.Errorf("PROJ-3 started = %v, want 2026-07-03 from the paged history", p3.Started)
	}
	if len(ds.pagedFor) != 1 || !strings.Contains(ds.pagedFor[0], "PROJ-3") {
		t.Errorf("only the truncated history should be paged: %v", ds.pagedFor)
	}

	// Reopened with a stale resolution date: open work, not a close.
	if p4 := byKey["PROJ-4"]; p4.Resolved != nil || p4.Started != nil {
		t.Errorf("PROJ-4 = %+v, want neither resolved nor started", p4)
	}
}

func TestDatedTicketsIncrementalWindow(t *testing.T) {
	ds := &datedServer{}
	if _, err := ds.jira(t, sharedRoutes()).DatedTickets(context.Background(), 48*time.Hour); err != nil {
		t.Fatalf("DatedTickets: %v", err)
	}
	if !strings.Contains(ds.jqls[0], "updated >= -2880m") {
		t.Errorf("jql = %s, want an updated window of 2880 minutes", ds.jqls[0])
	}
}

// Without the status list the history cannot be read, so a ticket in progress now
// is dated by its status category change and nothing else is guessed at.
func TestDatedTicketsFallsBackWithoutStatusCategories(t *testing.T) {
	ds := &datedServer{statusFails: true}
	got, err := ds.jira(t, sharedRoutes()).DatedTickets(context.Background(), 0)
	if err != nil {
		t.Fatalf("DatedTickets: %v", err)
	}
	if ds.expand[0] != "" {
		t.Errorf("no history to map, so none should be expanded: expand = %q", ds.expand[0])
	}
	for _, d := range got {
		switch d.Key {
		case "PROJ-2":
			if d.Started == nil || !d.Started.Equal(at("2026-07-04T11:00:00Z")) || d.StartedFrom != StartedFromStatusCategory {
				t.Errorf("PROJ-2 started = %v from %q, want the status category change date", d.Started, d.StartedFrom)
			}
		default:
			if d.Started != nil {
				t.Errorf("%s started = %v, want undated: it is not in progress now", d.Key, d.Started)
			}
		}
	}
}
