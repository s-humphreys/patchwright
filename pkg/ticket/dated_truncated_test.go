package ticket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
)

// The search's expanded changelog is the NEWEST page of history ("sorted by date,
// starting from the most recent", GET /rest/api/3/search/jql). A ticket reopened
// and moved back into progress has a progress entry on that page that is not its
// first; the first one is only on the full, oldest-first history.
func TestDatedTicketsReadsATruncatedHistoryInFull(t *testing.T) {
	var paged []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/rest/api/3/status":
			_, _ = w.Write([]byte(`[{"id":"1","statusCategory":{"key":"new"}},{"id":"3","statusCategory":{"key":"indeterminate"}},{"id":"6","statusCategory":{"key":"done"}}]`))
		case strings.HasSuffix(r.URL.Path, "/changelog"):
			paged = append(paged, r.URL.Path)
			_, _ = w.Write([]byte(`{"startAt":0,"maxResults":100,"total":3,"isLast":true,"values":[
			  {"created":"2026-07-02T09:00:00.000+0000","items":[{"field":"status","to":"3"}]},
			  {"created":"2026-07-05T09:00:00.000+0000","items":[{"field":"status","to":"6"}]},
			  {"created":"2026-08-10T09:00:00.000+0000","items":[{"field":"status","to":"3"}]}]}`))
		case r.URL.Path == "/rest/api/3/search/jql":
			_, _ = w.Write([]byte(`{"issues":[{"key":"PROJ-7","fields":{
			     "created":"2026-07-01T09:00:00.000+0000",
			     "statuscategorychangedate":"2026-08-10T09:00:00.000+0000",
			     "status":{"name":"In Progress","statusCategory":{"key":"indeterminate"}},
			     "customfield_1":["acr.io/app"]},
			   "changelog":{"startAt":0,"maxResults":1,"total":150,"histories":[
			     {"created":"2026-08-10T09:00:00.000+0000","items":[{"field":"status","to":"3"}]}]}}],"isLast":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	j := &Jira{BaseURL: srv.URL, Email: "e", Token: "t", Client: srv.Client(),
		cfg: config.JiraConfig{IssueType: "Container Vulnerability", Routes: sharedRoutes()}}

	got, err := j.DatedTickets(context.Background(), 0)
	if err != nil {
		t.Fatalf("DatedTickets: %v", err)
	}
	if len(got) != 1 || got[0].Started == nil || !got[0].Started.Equal(at("2026-07-02T09:00:00Z")) {
		t.Errorf("started = %v, want 2026-07-02 (the first move into progress, read from the full history); paged %v", got[0].Started, paged)
	}
}
