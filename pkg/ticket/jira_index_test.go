package ticket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
)

// The index is what makes "is someone already on this?" cheap: one query for the
// whole project, with each ticket's images read back out of the configured field.
func TestOpenByImageIndexesEveryImageOnATicket(t *testing.T) {
	var gotJQL, gotFields string
	pages := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotJQL = r.URL.Query().Get("jql")
		gotFields = r.URL.Query().Get("fields")
		pages++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("nextPageToken") == "" {
			// First page: a grouped ticket covering several images, as a real
			// chain-merged ticket does.
			_, _ = w.Write([]byte(`{"issues":[
			  {"key":"PROJ-1","fields":{
			     "summary":"Upgrade flux-operator to 0.58.0",
			     "status":{"name":"NEEDS REFINEMENT","statusCategory":{"key":"new"}},
			     "customfield_20983":["controlplaneio-fluxcd/flux-operator","fluxcd/source-controller"]}}
			],"nextPageToken":"more","isLast":false}`))
			return
		}
		_, _ = w.Write([]byte(`{"issues":[
		  {"key":"PROJ-2","fields":{
		     "summary":"Upgrade curl",
		     "status":{"name":"In Progress","statusCategory":{"key":"indeterminate"}},
		     "customfield_20983":["curlimages/curl"]}}
		],"isLast":true}`))
	}))
	defer srv.Close()

	j := &Jira{
		BaseURL: srv.URL, Email: "e", Token: "t", Client: srv.Client(),
		cfg: config.JiraConfig{Project: "PROJ", IssueType: "Container Vulnerability",
			ImageField: "customfield_20983"},
	}
	got, err := j.OpenByImage(context.Background())
	if err != nil {
		t.Fatalf("OpenByImage: %v", err)
	}

	if pages != 2 {
		t.Errorf("fetched %d pages, want 2: results must not be truncated at one page", pages)
	}
	// Every image on a grouped ticket must map to it, or the queue would show a
	// ticket against one image of seven.
	for _, repo := range []string{"controlplaneio-fluxcd/flux-operator", "fluxcd/source-controller"} {
		if refs := got[repo]; len(refs) != 1 || refs[0].Key != "PROJ-1" {
			t.Errorf("%s -> %+v, want PROJ-1", repo, refs)
		}
	}
	if refs := got["curlimages/curl"]; len(refs) != 1 || refs[0].Key != "PROJ-2" {
		t.Errorf("second page missing: %+v", refs)
	}
	if got["curlimages/curl"][0].Status != "In Progress" {
		t.Errorf("status not carried: %+v", got["curlimages/curl"][0])
	}

	// Only open tickets: a Done ticket must not suppress or mislabel current work.
	if !strings.Contains(gotJQL, "statusCategory != Done") {
		t.Errorf("jql does not exclude Done: %s", gotJQL)
	}
	// The configurable field has to be requested explicitly or Jira omits it.
	if !strings.Contains(gotFields, "customfield_20983") {
		t.Errorf("fields did not request the image field: %s", gotFields)
	}
}

// With labels instead of a custom field, the sanitised label has to be converted
// back to a repository or nothing would ever match a finding.
func TestOpenByImageReadsLabelFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("fields"), "labels") {
			t.Errorf("label mode should request labels: %s", r.URL.Query().Get("fields"))
		}
		_, _ = w.Write([]byte(`{"issues":[
		  {"key":"PROJ-9","fields":{"summary":"x",
		    "status":{"name":"To Do","statusCategory":{"key":"new"}},
		    "labels":["patchwright-fluxcd_source-controller","unrelated"]}}
		],"isLast":true}`))
	}))
	defer srv.Close()

	j := &Jira{BaseURL: srv.URL, Client: srv.Client(),
		cfg: config.JiraConfig{Project: "PROJ", ImageLabel: true}}
	got, err := j.OpenByImage(context.Background())
	if err != nil {
		t.Fatalf("OpenByImage: %v", err)
	}
	if refs := got["fluxcd/source-controller"]; len(refs) != 1 {
		t.Errorf("label not converted back to a repository: %+v", got)
	}
	if _, ok := got["unrelated"]; ok {
		t.Error("labels that are not ours must be ignored")
	}
}

func TestRepoFromLabel(t *testing.T) {
	if repo, ok := repoFromLabel("patchwright-fluxcd_source-controller"); !ok || repo != "fluxcd/source-controller" {
		t.Errorf("got %q %v", repo, ok)
	}
	if _, ok := repoFromLabel("change-requested"); ok {
		t.Error("a foreign label must not be read as one of ours")
	}
}

// Guard the response shape this depends on: Jira omits an unrequested field, so a
// silent typo in the field name would produce an empty index rather than an error.
func TestOpenByImageIgnoresIssuesWithoutTheField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issues":[{"key":"PROJ-3","fields":{
		  "summary":"no image field","status":{"name":"To Do","statusCategory":{"key":"new"}}}}],
		  "isLast":true}`))
	}))
	defer srv.Close()
	j := &Jira{BaseURL: srv.URL, Client: srv.Client(),
		cfg: config.JiraConfig{Project: "PROJ", ImageField: "customfield_1"}}
	got, err := j.OpenByImage(context.Background())
	if err != nil {
		t.Fatalf("OpenByImage: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want an empty index", got)
	}
}
