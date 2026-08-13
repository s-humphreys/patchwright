package ticket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
)

// transitionServer serves a transition list and records the transition posted.
type transitionServer struct {
	transitions []map[string]any
	posted      map[string]any
	status      int
}

func (ts *transitionServer) jira(t *testing.T, cfg config.JiraConfig) *Jira {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"transitions": ts.transitions})
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&ts.posted)
		if ts.status != 0 {
			w.WriteHeader(ts.status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return &Jira{BaseURL: srv.URL, Email: "e", Token: "t", Client: srv.Client(),
		cfg: cfg, byRoute: map[string]config.JiraConfig{routeName: cfg}}
}

func transition(id, name, toName, category string) map[string]any {
	return map[string]any{"id": id, "name": name,
		"to": map[string]any{"name": toName, "statusCategory": map[string]any{"key": category}}}
}

func baseCfg() config.JiraConfig {
	return config.JiraConfig{Board: 1, Project: "PROJ", Template: "t", ImageField: "customfield_1"}
}

func TestCloseUsesTheOnlyDoneTransition(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("11", "In Progress", "In Progress", "indeterminate"),
		transition("31", "Done", "Done", "done"),
	}}
	if err := ts.jira(t, baseCfg()).Close(context.Background(), "PROJ-1", "because"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tr, _ := ts.posted["transition"].(map[string]any)
	if tr["id"] != "31" {
		t.Errorf("transitioned with id %v, want 31 (the done one)", tr["id"])
	}
	// The comment must ride along in the same request, so an explanation cannot
	// arrive without the transition or the reverse.
	if _, ok := ts.posted["update"]; !ok {
		t.Error("no comment accompanied the transition")
	}
}

// Boards label these inconsistently, so a configured name is matched against both
// the transition and its target status.
func TestCloseHonoursTheConfiguredTransitionName(t *testing.T) {
	for _, name := range []string{"Resolve Issue", "resolve issue", "Complete"} {
		ts := &transitionServer{transitions: []map[string]any{
			transition("31", "Done", "Done", "done"),
			transition("41", "Resolve Issue", "Complete", "done"),
		}}
		cfg := baseCfg()
		cfg.CloseTransition = name
		if err := ts.jira(t, cfg).Close(context.Background(), "PROJ-1", "because"); err != nil {
			t.Fatalf("%q: Close: %v", name, err)
		}
		tr, _ := ts.posted["transition"].(map[string]any)
		if tr["id"] != "41" {
			t.Errorf("%q: transitioned with id %v, want 41", name, tr["id"])
		}
	}
}

// "Done" and "Won't Do" say very different things about the same work, so an
// ambiguous workflow is refused rather than guessed at.
func TestCloseRefusesAmbiguousWorkflows(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("31", "Done", "Done", "done"),
		transition("32", "Won't Do", "Won't Do", "done"),
	}}
	err := ts.jira(t, baseCfg()).Close(context.Background(), "PROJ-1", "because")
	if err == nil {
		t.Fatal("closed a ticket whose workflow has two ways to finish")
	}
	for _, want := range []string{"Won't Do", "closeTransition"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
	if ts.posted != nil {
		t.Errorf("posted a transition anyway: %v", ts.posted)
	}
}

func TestCloseReportsWhenNothingCanFinishTheTicket(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("11", "Start", "In Progress", "indeterminate"),
	}}
	err := ts.jira(t, baseCfg()).Close(context.Background(), "PROJ-1", "because")
	if err == nil || !strings.Contains(err.Error(), "no transition into a done status") {
		t.Fatalf("err = %v", err)
	}
	// The available transitions are listed, because the fix is to name one.
	if !strings.Contains(err.Error(), "Start -> In Progress") {
		t.Errorf("error does not list what was available: %v", err)
	}
}

func TestCloseReportsAMissingNamedTransition(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("31", "Done", "Done", "done"),
	}}
	cfg := baseCfg()
	cfg.CloseTransition = "Ship It"
	err := ts.jira(t, cfg).Close(context.Background(), "PROJ-1", "because")
	if err == nil || !strings.Contains(err.Error(), `no transition named "Ship It"`) {
		t.Fatalf("err = %v", err)
	}
	// Falling back to the done transition would close tickets through a workflow
	// step the operator did not choose.
	if ts.posted != nil {
		t.Errorf("fell back to another transition: %v", ts.posted)
	}
}

// A transition named in a route governs that route's board, so one project's
// workflow name is never imposed on another's.
func TestCloseUsesTheRoutesTransitionForItsOwnProject(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("31", "Done", "Done", "done"),
		transition("41", "Ship It", "Shipped", "done"),
	}}
	cfg := baseCfg()
	cfg.CloseTransition = "Done"
	cfg.Routes = []config.TicketRoute{
		{Name: "sre", When: "true", Project: "SRE", CloseTransition: "Ship It"},
	}
	j := ts.jira(t, cfg)
	// Rebuild the route index the way NewJira would, so cfgForKey can resolve it.
	j.byRoute = map[string]config.JiraConfig{routeName: cfg}
	for _, r := range cfg.Routes {
		j.byRoute[r.Name] = cfg.Resolve(r)
	}

	if err := j.Close(context.Background(), "SRE-7", "because"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tr, _ := ts.posted["transition"].(map[string]any)
	if tr["id"] != "41" {
		t.Errorf("SRE ticket transitioned with id %v, want 41 (its route's transition)", tr["id"])
	}

	ts.posted = nil
	if err := j.Close(context.Background(), "PROJ-7", "because"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tr, _ = ts.posted["transition"].(map[string]any)
	if tr["id"] != "31" {
		t.Errorf("base ticket transitioned with id %v, want 31", tr["id"])
	}
}

// A workflow that rejects a comment supplied with the transition must still close,
// with the reasoning posted separately rather than lost.
func TestCloseFallsBackWhenTheWorkflowRejectsTheComment(t *testing.T) {
	var posts int
	var sawComment bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"transitions": []map[string]any{
				transition("31", "Done", "Done", "done"),
			}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/comment") {
			sawComment = true
			w.WriteHeader(http.StatusCreated)
			return
		}
		posts++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		// Reject only the attempt carrying a comment, as a transition screen with
		// required fields would.
		if _, ok := body["update"]; ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errorMessages":["Field 'comment' cannot be set"]}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := baseCfg()
	j := &Jira{BaseURL: srv.URL, Email: "e", Token: "t", Client: srv.Client(),
		cfg: cfg, byRoute: map[string]config.JiraConfig{routeName: cfg}}
	if err := j.Close(context.Background(), "PROJ-1", "because reasons"); err != nil {
		t.Fatalf("Close failed instead of retrying without the comment: %v", err)
	}
	if posts != 2 {
		t.Errorf("made %d transition attempts, want 2 (with, then without, the comment)", posts)
	}
	if !sawComment {
		t.Error("the reasoning was lost: no comment posted after the bare transition")
	}
}
