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
	if err := ts.jira(t, baseCfg()).Close(context.Background(), CloseRequest{Key: "PROJ-1", Comment: "because"}); err != nil {
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
		if err := ts.jira(t, cfg).Close(context.Background(), CloseRequest{Key: "PROJ-1", Comment: "because"}); err != nil {
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
	err := ts.jira(t, baseCfg()).Close(context.Background(), CloseRequest{Key: "PROJ-1", Comment: "because"})
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
	err := ts.jira(t, baseCfg()).Close(context.Background(), CloseRequest{Key: "PROJ-1", Comment: "because"})
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
	err := ts.jira(t, cfg).Close(context.Background(), CloseRequest{Key: "PROJ-1", Comment: "because"})
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

	if err := j.Close(context.Background(), CloseRequest{Key: "SRE-7", Comment: "because"}); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tr, _ := ts.posted["transition"].(map[string]any)
	if tr["id"] != "41" {
		t.Errorf("SRE ticket transitioned with id %v, want 41 (its route's transition)", tr["id"])
	}

	ts.posted = nil
	if err := j.Close(context.Background(), CloseRequest{Key: "PROJ-7", Comment: "because"}); err != nil {
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
	if err := j.Close(context.Background(), CloseRequest{Key: "PROJ-1", Comment: "because reasons"}); err != nil {
		t.Fatalf("Close failed instead of retrying without the comment: %v", err)
	}
	if posts != 2 {
		t.Errorf("made %d transition attempts, want 2 (with, then without, the comment)", posts)
	}
	if !sawComment {
		t.Error("the reasoning was lost: no comment posted after the bare transition")
	}
}

// commentServer records posted comments and serves them back, so a second run
// sees what the first one wrote.
type commentServer struct {
	posted []string
	gets   int
}

func (cs *commentServer) jira(t *testing.T) *Jira {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			cs.gets++
			comments := make([]map[string]any, 0, len(cs.posted))
			for _, body := range cs.posted {
				comments = append(comments, map[string]any{
					"id": "1", "body": ADFDocument(body),
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"startAt": 0, "maxResults": 100, "total": len(comments), "comments": comments,
			})
			return
		}
		var body struct {
			Body map[string]any `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		cs.posted = append(cs.posted, flattenADF(body.Body))
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	cfg := baseCfg()
	return &Jira{BaseURL: srv.URL, Email: "e", Token: "t", Client: srv.Client(),
		cfg: cfg, byRoute: map[string]config.JiraConfig{routeName: cfg}}
}

// flattenADF pulls the text out of an ADF document, which is how the marker is
// found in a real response too.
func flattenADF(doc map[string]any) string {
	raw, _ := json.Marshal(doc)
	return string(raw)
}

// The bug: reconciliation runs on a loop, so a note-done posted every refresh
// buries the ticket's own history and trains people to ignore the tool.
func TestCommentOncePostsOnlyOnce(t *testing.T) {
	cs := &commentServer{}
	j := cs.jira(t)

	posted, err := j.CommentOnce(context.Background(), "PROJ-1", "note-done", "the work looks done")
	if err != nil || !posted {
		t.Fatalf("first call: posted=%v err=%v", posted, err)
	}
	// Simulate the next hourly refresh, and the ten after it.
	for i := 0; i < 10; i++ {
		posted, err = j.CommentOnce(context.Background(), "PROJ-1", "note-done", "the work looks done")
		if err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
		if posted {
			t.Fatalf("refresh %d posted a duplicate comment", i)
		}
	}
	if len(cs.posted) != 1 {
		t.Errorf("ticket has %d comments, want 1", len(cs.posted))
	}
}

// A note whose content genuinely changed is worth saying again: the upgrade target
// moving is news, the same target is not.
func TestCommentOncePostsAgainWhenTheContentChanges(t *testing.T) {
	cs := &commentServer{}
	j := cs.jira(t)

	if _, err := j.CommentOnce(context.Background(), "PROJ-1", "note-stale:3.1.0", "now at 3.1.0"); err != nil {
		t.Fatal(err)
	}
	posted, err := j.CommentOnce(context.Background(), "PROJ-1", "note-stale:3.2.0", "now at 3.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if !posted {
		t.Error("a changed target did not produce a new comment")
	}
	if len(cs.posted) != 2 {
		t.Errorf("ticket has %d comments, want 2", len(cs.posted))
	}
}

// An empty dedupe means "always post", which is what the extend explanation wants:
// it only happens when the images actually changed.
func TestCommentOnceWithoutADedupeAlwaysPosts(t *testing.T) {
	cs := &commentServer{}
	j := cs.jira(t)
	for i := 0; i < 3; i++ {
		posted, err := j.CommentOnce(context.Background(), "PROJ-1", "", "adding images")
		if err != nil || !posted {
			t.Fatalf("call %d: posted=%v err=%v", i, posted, err)
		}
	}
	if len(cs.posted) != 3 {
		t.Errorf("posted %d comments, want 3", len(cs.posted))
	}
	if cs.gets != 0 {
		t.Errorf("read comments %d times for an undeduplicated post", cs.gets)
	}
}

// The marker has to survive the round trip, or every run reposts.
func TestTheDedupeMarkerIsPresentInWhatWasPosted(t *testing.T) {
	cs := &commentServer{}
	j := cs.jira(t)
	if _, err := j.CommentOnce(context.Background(), "PROJ-1", "note-done", "body text"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cs.posted[0], commentRef("note-done")) {
		t.Errorf("posted comment does not carry its reference: %s", cs.posted[0])
	}
}

// The metric's operation label is built from the path, so it must not carry issue
// keys: one series per ticket, forever, is a metrics incident rather than
// observability.
func TestJiraOperationLabelIsBounded(t *testing.T) {
	for _, tc := range []struct{ method, path, want string }{
		{"GET", "/rest/api/3/issue/PROJ-123?fields=status", "get issue"},
		{"GET", "/rest/api/3/issue/PROJ-999999", "get issue"},
		{"PUT", "/rest/api/3/issue/PROJ-1", "put issue"},
		{"POST", "/rest/api/3/issue", "post issue"},
		{"POST", "/rest/api/3/issue/PROJ-1/comment", "post issue/comment"},
		{"GET", "/rest/api/3/issue/PROJ-1/transitions", "get issue/transitions"},
		{"POST", "/rest/api/3/issue/PROJ-1/transitions", "post issue/transitions"},
		{"GET", "/rest/api/3/search/jql?jql=project+%3D+%22PROJ%22", "get search"},
	} {
		if got := jiraOperation(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s -> %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
	// Two different tickets must produce one label, not two.
	a := jiraOperation("GET", "/rest/api/3/issue/PROJ-1")
	b := jiraOperation("GET", "/rest/api/3/issue/OTHER-42")
	if a != b {
		t.Errorf("issue keys leaked into the label: %q vs %q", a, b)
	}
}

// One real workflow, as observed: from NEEDS REFINEMENT the only closing transition
// is "WON'T BE DONE". For a ticket nobody picked up that is an accurate record — the
// upgrade landed by another route — so it is allowed.
func TestUnworkedTicketClosesViaTheUnworkedTransition(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("21", "Story Refined", "To Do", "indeterminate"),
		transition("51", "WON'T BE DONE", "WON'T BE DONE", "done"),
	}}
	cfg := baseCfg()
	cfg.CloseTransition = "Done"
	cfg.CloseTransitionUnworked = "WON'T BE DONE"

	err := ts.jira(t, cfg).Close(context.Background(), CloseRequest{
		Key: "PROJ-1", Comment: "because", Unworked: true,
	})
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	tr, _ := ts.posted["transition"].(map[string]any)
	if tr["id"] != "51" {
		t.Errorf("transitioned with id %v, want 51 (the unworked transition)", tr["id"])
	}
}

// The same workflow, but somebody worked the ticket: recording their work as "won't
// be done" would misrepresent it, so this still fails loudly.
func TestWorkedTicketWillNotUseTheUnworkedTransition(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("51", "WON'T BE DONE", "WON'T BE DONE", "done"),
	}}
	cfg := baseCfg()
	cfg.CloseTransition = "Done"
	cfg.CloseTransitionUnworked = "WON'T BE DONE"

	err := ts.jira(t, cfg).Close(context.Background(), CloseRequest{
		Key: "PROJ-1", Comment: "because", Unworked: false,
	})
	if err == nil {
		t.Fatal("a worked ticket was closed as won't-be-done")
	}
	for _, want := range []string{`no transition named "Done"`, "WON'T BE DONE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
	if ts.posted != nil {
		t.Errorf("posted a transition anyway: %v", ts.posted)
	}
}

// "Done" is the truer statement about finished work, so it wins wherever it is
// available — even on a ticket nobody touched.
func TestPreferredTransitionWinsForUnworkedTickets(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("31", "Done", "Done", "done"),
		transition("51", "WON'T BE DONE", "WON'T BE DONE", "done"),
	}}
	cfg := baseCfg()
	cfg.CloseTransition = "Done"
	cfg.CloseTransitionUnworked = "WON'T BE DONE"

	if err := ts.jira(t, cfg).Close(context.Background(), CloseRequest{
		Key: "PROJ-1", Comment: "because", Unworked: true,
	}); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tr, _ := ts.posted["transition"].(map[string]any)
	if tr["id"] != "31" {
		t.Errorf("transitioned with id %v, want 31 (Done)", tr["id"])
	}
}

// A ticket closed as not-worked that keeps its original priority still appears in
// every "highest priority" filter until somebody notices it is closed.
func TestUnworkedCloseClearsThePriority(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("51", "WON'T BE DONE", "WON'T BE DONE", "done"),
	}}
	cfg := baseCfg()
	cfg.CloseTransition = "Done"
	cfg.CloseTransitionUnworked = "WON'T BE DONE"
	cfg.ClosePriorityUnworked = "Unprioritised"

	if err := ts.jira(t, cfg).Close(context.Background(), CloseRequest{
		Key: "PROJ-1", Comment: "because", Unworked: true,
	}); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fields, ok := ts.posted["fields"].(map[string]any)
	if !ok {
		t.Fatalf("transition carried no fields: %v", ts.posted)
	}
	pri, _ := fields["priority"].(map[string]any)
	if pri["name"] != "Unprioritised" {
		t.Errorf("priority = %v, want Unprioritised", pri["name"])
	}
}

// Work somebody completed keeps the priority it was triaged at: that is a record of
// how urgent it was, not noise to clear.
func TestCloseViaDoneLeavesThePriorityAlone(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("31", "Done", "Done", "done"),
		transition("51", "WON'T BE DONE", "WON'T BE DONE", "done"),
	}}
	cfg := baseCfg()
	cfg.CloseTransition = "Done"
	cfg.CloseTransitionUnworked = "WON'T BE DONE"
	cfg.ClosePriorityUnworked = "Unprioritised"

	// Unworked, but Done is available and wins — so the priority stays.
	if err := ts.jira(t, cfg).Close(context.Background(), CloseRequest{
		Key: "PROJ-1", Comment: "because", Unworked: true,
	}); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := ts.posted["fields"]; ok {
		t.Errorf("a close via Done changed the priority: %v", ts.posted)
	}
}

// Without the setting, nothing touches priority — enabling the unworked transition
// must not silently start editing fields.
func TestUnworkedCloseWithoutAPriorityLeavesItAlone(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("51", "WON'T BE DONE", "WON'T BE DONE", "done"),
	}}
	cfg := baseCfg()
	cfg.CloseTransition = "Done"
	cfg.CloseTransitionUnworked = "WON'T BE DONE"

	if err := ts.jira(t, cfg).Close(context.Background(), CloseRequest{
		Key: "PROJ-1", Comment: "because", Unworked: true,
	}); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := ts.posted["fields"]; ok {
		t.Errorf("priority was changed without being configured: %v", ts.posted)
	}
}

// A transition screen that rejects fields must still close the ticket, with the
// priority applied separately rather than lost.
func TestPriorityIsAppliedSeparatelyWhenTheScreenRejectsIt(t *testing.T) {
	var transitions, edits int
	var editedPriority string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"transitions": []map[string]any{
				transition("51", "WON'T BE DONE", "WON'T BE DONE", "done"),
			}})
		case r.Method == http.MethodPut:
			edits++
			var body struct {
				Fields struct {
					Priority struct{ Name string } `json:"priority"`
				} `json:"fields"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			editedPriority = body.Fields.Priority.Name
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/comment"):
			w.WriteHeader(http.StatusCreated)
		default:
			transitions++
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			// Reject anything carrying extra fields, as a restrictive screen would.
			if _, ok := body["fields"]; ok {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errorMessages":["Field 'priority' cannot be set"]}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	cfg := baseCfg()
	cfg.CloseTransitionUnworked = "WON'T BE DONE"
	cfg.ClosePriorityUnworked = "Unprioritised"
	j := &Jira{BaseURL: srv.URL, Email: "e", Token: "t", Client: srv.Client(),
		cfg: cfg, byRoute: map[string]config.JiraConfig{routeName: cfg}}

	if err := j.Close(context.Background(), CloseRequest{
		Key: "PROJ-1", Comment: "because", Unworked: true,
	}); err != nil {
		t.Fatalf("Close failed instead of retrying without the fields: %v", err)
	}
	if transitions != 2 {
		t.Errorf("made %d transition attempts, want 2 (with, then without, the fields)", transitions)
	}
	if edits != 1 || editedPriority != "Unprioritised" {
		t.Errorf("priority not applied separately: edits=%d priority=%q", edits, editedPriority)
	}
}
