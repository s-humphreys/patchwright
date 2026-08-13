package ticket

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

func draft(summary string, images []string, latest string) Draft {
	ups := make([]ImageUpgrade, 0, len(images))
	for _, img := range images {
		ups = append(ups, ImageUpgrade{Repo: img, Current: "1.0.0", Latest: latest})
	}
	return Draft{Summary: summary, Images: images, Upgrades: ups}
}

func assessed(repo string) sink.FindingView {
	return sink.FindingView{Repository: repo, ProviderAssessed: true}
}

func kinds(actions []Action) []ActionKind {
	out := make([]ActionKind, len(actions))
	for i, a := range actions {
		out[i] = a.Kind
	}
	return out
}

// Nothing open: raise it.
func TestReconcileCreatesWhenNothingCoversTheImages(t *testing.T) {
	got := Reconcile(ReconcileInput{
		Drafts:      []Draft{draft("Upgrade app to 2.0.0", []string{"acme/app"}, "2.0.0")},
		OpenByImage: map[string][]Existing{},
	})
	if len(got) != 1 || got[0].Kind != ActionCreate {
		t.Fatalf("got %v, want one create", kinds(got))
	}
}

// The nats case, which is the reason this exists: a ticket covering one image of a
// change suppressed the other two, leaving them with no ticket at all.
func TestReconcileExtendsATicketThatCoversPartOfTheChange(t *testing.T) {
	d := draft("Upgrade event-bus images (3)", []string{"a/nats", "a/reloader", "a/exporter"}, "2.0.0")
	got := Reconcile(ReconcileInput{
		Drafts: []Draft{d},
		OpenByImage: map[string][]Existing{
			"a/exporter": {{Key: "PROJ-1", Status: "To Do", Summary: "Upgrade exporter to 1.0.0"}},
		},
		Findings: []sink.FindingView{assessed("a/nats"), assessed("a/reloader"), assessed("a/exporter")},
	})
	if len(got) != 1 || got[0].Kind != ActionExtend {
		t.Fatalf("got %v, want one extend", kinds(got))
	}
	if got[0].TicketKey != "PROJ-1" {
		t.Errorf("ticket = %q, want PROJ-1", got[0].TicketKey)
	}
	want := []string{"a/nats", "a/reloader"}
	if len(got[0].Images) != 2 || got[0].Images[0] != want[0] || got[0].Images[1] != want[1] {
		t.Errorf("images = %v, want %v", got[0].Images, want)
	}
	// The comment has to say why, or a reader sees images appear with no reason.
	if !strings.Contains(got[0].Message, "suppresses the rest") {
		t.Errorf("comment does not explain the gap: %s", got[0].Message)
	}
}

// Fully covered and current: do nothing, but say so rather than going silent.
func TestReconcileSkipsATicketThatAlreadyCoversTheChange(t *testing.T) {
	got := Reconcile(ReconcileInput{
		Drafts: []Draft{draft("Upgrade app to 2.0.0", []string{"acme/app"}, "2.0.0")},
		OpenByImage: map[string][]Existing{
			"acme/app": {{Key: "PROJ-2", Summary: "Upgrade app to 2.0.0"}},
		},
		Findings: []sink.FindingView{assessed("acme/app")},
	})
	if len(got) != 1 || got[0].Kind != ActionSkip {
		t.Fatalf("got %v, want one skip", kinds(got))
	}
}

// A ticket asking for a version that is no longer the available one is misleading
// by the time someone picks it up.
func TestReconcileNotesStaleTarget(t *testing.T) {
	got := Reconcile(ReconcileInput{
		Drafts: []Draft{draft("Upgrade app to 2.1.0", []string{"acme/app"}, "2.1.0")},
		OpenByImage: map[string][]Existing{
			"acme/app": {{Key: "PROJ-3", Summary: "Upgrade app to 2.0.0"}},
		},
		Findings: []sink.FindingView{assessed("acme/app")},
	})
	if len(got) != 1 || got[0].Kind != ActionNoteStale {
		t.Fatalf("got %v, want one note-stale", kinds(got))
	}
	if !strings.Contains(got[0].Message, "2.1.0") || !strings.Contains(got[0].Message, "2.0.0") {
		t.Errorf("comment should name both versions: %s", got[0].Message)
	}
}

// A grouped ticket's summary carries no single version, so there is nothing to
// compare and nothing should be claimed.
func TestReconcileDoesNotGuessStalenessForGroupedTickets(t *testing.T) {
	d := draft("Upgrade example images (2) to their latest versions",
		[]string{"acme/a", "acme/b"}, "2.0.0")
	got := Reconcile(ReconcileInput{
		Drafts: []Draft{d},
		OpenByImage: map[string][]Existing{
			"acme/a": {{Key: "PROJ-4", Summary: "Upgrade example images (2) to their latest versions"}},
			"acme/b": {{Key: "PROJ-4", Summary: "Upgrade example images (2) to their latest versions"}},
		},
		Findings: []sink.FindingView{assessed("acme/a"), assessed("acme/b")},
	})
	if len(got) != 1 || got[0].Kind != ActionSkip {
		t.Fatalf("got %v, want one skip", kinds(got))
	}
}

// Work that has left the queue is worth flagging, but never closing.
func TestReconcileNotesTicketsNoLongerInTheQueue(t *testing.T) {
	got := Reconcile(ReconcileInput{
		Drafts: nil,
		OpenByImage: map[string][]Existing{
			"acme/done": {{Key: "PROJ-5", Summary: "Upgrade done to 2.0.0"}},
		},
		Findings: []sink.FindingView{assessed("acme/done")},
	})
	if len(got) != 1 || got[0].Kind != ActionNoteDone {
		t.Fatalf("got %v, want one note-done", kinds(got))
	}
	if !strings.Contains(got[0].Message, "human decision") {
		t.Errorf("comment should leave closing to a person: %s", got[0].Message)
	}
}

// The distinction that stops this retiring real work: a finding can leave the queue
// because it was fixed, or because nothing is assessing the image any more.
func TestReconcileDistinguishesFixedFromNoLongerAssessed(t *testing.T) {
	got := Reconcile(ReconcileInput{
		OpenByImage: map[string][]Existing{
			"acme/blind": {{Key: "PROJ-6", Summary: "Upgrade blind to 2.0.0"}},
		},
		// Present, but neither assessed nor scanned: nothing has looked at it.
		Findings: []sink.FindingView{{Repository: "acme/blind"}},
	})
	if len(got) != 1 || got[0].Kind != ActionNoteDone {
		t.Fatalf("got %v, want one note-done", kinds(got))
	}
	if !strings.Contains(got[0].Message, "cannot tell") {
		t.Errorf("comment must not imply the work is done: %s", got[0].Message)
	}
	if !strings.Contains(got[0].Why, "coverage") {
		t.Errorf("reason should name the coverage problem: %s", got[0].Why)
	}
}

// Reconciliation never closes or transitions a ticket, whatever it concludes.
func TestReconcileNeverClosesAnything(t *testing.T) {
	all := Reconcile(ReconcileInput{
		Drafts: []Draft{draft("Upgrade app to 2.0.0", []string{"acme/app"}, "2.0.0")},
		OpenByImage: map[string][]Existing{
			"acme/gone": {{Key: "PROJ-7", Summary: "Upgrade gone to 1.0.0"}},
		},
		Findings: []sink.FindingView{assessed("acme/gone")},
	})
	for _, a := range all {
		switch a.Kind {
		case ActionCreate, ActionExtend, ActionNoteStale, ActionNoteDone, ActionSkip:
		default:
			t.Errorf("unexpected action kind %q: closing must stay a human decision", a.Kind)
		}
	}
}

// recorder captures applied actions without a Jira.
type recorder struct {
	created  []Draft
	extended map[string][]string
	comments map[string][]string
	updated  map[string]Draft
	failOn   ActionKind
}

func newRecorder() *recorder {
	return &recorder{extended: map[string][]string{}, comments: map[string][]string{},
		updated: map[string]Draft{}}
}

func (r *recorder) Update(_ context.Context, key string, d Draft) error {
	if r.failOn == ActionUpdate {
		return errors.New("boom")
	}
	r.updated[key] = d
	return nil
}

func (r *recorder) Create(_ context.Context, d Draft) (string, error) {
	if r.failOn == ActionCreate {
		return "", errors.New("boom")
	}
	r.created = append(r.created, d)
	return "PROJ-NEW", nil
}

func (r *recorder) AddImages(_ context.Context, key string, images []string) error {
	if r.failOn == ActionExtend {
		return errors.New("boom")
	}
	r.extended[key] = append(r.extended[key], images...)
	return nil
}

func (r *recorder) Comment(_ context.Context, key, body string) error {
	r.comments[key] = append(r.comments[key], body)
	return nil
}

func TestApplyPerformsEachActionKind(t *testing.T) {
	rec := newRecorder()
	results := Apply(context.Background(), rec, []Action{
		{Kind: ActionCreate, Draft: draft("new", []string{"a/b"}, "2.0.0")},
		{Kind: ActionExtend, TicketKey: "PROJ-1", Images: []string{"a/c"}, Message: "why"},
		{Kind: ActionNoteStale, TicketKey: "PROJ-2", Message: "moved on"},
		{Kind: ActionSkip, TicketKey: "PROJ-3"},
	})

	if len(rec.created) != 1 {
		t.Errorf("created %d, want 1", len(rec.created))
	}
	if got := rec.extended["PROJ-1"]; len(got) != 1 || got[0] != "a/c" {
		t.Errorf("extended = %v, want [a/c]", got)
	}
	// Extending must also explain itself.
	if len(rec.comments["PROJ-1"]) != 1 {
		t.Errorf("extend did not comment: %v", rec.comments)
	}
	if len(rec.comments["PROJ-2"]) != 1 {
		t.Errorf("stale note not posted: %v", rec.comments)
	}
	if len(rec.comments["PROJ-3"]) != 0 {
		t.Errorf("skip must do nothing, got %v", rec.comments["PROJ-3"])
	}
	if results[0].Key != "PROJ-NEW" {
		t.Errorf("created key = %q, want PROJ-NEW", results[0].Key)
	}
	if counts := Summarize(results); counts[ActionCreate] != 1 || counts[ActionSkip] != 1 {
		t.Errorf("summary = %v", counts)
	}
}

// One ticket failing must not strand the rest, and a failure must not be counted
// as done.
func TestApplyContinuesAfterAFailureAndDoesNotCountIt(t *testing.T) {
	rec := newRecorder()
	rec.failOn = ActionExtend
	results := Apply(context.Background(), rec, []Action{
		{Kind: ActionExtend, TicketKey: "PROJ-1", Images: []string{"a/c"}},
		{Kind: ActionNoteStale, TicketKey: "PROJ-2", Message: "moved on"},
	})
	if results[0].Err == nil {
		t.Error("expected the extend to fail")
	}
	if len(rec.comments["PROJ-2"]) != 1 {
		t.Error("a later action was skipped because an earlier one failed")
	}
	if counts := Summarize(results); counts[ActionExtend] != 0 {
		t.Errorf("a failed action was counted as done: %v", counts)
	}
}

// A failed image update must not be followed by a comment explaining a change that
// did not happen.
func TestApplyDoesNotExplainAnExtendThatFailed(t *testing.T) {
	rec := newRecorder()
	rec.failOn = ActionExtend
	Apply(context.Background(), rec, []Action{
		{Kind: ActionExtend, TicketKey: "PROJ-1", Images: []string{"a/c"}, Message: "why"},
	})
	if len(rec.comments["PROJ-1"]) != 0 {
		t.Errorf("commented despite the update failing: %v", rec.comments["PROJ-1"])
	}
}

// A stale ticket nobody has picked up is corrected in place: leaving a wrong
// summary with the right answer in a comment underneath wastes the reader's time
// twice.
func TestStaleTicketIsRewrittenWhenUntouched(t *testing.T) {
	d := draft("Upgrade app to 1.2", []string{"acr.io/app"}, "1.2")
	actions := Reconcile(ReconcileInput{
		Drafts: []Draft{d},
		OpenByImage: map[string][]Existing{
			"acr.io/app": {{
				Key: "PROJ-1", Summary: "Upgrade app to 1.1",
				Status: "To Do", Category: "new", Assigned: false,
			}},
		},
	})
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want 1: %+v", len(actions), actions)
	}
	a := actions[0]
	if a.Kind != ActionUpdate {
		t.Fatalf("kind = %q, want %q", a.Kind, ActionUpdate)
	}
	if a.TicketKey != "PROJ-1" {
		t.Errorf("ticket = %q", a.TicketKey)
	}
	// The fresh draft has to travel with the action, or the write has nothing to
	// write.
	if a.Draft.Summary == "" {
		t.Error("update action carries no draft, so there is no new content")
	}
}

// Once someone has engaged with a ticket, editing it would change the task after
// they read it, so it is commented on instead.
func TestStaleTicketIsOnlyCommentedOnWhenTouched(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing Existing
	}{
		{"assigned but not started", Existing{
			Key: "PROJ-1", Summary: "Upgrade app to 1.1",
			Category: "new", Assigned: true,
		}},
		{"in progress and unassigned", Existing{
			Key: "PROJ-1", Summary: "Upgrade app to 1.1",
			Category: "indeterminate", Assigned: false,
		}},
		{"in progress and assigned", Existing{
			Key: "PROJ-1", Summary: "Upgrade app to 1.1",
			Category: "indeterminate", Assigned: true,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actions := Reconcile(ReconcileInput{
				Drafts:      []Draft{draft("Upgrade app to 1.2", []string{"acr.io/app"}, "1.2")},
				OpenByImage: map[string][]Existing{"acr.io/app": {tc.existing}},
			})
			if len(actions) != 1 {
				t.Fatalf("got %d actions: %+v", len(actions), actions)
			}
			if actions[0].Kind != ActionNoteStale {
				t.Errorf("kind = %q, want %q: an engaged ticket must not be rewritten",
					actions[0].Kind, ActionNoteStale)
			}
			if actions[0].Message == "" {
				t.Error("no comment body, so the drift would go unreported")
			}
		})
	}
}

// Untouched is a conjunction, and both halves matter on real boards.
func TestUntouched(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    Existing
		want bool
	}{
		{"unassigned and to do", Existing{Category: "new"}, true},
		{"assigned and to do", Existing{Category: "new", Assigned: true}, false},
		{"unassigned and in progress", Existing{Category: "indeterminate"}, false},
		{"done", Existing{Category: "done"}, false},
		{"no category reported", Existing{}, false},
	} {
		if got := tc.e.Untouched(); got != tc.want {
			t.Errorf("%s: Untouched() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Apply has to route the new kind to the write, or a planned update silently
// does nothing.
func TestApplyPerformsUpdates(t *testing.T) {
	rec := newRecorder()
	d := draft("Upgrade app to 1.2", []string{"acr.io/app"}, "1.2")
	results := Apply(context.Background(), rec, []Action{
		{Kind: ActionUpdate, TicketKey: "PROJ-1", Draft: d},
	})
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("results = %+v", results)
	}
	got, ok := rec.updated["PROJ-1"]
	if !ok {
		t.Fatalf("no update recorded; updated = %v", rec.updated)
	}
	if got.Summary != d.Summary {
		t.Errorf("updated with summary %q, want %q", got.Summary, d.Summary)
	}
	if len(rec.comments["PROJ-1"]) != 0 {
		t.Errorf("an update also posted a comment: %v", rec.comments["PROJ-1"])
	}
}
