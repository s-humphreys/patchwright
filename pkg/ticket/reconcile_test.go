package ticket

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
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
	closed   map[string]string
	failOn   ActionKind
}

func newRecorder() *recorder {
	return &recorder{extended: map[string][]string{}, comments: map[string][]string{},
		updated: map[string]Draft{}, closed: map[string]string{}}
}

func (r *recorder) Close(_ context.Context, key, comment string) error {
	if r.failOn == ActionClose {
		return errors.New("boom")
	}
	r.closed[key] = comment
	return nil
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

// onLatest builds a finding for a repository that is demonstrably already on its
// latest version: remediation checked, versions resolved, nothing available, and
// liveness reconciled.
// autoCloseCfg is the minimum configuration that permits closing.
func autoCloseCfg() config.JiraConfig {
	return config.JiraConfig{Project: "PROJ", AutoClose: true}
}

func onLatest(repo, version string) sink.FindingView {
	return sink.FindingView{
		Repository: repo, Tag: version, ProviderAssessed: true, RemediationChecked: true,
		Liveness: &sink.LivenessView{Live: true},
		Upgrade: &sink.UpgradeView{
			Kind: "image", Current: version, Latest: version, Resolved: true, Available: false,
		},
	}
}

// The case this exists for: someone merged the Renovate PR and rolled it out
// without ever seeing the ticket.
func TestClosesATicketWhoseWorkIsProvablyDone(t *testing.T) {
	actions := Reconcile(ReconcileInput{
		Config:      autoCloseCfg(),
		Findings:    []sink.FindingView{onLatest("acme/app", "2.0.0")},
		OpenByImage: map[string][]Existing{"acme/app": {{Key: "PROJ-1", Category: "new"}}},
	})
	if len(actions) != 1 {
		t.Fatalf("got %d actions: %+v", len(actions), actions)
	}
	if actions[0].Kind != ActionClose {
		t.Fatalf("kind = %q, want %q", actions[0].Kind, ActionClose)
	}
	// The comment must state the evidence, so a human reading the closed ticket
	// can check the reasoning rather than take it on trust.
	for _, want := range []string{"acme/app is on 2.0.0", "Checked, not assumed"} {
		if !strings.Contains(actions[0].Message, want) {
			t.Errorf("close comment does not mention %q: %s", want, actions[0].Message)
		}
	}
}

// Without the flag the same evidence must only comment. Closing tickets is not a
// behaviour anyone should acquire by upgrading.
func TestDoesNotCloseWhenAutoCloseIsOff(t *testing.T) {
	actions := Reconcile(ReconcileInput{
		Findings:    []sink.FindingView{onLatest("acme/app", "2.0.0")},
		OpenByImage: map[string][]Existing{"acme/app": {{Key: "PROJ-1"}}},
	})
	if len(actions) != 1 || actions[0].Kind != ActionNoteDone {
		t.Fatalf("actions = %+v, want a single note-done", actions)
	}
}

// Each guard, alone, must be enough to stop a close. These are the ways "it looks
// done" is not the same as "it is done".
func TestCloseGuards(t *testing.T) {
	for _, tc := range []struct {
		name    string
		finding func() sink.FindingView
	}{
		{"remediation never ran", func() sink.FindingView {
			f := onLatest("acme/app", "2.0.0")
			f.RemediationChecked = false
			return f
		}},
		{"versions could not be resolved", func() sink.FindingView {
			f := onLatest("acme/app", "2.0.0")
			f.Upgrade.Resolved = false
			return f
		}},
		{"an upgrade is still available", func() sink.FindingView {
			f := onLatest("acme/app", "2.0.0")
			f.Upgrade.Available = true
			f.Upgrade.Latest = "2.1.0"
			return f
		}},
		{"liveness was never reconciled", func() sink.FindingView {
			f := onLatest("acme/app", "2.0.0")
			f.Liveness = nil
			return f
		}},
		{"no upgrade information at all", func() sink.FindingView {
			f := onLatest("acme/app", "2.0.0")
			f.Upgrade = nil
			return f
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actions := Reconcile(ReconcileInput{
				Config:      autoCloseCfg(),
				Findings:    []sink.FindingView{tc.finding()},
				OpenByImage: map[string][]Existing{"acme/app": {{Key: "PROJ-1"}}},
			})
			for _, a := range actions {
				if a.Kind == ActionClose {
					t.Errorf("closed despite %s: %+v", tc.name, a)
				}
			}
		})
	}
}

// A repository absent from the assessment is the ambiguous case the whole design
// refuses to close on: it cannot be told from a provider that stopped looking.
func TestDoesNotCloseWhenTheImageIsNoLongerReported(t *testing.T) {
	actions := Reconcile(ReconcileInput{
		Config:      autoCloseCfg(),
		Findings:    []sink.FindingView{onLatest("acme/other", "1.0.0")},
		OpenByImage: map[string][]Existing{"acme/app": {{Key: "PROJ-1"}}},
	})
	if len(actions) != 1 || actions[0].Kind != ActionNoteDone {
		t.Fatalf("actions = %+v, want note-done for an unreported image", actions)
	}
	if !strings.Contains(actions[0].Message, "cannot tell") {
		t.Errorf("comment does not admit the ambiguity: %s", actions[0].Message)
	}
}

// A ticket covering several images is only done when every one of them is.
func TestDoesNotCloseWhileAnyCoveredImageLags(t *testing.T) {
	lagging := onLatest("acme/two", "1.0.0")
	lagging.Upgrade.Available = true
	lagging.Upgrade.Latest = "1.1.0"
	ticketRef := Existing{Key: "PROJ-1"}
	actions := Reconcile(ReconcileInput{
		Config:   autoCloseCfg(),
		Findings: []sink.FindingView{onLatest("acme/one", "2.0.0"), lagging},
		OpenByImage: map[string][]Existing{
			"acme/one": {ticketRef}, "acme/two": {ticketRef},
		},
	})
	for _, a := range actions {
		if a.Kind == ActionClose {
			t.Errorf("closed while acme/two still has an upgrade available: %+v", a)
		}
	}
}

// An old tag still running somewhere means the rollout is incomplete, even though
// another finding for the same repository is on the latest version.
func TestDoesNotCloseWhenAnOldTagIsStillRunning(t *testing.T) {
	old := onLatest("acme/app", "1.0.0")
	old.Upgrade.Available = true
	old.Upgrade.Latest = "2.0.0"
	actions := Reconcile(ReconcileInput{
		Config:      autoCloseCfg(),
		Findings:    []sink.FindingView{onLatest("acme/app", "2.0.0"), old},
		OpenByImage: map[string][]Existing{"acme/app": {{Key: "PROJ-1"}}},
	})
	for _, a := range actions {
		if a.Kind == ActionClose {
			t.Errorf("closed while 1.0.0 is still running: %+v", a)
		}
	}
}

func TestApplyPerformsCloses(t *testing.T) {
	rec := newRecorder()
	results := Apply(context.Background(), rec, []Action{
		{Kind: ActionClose, TicketKey: "PROJ-1", Message: "done because reasons"},
	})
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("results = %+v", results)
	}
	if got := rec.closed["PROJ-1"]; got != "done because reasons" {
		t.Errorf("closed with comment %q", got)
	}
}

// Closing is per-tracker: a route can automate it for its own board without
// automating it everywhere. Resolved by the ticket's project, because that is the
// board it is actually on.
func TestAutoCloseIsResolvedPerProject(t *testing.T) {
	yes, no := true, false
	cfg := config.JiraConfig{
		Project: "DVOP", AutoClose: false,
		Routes: []config.TicketRoute{
			{Name: "sre", When: "true", Project: "SRE", AutoClose: &yes},
			{Name: "locked", When: "true", Project: "LOCKED", AutoClose: &no},
		},
	}
	for _, tc := range []struct {
		key       string
		wantClose bool
	}{
		{"SRE-1", true},     // its route opts in
		{"DVOP-1", false},   // base has it off
		{"LOCKED-1", false}, // its route opts out explicitly
		{"OTHER-1", false},  // unknown project falls back to the base
	} {
		actions := Reconcile(ReconcileInput{
			Config:      cfg,
			Findings:    []sink.FindingView{onLatest("acme/app", "2.0.0")},
			OpenByImage: map[string][]Existing{"acme/app": {{Key: tc.key}}},
		})
		var closed bool
		for _, a := range actions {
			if a.Kind == ActionClose {
				closed = true
			}
		}
		if closed != tc.wantClose {
			t.Errorf("%s: closed = %v, want %v", tc.key, closed, tc.wantClose)
		}
	}
}
