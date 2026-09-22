package ticket

import (
	"context"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Closing a ticket because its work stopped mattering, rather than because it was
// done. Opt-in per project, untouched tickets only, and never on absent data.

func noLongerActionableCfg() config.JiraConfig {
	return config.JiraConfig{
		DefaultTemplate: "t",
		Routes: []config.TicketRoute{{
			Name: "r", When: "true", Project: "PROJ", Board: 1, ImageField: "customfield_1",
			CloseTransitionNoLongerActionable: "WON'T BE DONE", ClosePriorityNoLongerActionable: "Lowest",
		}},
	}
}

// notRunning is an image still reported and assessed, with the upgrade still
// available, whose every workload has gone: suppressed by the not-running rule.
func notRunning(repo string) sink.FindingView {
	return sink.FindingView{
		Repository: repo, ProviderAssessed: true, Scanned: true, Suppressed: true, Rule: "not-running",
		RemediationChecked: true,
		Upgrade:            &sink.UpgradeView{Resolved: true, Available: true, Current: "1.0.0", Latest: "2.0.0"},
		Liveness:           &sink.LivenessView{Live: false},
	}
}

// riskGone is live, no longer matches any rule, and still has a newer version.
func riskGone(repo string) sink.FindingView {
	f := notRunning(repo)
	f.Suppressed, f.Rule = false, ""
	f.Liveness = &sink.LivenessView{Live: true}
	return f
}

func TestClosesAnUntouchedTicketWhoseImageIsNotRunningAnywhere(t *testing.T) {
	got := Reconcile(ReconcileInput{
		Config:      noLongerActionableCfg(),
		Findings:    []sink.FindingView{notRunning("acme/off"), notRunning("acme/off")},
		OpenByImage: map[string][]Existing{"acme/off": {{Key: "PROJ-1", Category: "new"}}},
	})
	if len(got) != 1 || got[0].Kind != ActionClose {
		t.Fatalf("got %v, want one close", kinds(got))
	}
	a := got[0]
	if !a.NoLongerActionable || !a.Unworked || a.Reason != ReasonNotRunning {
		t.Errorf("close should be flagged not-actionable, unworked, not-running: %+v", a)
	}
	for _, want := range []string{"no longer running anywhere", "still in the image", "new ticket will be raised", "Reopen if this is wrong"} {
		if !strings.Contains(a.Message, want) {
			t.Errorf("comment should say %q: %s", want, a.Message)
		}
	}
}

func TestClosesAnUntouchedTicketNoRuleAsksForAnyMore(t *testing.T) {
	got := Reconcile(ReconcileInput{
		Config:      noLongerActionableCfg(),
		Findings:    []sink.FindingView{riskGone("acme/calm"), notRunning("acme/calm")},
		OpenByImage: map[string][]Existing{"acme/calm": {{Key: "PROJ-2", Category: "new"}}},
	})
	if len(got) != 1 || got[0].Kind != ActionClose || got[0].Reason != ReasonNoLongerActionable {
		t.Fatalf("got %+v, want one close for no-longer-actionable (one deployment is live)", got)
	}
	if !strings.Contains(got[0].Message, "no longer required by policy") {
		t.Errorf("comment = %s", got[0].Message)
	}
}

// Someone has the ticket: say why the queue dropped it and leave the decision to them.
func TestWorkedTicketsAreOnlyToldWhy(t *testing.T) {
	for _, tc := range []struct {
		name string
		t    Existing
	}{
		{"assigned", Existing{Key: "PROJ-3", Category: "new", Assigned: true}},
		{"in progress", Existing{Key: "PROJ-3", Category: "indeterminate"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Reconcile(ReconcileInput{
				Config:      noLongerActionableCfg(),
				Findings:    []sink.FindingView{notRunning("acme/off")},
				OpenByImage: map[string][]Existing{"acme/off": {tc.t}},
			})
			if len(got) != 1 || got[0].Kind != ActionNoteDone {
				t.Fatalf("got %v, want one note-done", kinds(got))
			}
			if got[0].Reason != ReasonNotRunning || !strings.Contains(got[0].Message, "no workload is running") {
				t.Errorf("note should carry the reason: %+v", got[0])
			}
			if got[0].Dedupe != "note-done:"+ReasonNotRunning {
				t.Errorf("dedupe should be keyed on the reason: %q", got[0].Dedupe)
			}
		})
	}
}

func TestNoLongerActionableIsOffByDefault(t *testing.T) {
	got := Reconcile(ReconcileInput{
		Findings:    []sink.FindingView{notRunning("acme/off")},
		OpenByImage: map[string][]Existing{"acme/off": {{Key: "PROJ-4", Category: "new"}}},
	})
	if len(got) != 1 || got[0].Kind != ActionNoteDone {
		t.Fatalf("without the option nothing closes: %v", kinds(got))
	}
}

// The guards that keep it honest: still actionable anywhere is a draft, not done;
// dropped by a priority threshold is a hold; unreadable is a hold; gone from the
// assessment is a comment, never a close.
func TestNoLongerActionableGuards(t *testing.T) {
	cfg := noLongerActionableCfg()
	open := map[string][]Existing{"acme/app": {{Key: "PROJ-5", Category: "new"}}}

	t.Run("one environment still actionable", func(t *testing.T) {
		live := riskGone("acme/app")
		live.Actionable = true
		got := Reconcile(ReconcileInput{
			Config: cfg, OpenByImage: open,
			Drafts:   []Draft{draft("Upgrade app to 2.0.0", []string{"acme/app"}, "2.0.0")},
			Findings: []sink.FindingView{live, notRunning("acme/app")},
		})
		for _, a := range got {
			if a.Kind == ActionClose {
				t.Fatalf("a ticket with a live actionable deployment must not close: %+v", got)
			}
		}
	})
	t.Run("below the priority threshold", func(t *testing.T) {
		got := Reconcile(ReconcileInput{
			Config: cfg, OpenByImage: open,
			Skipped:  []Skip{{Image: "acme/app", Reason: "below minPriority", Policy: true}},
			Findings: []sink.FindingView{riskGone("acme/app")},
		})
		if len(got) != 1 || got[0].Kind != ActionHold {
			t.Fatalf("want hold, got %+v", got)
		}
	})
	t.Run("gone from the assessment", func(t *testing.T) {
		got := Reconcile(ReconcileInput{Config: cfg, OpenByImage: open})
		if len(got) != 1 || got[0].Kind != ActionNoteDone || !strings.Contains(got[0].Message, "cannot tell") {
			t.Fatalf("absent data is a comment, never a close: %+v", got)
		}
	})
	t.Run("liveness unknown is not not-running", func(t *testing.T) {
		f := notRunning("acme/app")
		f.Liveness = nil
		got := Reconcile(ReconcileInput{Config: cfg, OpenByImage: open, Findings: []sink.FindingView{f}})
		if len(got) != 1 || got[0].Kind != ActionClose || got[0].Reason != ReasonNoLongerActionable {
			t.Fatalf("without liveness the claim can only be that no rule asks: %+v", got)
		}
	})
}

func TestUpgradeLandedCloseCarriesItsReason(t *testing.T) {
	actions := Reconcile(ReconcileInput{
		Config:      autoCloseCfg(),
		Findings:    []sink.FindingView{onLatest("acme/app", "2.0.0")},
		OpenByImage: map[string][]Existing{"acme/app": {{Key: "PROJ-1", Category: "new"}}},
	})
	if len(actions) != 1 || actions[0].Reason != ReasonUpgradeLanded || actions[0].NoLongerActionable {
		t.Fatalf("a proven close is upgrade-landed and not flagged not-actionable: %+v", actions)
	}
}

func TestJiraCloseUsesTheNotActionableTransition(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{
		transition("8", "WON'T BE DONE", "WON'T BE DONE", "done"),
		transition("31", "Done", "Done", "done"),
	}}
	cfg := baseCfg()
	cfg.CloseTransition = "Done"
	cfg.CloseTransitionNoLongerActionable, cfg.ClosePriorityNoLongerActionable = "WON'T BE DONE", "Lowest"
	err := ts.jira(t, cfg).Close(context.Background(), CloseRequest{Key: "PROJ-1", Comment: "why", Unworked: true, NoLongerActionable: true})
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	tr, _ := ts.posted["transition"].(map[string]any)
	if tr["id"] != "8" {
		t.Errorf("transitioned with %v, want 8 (the not-done one), not the Done transition", tr["id"])
	}
	if ts.editedPriority != "Lowest" {
		t.Errorf("priority should be replaced on the way out by an edit: %q", ts.editedPriority)
	}
	if len(ts.comments) != 1 || !strings.Contains(ts.comments[0], "why") {
		t.Errorf("the reason should be posted as a comment before closing: %v", ts.comments)
	}
}

func TestJiraCloseRefusesNotActionableWithoutConfiguration(t *testing.T) {
	ts := &transitionServer{transitions: []map[string]any{transition("31", "Done", "Done", "done")}}
	err := ts.jira(t, baseCfg()).Close(context.Background(), CloseRequest{Key: "PROJ-1", NoLongerActionable: true})
	if err == nil || !strings.Contains(err.Error(), "closeTransitionNoLongerActionable") {
		t.Fatalf("must refuse rather than fall back to Done: %v", err)
	}
	if ts.posted != nil || len(ts.comments) != 0 {
		t.Errorf("nothing should have been posted")
	}
}
