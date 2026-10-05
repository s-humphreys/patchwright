package ticket

import (
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// A ticket whose images the history record credited as decommissioned is done by
// decommission: closed when nobody picked it up and the board opted in, otherwise
// told why, and never while an image shows up running again.
func TestDecommissionedTickets(t *testing.T) {
	untouched := Existing{Key: "PROJ-1", Category: "new"}
	worked := Existing{Key: "PROJ-1", Category: "indeterminate"}
	running := riskGone("acme/off")
	unknown := notRunning("acme/off")
	unknown.Liveness = nil

	cases := []struct {
		name     string
		ticket   Existing
		images   []string
		findings []sink.FindingView
		credited map[string]bool
		cfg      config.JiraConfig
		kind     ActionKind
		reason   string
		message  string
	}{
		{name: "untouched and no longer reported is closed", ticket: untouched, credited: map[string]bool{"acme/off": true},
			cfg: noLongerActionableCfg(), kind: ActionClose, reason: ReasonDecommissioned, message: "were decommissioned"},
		{name: "untouched and reported not running is closed as decommissioned", ticket: untouched, findings: []sink.FindingView{notRunning("acme/off")},
			credited: map[string]bool{"acme/off": true}, cfg: noLongerActionableCfg(), kind: ActionClose, reason: ReasonDecommissioned, message: "Removing the workloads remediated"},
		{name: "worked ticket is told", ticket: worked, credited: map[string]bool{"acme/off": true},
			cfg: noLongerActionableCfg(), kind: ActionNoteDone, reason: ReasonDecommissioned, message: "closing is a human decision"},
		{name: "board without the transition is told", ticket: untouched, credited: map[string]bool{"acme/off": true},
			kind: ActionNoteDone, reason: ReasonDecommissioned, message: "credits this ticket's images as decommissioned"},
		{name: "not credited stays a blind note", ticket: untouched, cfg: noLongerActionableCfg(),
			kind: ActionNoteDone, message: "cannot tell whether"},
		{name: "one image of two credited stays blind", ticket: untouched, images: []string{"acme/other"},
			credited: map[string]bool{"acme/off": true}, cfg: noLongerActionableCfg(), kind: ActionNoteDone, message: "cannot tell whether"},
		{name: "running again is not decommissioned", ticket: untouched, findings: []sink.FindingView{running},
			credited: map[string]bool{"acme/off": true}, cfg: noLongerActionableCfg(), kind: ActionClose, reason: ReasonNoLongerActionable},
		{name: "liveness unknown is not decommissioned", ticket: untouched, findings: []sink.FindingView{unknown},
			credited: map[string]bool{"acme/off": true}, cfg: noLongerActionableCfg(), kind: ActionClose, reason: ReasonNoLongerActionable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			index := map[string][]Existing{"acme/off": {c.ticket}}
			for _, img := range c.images {
				index[img] = []Existing{c.ticket}
			}
			got := Reconcile(ReconcileInput{Config: c.cfg, Findings: c.findings, OpenByImage: index, Decommissioned: c.credited})
			if len(got) != 1 || got[0].Kind != c.kind {
				t.Fatalf("got %+v, want one %s", got, c.kind)
			}
			a := got[0]
			if a.Reason != c.reason {
				t.Errorf("reason = %q, want %q", a.Reason, c.reason)
			}
			if !strings.Contains(a.Message, c.message) {
				t.Errorf("message should say %q: %s", c.message, a.Message)
			}
			if c.reason == ReasonDecommissioned && a.Kind == ActionClose && (!a.Unworked || !a.NoLongerActionable) {
				t.Errorf("a decommission close goes through the not-worked, no-longer-actionable transition: %+v", a)
			}
			if c.reason == ReasonDecommissioned && a.Kind == ActionNoteDone && a.Dedupe != "note-done:"+ReasonDecommissioned {
				t.Errorf("dedupe = %q", a.Dedupe)
			}
		})
	}
}
