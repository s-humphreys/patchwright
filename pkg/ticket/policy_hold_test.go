package ticket

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Every configuration decision not to ticket something holds an open ticket for
// it, whatever the decision was. Driven through the planner rather than with
// hand-built skips: the planner records a full image reference for some skips,
// while tickets are indexed by bare repository, and a hold that never matches
// lets the ticket fall through to being closed as "no longer required by policy".
func TestEveryPolicySkipFromThePlannerHoldsItsOpenTicket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.tmpl")
	if err := os.WriteFile(path, []byte("Summary: Upgrade {{ .ServiceName }}\n\nbody\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	route := config.TicketRoute{
		Name: "platform", When: "owner['class'] == 'platform'", Board: 1, Project: "PROJ",
		ImageField: "customfield_1", CloseTransitionNoLongerActionable: "WON'T BE DONE",
	}
	// Live, assessed, and the upgrade still available: nothing about it is done.
	outstanding := func(repo string, opts ...func(*sink.FindingView)) sink.FindingView {
		return finding(repo, append([]func(*sink.FindingView){func(f *sink.FindingView) {
			f.ProviderAssessed, f.Scanned = true, true
			f.Owner = sink.OwnerView{Class: "platform"}
			f.Liveness = &sink.LivenessView{Live: true}
		}}, opts...)...)
	}

	cases := []struct {
		name    string
		cfg     func(*config.JiraConfig)
		finding sink.FindingView
	}{
		{
			name: "excluded",
			cfg: func(c *config.JiraConfig) {
				c.Exclude = []config.ExcludeRule{{
					Name: "crossplane", When: "dimensions['namespace'].exists(n, n == 'crossplane-system')",
				}}
			},
			finding: outstanding("crossplane-contrib/function-auto-ready", func(f *sink.FindingView) {
				f.Dimensions = map[string][]string{"namespace": {"crossplane-system"}}
			}),
		},
		{
			name: "no route",
			finding: outstanding("acme/app", func(f *sink.FindingView) {
				f.Owner = sink.OwnerView{Class: "unrouted"}
			}),
		},
		{
			name: "below minimum priority",
			cfg:  func(c *config.JiraConfig) { c.MinPriority = "urgent" },
			finding: outstanding("acme/app", func(f *sink.FindingView) {
				f.Priority = "high"
			}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.JiraConfig{DefaultTemplate: path, Routes: []config.TicketRoute{route}}
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			p, err := NewPlanner(cfg)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := p.Plan([]sink.FindingView{tc.finding})
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Drafts) != 0 || len(plan.Skips) != 1 || !plan.Skips[0].Policy {
				t.Fatalf("want exactly one policy skip, got drafts=%d skips=%+v", len(plan.Drafts), plan.Skips)
			}

			actions := Reconcile(ReconcileInput{
				Config:   cfg,
				Drafts:   plan.Drafts,
				Skipped:  plan.Skips,
				Findings: []sink.FindingView{tc.finding},
				OpenByImage: map[string][]Existing{
					tc.finding.Repository: {{Key: "PROJ-1", Category: "new"}},
				},
			})
			if len(actions) != 1 || actions[0].Kind != ActionHold {
				t.Fatalf("got %+v, want one hold: configuration declining to ticket is not the work "+
					"being done, and not a reason to close", actions)
			}
		})
	}
}
