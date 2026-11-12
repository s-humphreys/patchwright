package ticket

import (
	"slices"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	grouping "github.com/s-humphreys/patchwright/pkg/group"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// countsView is one tag of a service with the provider's counts for it.
func countsView(tag, account string, assessed bool, critical, high int) sink.FindingView {
	return sink.FindingView{
		Image: "acr.io/svc:" + tag, Repository: "acr.io/svc", Tag: tag,
		ProviderAssessed: assessed,
		Counts:           map[string]int{"critical": critical, "high": high},
		Dimensions:       map[string][]string{"account": {account}},
	}
}

// A ticket's severity counts describe the worst running image, not the sum of its
// tags: three tags of one service share most of their CVEs, so a sum names a number
// no image carries and disagrees with the queue and the service report.
func TestTicketCountsAreTheWorstImageNotTheSum(t *testing.T) {
	cases := []struct {
		name                   string
		group                  []sink.FindingView
		wantCritical, wantHigh int
		wantAssessed           bool
	}{
		{
			// The production tag is the oldest and the worst: a rule that took the
			// newest, or the first, would under-report it.
			name: "multi-tag group whose worst image is not the newest tag",
			group: []sink.FindingView{
				countsView("1.0.347", "Development UK", true, 1, 70),
				countsView("1.0.346", "PreProduction UK", true, 1, 76),
				countsView("1.0.334", "Production UK", true, 2, 79),
			},
			wantCritical: 2, wantHigh: 79, wantAssessed: true,
		},
		{
			name:         "single tag is its own counts",
			group:        []sink.FindingView{countsView("2.4.1", "Production UK", true, 5, 594)},
			wantCritical: 5, wantHigh: 594, wantAssessed: true,
		},
		{
			// Each severity is the worst on its own, as the service report's
			// critical_worst_deployment and high_worst_deployment are.
			name: "severities disagreeing on the worst tag are each the worst",
			group: []sink.FindingView{
				countsView("2", "Development UK", true, 3, 10),
				countsView("1", "Production UK", true, 1, 40),
			},
			wantCritical: 3, wantHigh: 40, wantAssessed: true,
		},
		{
			// An unassessed tag's counts are ignorance, not evidence.
			name: "unassessed tag does not set the worst",
			group: []sink.FindingView{
				countsView("2", "Development UK", false, 9, 99),
				countsView("1", "Production UK", true, 1, 4),
			},
			wantCritical: 1, wantHigh: 4, wantAssessed: true,
		},
		{
			name:  "nothing assessed reports nothing",
			group: []sink.FindingView{countsView("1", "Production UK", false, 0, 0)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newTemplateData(ticketGroup{primary: tc.group}, nil, 0)
			if d.CriticalCount != tc.wantCritical || d.HighCount != tc.wantHigh {
				t.Errorf("counts = %d critical, %d high; want %d, %d",
					d.CriticalCount, d.HighCount, tc.wantCritical, tc.wantHigh)
			}
			if d.ProviderAssessed != tc.wantAssessed {
				t.Errorf("ProviderAssessed = %v, want %v", d.ProviderAssessed, tc.wantAssessed)
			}
			// The ticket and the queue item over the same tags must say the same.
			it := grouping.Items(tc.group)
			if len(it) != 1 || it[0].Critical != d.CriticalCount || it[0].High != d.HighCount {
				t.Errorf("ticket says %d/%d, queue item says %+v", d.CriticalCount, d.HighCount, it)
			}
		})
	}
}

// A row is labelled with the latest environment its tag reaches, without the
// "preproduction contains prod" mistake coming back.
func TestDeploymentEnvironmentIsTheLatestReached(t *testing.T) {
	cases := []struct {
		name       string
		envs       []config.Environment
		accounts   []string
		namespaces []string
		want       string
		wantRank   int
	}{
		{
			name:     "dev, pre and prod accounts is production",
			accounts: []string{"Development UK", "PreProduction UK", "Production UK"},
			want:     "production", wantRank: 3,
		},
		{
			name:     "pre-production only is staging, not production",
			accounts: []string{"PreProduction UK", "PreProduction EU"},
			want:     "staging", wantRank: 2,
		},
		{
			name:       "namespace-only match when no account is recognised",
			accounts:   []string{"Shared Infrastructure"},
			namespaces: []string{"payments-dev", "payments-prod"},
			want:       "production", wantRank: 3,
		},
		{
			name:       "namespace-only match with no accounts at all",
			namespaces: []string{"payments-uat"},
			want:       "staging", wantRank: 2,
		},
		{
			// "delivery" contains "live". The account says where this runs.
			name:       "a recognised account outranks a stray namespace hit",
			accounts:   []string{"Development UK"},
			namespaces: []string{"delivery"},
			want:       "development", wantRank: 0,
		},
		{
			name:     "unrecognised environment says nothing and sorts last",
			accounts: []string{"Shared Infrastructure"},
			want:     "", wantRank: 4,
		},
		{
			name: "configured sequence takes the latest too",
			envs: []config.Environment{
				{Name: "prelive", Match: []string{"preproduction"}},
				{Name: "live", Match: []string{"production"}},
			},
			accounts: []string{"Production UK", "PreProduction UK"},
			want:     "live", wantRank: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, rank := environmentOf(tc.envs, tc.accounts, tc.namespaces)
			if got != tc.want || rank != tc.wantRank {
				t.Errorf("environmentOf = %q/%d, want %q/%d", got, rank, tc.want, tc.wantRank)
			}
		})
	}
}

// Rows are ordered by the latest environment each tag reaches, so the tag furthest
// along is last, and a disambiguator names every environment covered rather than
// only each row's label.
func TestDeploymentsOrderByLatestAndSpanCoversAll(t *testing.T) {
	group := []sink.FindingView{
		countsView("1.0.334", "Production UK", true, 0, 0),
		countsView("1.0.347", "Development UK", true, 0, 0),
		countsView("1.0.346", "PreProduction UK", true, 0, 0),
	}
	// The newest tag runs in development and pre-production both.
	group[1].Dimensions["account"] = []string{"Development UK", "PreProduction UK"}

	d := newTemplateData(ticketGroup{primary: group}, nil, 0)
	var tags, envs []string
	for _, dep := range d.Deployments {
		tags = append(tags, dep.Tag)
		envs = append(envs, dep.Environment)
	}
	if want := []string{"1.0.346", "1.0.347", "1.0.334"}; !slices.Equal(tags, want) {
		t.Errorf("tags = %v, want %v", tags, want)
	}
	if want := []string{"staging", "staging", "production"}; !slices.Equal(envs, want) {
		t.Errorf("environments = %v, want %v", envs, want)
	}
	if want := []string{"development", "staging", "production"}; !slices.Equal(d.environmentSpan(), want) {
		t.Errorf("span = %v, want %v: development is covered though no row is labelled it",
			d.environmentSpan(), want)
	}
}
