package mcp

import (
	"strings"
	"testing"
)

const unmeasuredFailure = "the base scanner could not run: vulnerability database unavailable: 404 Not Found"

// differentialState puts the fixture's two deployments, both carrying CVE-2026-1,
// into one of three states: neither measured nor failed (unmeasurable), both failed
// this run, or the first measured and the second failed this run.
func differentialState(state string) Assessment {
	a := fixture()
	second := &a.Findings[1]
	second.Vulns = append(second.Vulns, a.Findings[0].Vulns[0])
	second.Vulns[0].OriginDetermined, second.Vulns[0].FixedByUpgrade, second.Vulns[0].Origin = false, false, ""

	if state == "partial" {
		second.BaseDiffError = unmeasuredFailure
		return a
	}
	first := &a.Findings[0]
	first.BaseDiff = nil
	for i := range first.Vulns {
		first.Vulns[i].OriginDetermined, first.Vulns[i].FixedByUpgrade, first.Vulns[i].Origin = false, false, ""
	}
	if state == "failed" {
		first.BaseDiffError = unmeasuredFailure
		second.BaseDiffError = unmeasuredFailure
	}
	return a
}

// "Could not be measured this run" is an outage the next run retries; "not
// measurable" is a property of the images. Every report that builds coverage
// caveats must word them apart, or it sends the reader to fix a registry when the
// scanner is what broke, or the reverse.
func TestEveryReportTellsUnmeasuredThisRunFromUnmeasurable(t *testing.T) {
	reports := map[string]func(Assessment) []string{
		"service_report": func(a Assessment) []string {
			r, ok := serviceReport(a, "apps/storefront")
			if !ok {
				t.Fatal("service not found")
			}
			return r.Caveats
		},
		"team_report": func(a Assessment) []string {
			r, _, ok := teamReport(a, "payments")
			if !ok {
				t.Fatal("team not found")
			}
			return r.Caveats
		},
		"estate_summary": func(a Assessment) []string { return estateSummary(a).Caveats },
		"worst_first":    func(a Assessment) []string { return worstFirst(a, "", "", 10).Caveats },
		"explain_cve": func(a Assessment) []string {
			r, ok := cveReport(a, "CVE-2026-1")
			if !ok {
				t.Fatal("CVE not found")
			}
			return r.Caveats
		},
	}
	const (
		thisRunNone    = "could not measure any deployment this run"
		thisRunPartial = "could not measure 1 of the 2 deployments it set out to this run"
		unmeasurable   = "Base images could not be resolved or scanned"
	)
	for _, tc := range []struct {
		state string
		want  string
		deny  []string
	}{
		{"unmeasurable", unmeasurable, []string{"this run"}},
		{"failed", thisRunNone, []string{unmeasurable, thisRunPartial}},
		{"partial", thisRunPartial, []string{unmeasurable, thisRunNone, "deleted from its registry"}},
	} {
		for name, caveats := range reports {
			t.Run(tc.state+"/"+name, func(t *testing.T) {
				joined := strings.Join(caveats(differentialState(tc.state)), " ")
				if !strings.Contains(joined, tc.want) {
					t.Errorf("caveats should say %q:\n%s", tc.want, joined)
				}
				for _, d := range tc.deny {
					if strings.Contains(joined, d) {
						t.Errorf("caveats should not say %q:\n%s", d, joined)
					}
				}
			})
		}
	}
}

func TestServiceReportCarriesTheUnmeasuredCountAndReason(t *testing.T) {
	for _, tc := range []struct {
		state      string
		wantCount  int
		wantReason string
	}{
		{"unmeasurable", 0, ""},
		{"failed", 2, unmeasuredFailure},
		{"partial", 1, unmeasuredFailure},
	} {
		t.Run(tc.state, func(t *testing.T) {
			r, _ := serviceReport(differentialState(tc.state), "apps/storefront")
			if r.Upgrade.DeploymentsUnmeasured != tc.wantCount || r.Upgrade.UnmeasuredReason != tc.wantReason {
				t.Errorf("unmeasured = %d %q, want %d %q", r.Upgrade.DeploymentsUnmeasured,
					r.Upgrade.UnmeasuredReason, tc.wantCount, tc.wantReason)
			}
		})
	}
}
