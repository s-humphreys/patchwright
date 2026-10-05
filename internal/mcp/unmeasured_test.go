package mcp

import (
	"strings"
	"testing"
)

// "Could not be measured this run" is an outage the next run retries; "not
// measurable" is a property of the image. A report that words them the same sends
// the reader to fix a registry when the scanner is what broke, or the reverse.
func TestServiceReportTellsUnmeasuredThisRunFromUnmeasurable(t *testing.T) {
	const failure = "the base scanner could not run: vulnerability database unavailable: 404 Not Found"
	for _, tc := range []struct {
		name string
		// failed marks the measured deployment as failed this run instead.
		failed     bool
		want, deny string
	}{
		{"failed this run", true, "could not measure any deployment this run", "base could not be resolved or scanned"},
		{"never measured", false, "base could not be resolved or scanned", "this run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := fixture()
			// Neither deployment measured; one of them failed this run, or neither did.
			a.Findings[0].BaseDiff = nil
			for i := range a.Findings[0].Vulns {
				a.Findings[0].Vulns[i].OriginDetermined = false
			}
			if tc.failed {
				a.Findings[0].BaseDiffError = failure
			}
			r, ok := serviceReport(a, "apps/storefront")
			if !ok {
				t.Fatal("service not found")
			}
			joined := strings.Join(r.Caveats, " ")
			if !strings.Contains(joined, tc.want) {
				t.Errorf("caveats should say %q: %v", tc.want, r.Caveats)
			}
			if strings.Contains(joined, tc.deny) {
				t.Errorf("caveats should not say %q: %v", tc.deny, r.Caveats)
			}
			if tc.failed && (r.Upgrade.DeploymentsUnmeasured != 1 || r.Upgrade.UnmeasuredReason != failure) {
				t.Errorf("upgrade should carry the unmeasured count and reason: %+v", r.Upgrade)
			}
		})
	}
}

// Partly measured: the failed deployment is named as such rather than folded into
// "the base was deleted from its registry".
func TestServiceReportNamesAPartialFailureThisRun(t *testing.T) {
	a := fixture()
	a.Findings[1].BaseDiffError = "base scan failed: timeout"
	r, _ := serviceReport(a, "apps/storefront")
	joined := strings.Join(r.Caveats, " ")
	if !strings.Contains(joined, "could not measure 1 of 2 deployments this run") {
		t.Errorf("partial failure not stated: %v", r.Caveats)
	}
	if strings.Contains(joined, "deleted from its registry") {
		t.Errorf("a failure this run is not a deleted base: %v", r.Caveats)
	}
}
