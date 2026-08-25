package model_test

import (
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

func occ(exposed *bool) model.Occurrence { return model.Occurrence{Exposed: exposed, Assessed: true} }

func ptr(b bool) *bool { return &b }

func TestExposureTreatsUnknownAsItsOwnAnswer(t *testing.T) {
	cases := []struct {
		name string
		occs []model.Occurrence
		want string
	}{
		{"nothing reported", []model.Occurrence{occ(nil), occ(nil)}, model.ExposureUnknown},
		{"all internal", []model.Occurrence{occ(ptr(false))}, model.ExposureInternal},
		{"one exposed", []model.Occurrence{occ(ptr(false)), occ(ptr(true))}, model.ExposurePublic},
		// Exposed somewhere is exposed: the image is reachable, whatever the other
		// workloads running it are doing.
		{"exposed plus unknown", []model.Occurrence{occ(nil), occ(ptr(true))}, model.ExposurePublic},
		{"internal plus unknown", []model.Occurrence{occ(nil), occ(ptr(false))}, model.ExposureInternal},
		{"no workloads", nil, model.ExposureUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := model.Finding{Occurrences: c.occs}
			if got := f.Exposure(); got != c.want {
				t.Fatalf("Exposure() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSignalsAreOnlyEverPositiveStatements(t *testing.T) {
	// An internal, assessed, unexploited finding with no pull request carries no
	// signals at all. Nothing in the list may assert the negative of anything.
	f := model.Finding{Occurrences: []model.Occurrence{occ(ptr(false))}}
	if got := f.Signals(); len(got) != 0 {
		t.Fatalf("expected no signals, got %v", got)
	}
}

func TestSignalsReportWhatIsThere(t *testing.T) {
	f := model.Finding{
		Occurrences: []model.Occurrence{occ(ptr(true))},
		Vulns:       []model.Vulnerability{{ID: "CVE-1", KEV: true}},
		InFlight:    &model.InFlight{Repository: "app", Stale: true},
	}
	got := map[string]bool{}
	for _, s := range f.Signals() {
		got[s] = true
	}
	for _, want := range []string{model.SignalExposed, model.SignalKnownExploit, model.SignalInFlight, model.SignalStaleFix} {
		if !got[want] {
			t.Errorf("missing signal %q in %v", want, f.Signals())
		}
	}
}

func TestUnassessedIsASignal(t *testing.T) {
	// The provider never assessed it, so its zero counts are absence of data. That is
	// worth a badge: it is the difference between clean and unknown.
	f := model.Finding{Occurrences: []model.Occurrence{{Exposed: ptr(false)}}}
	found := false
	for _, s := range f.Signals() {
		if s == model.SignalUnassessed {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an unassessed signal, got %v", f.Signals())
	}
}
