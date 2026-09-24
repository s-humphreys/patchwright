package model_test

import (
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

func assessed() model.Occurrence { return model.Occurrence{Assessed: true} }

func TestSignalsAreOnlyEverPositiveStatements(t *testing.T) {
	// An assessed, unexploited finding with no pull request carries no
	// signals at all. Nothing in the list may assert the negative of anything.
	f := model.Finding{Occurrences: []model.Occurrence{assessed()}}
	if got := f.Signals(); len(got) != 0 {
		t.Fatalf("expected no signals, got %v", got)
	}
}

func TestSignalsReportWhatIsThere(t *testing.T) {
	f := model.Finding{
		Occurrences: []model.Occurrence{assessed()},
		Vulns:       []model.Vulnerability{{ID: "CVE-1", KEV: true}},
		InFlight:    &model.InFlight{Repository: "app", Stale: true},
	}
	got := map[string]bool{}
	for _, s := range f.Signals() {
		got[s] = true
	}
	for _, want := range []string{model.SignalKnownExploit, model.SignalInFlight, model.SignalStaleFix} {
		if !got[want] {
			t.Errorf("missing signal %q in %v", want, f.Signals())
		}
	}
}

func TestUnassessedIsASignal(t *testing.T) {
	// The provider never assessed it, so its zero counts are absence of data. That is
	// worth a badge: it is the difference between clean and unknown.
	f := model.Finding{Occurrences: []model.Occurrence{{}}}
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

func TestFallbackScanSignalRidesAlongsideUnassessed(t *testing.T) {
	f := model.Finding{
		Occurrences:     []model.Occurrence{{Assessed: false}},
		FallbackScanned: true,
		CountsSource:    "trivy",
	}
	got := f.Signals()
	var unassessed, fallback bool
	for _, s := range got {
		switch s {
		case model.SignalUnassessed:
			unassessed = true
		case model.SignalFallbackScan:
			fallback = true
		}
	}
	// Both, not one. The coverage gap is still a coverage gap; the fallback only
	// says where the numbers on the row came from.
	if !unassessed || !fallback {
		t.Errorf("signals = %v, want both unassessed and fallback-scan", got)
	}
}

func TestNoFallbackSignalWithoutAFallbackScan(t *testing.T) {
	f := model.Finding{Occurrences: []model.Occurrence{{Assessed: false}}}
	for _, s := range f.Signals() {
		if s == model.SignalFallbackScan {
			t.Fatal("a signal is a positive statement; an unscanned image must not carry it")
		}
	}
}

func TestCountsFromVulns(t *testing.T) {
	c := model.CountsFromVulns([]model.Vulnerability{
		{ID: "1", Severity: model.SeverityCritical},
		{ID: "2", Severity: model.SeverityCritical},
		{ID: "3", Severity: ""},
	})
	if c.Get(model.SeverityCritical) != 2 {
		t.Errorf("critical = %d, want 2", c.Get(model.SeverityCritical))
	}
	// An unlabelled severity becomes "unknown" rather than vanishing: a CVE nobody
	// graded is still a CVE, and dropping it would understate the total.
	if c.Get(model.SeverityUnknown) != 1 {
		t.Errorf("unknown = %d, want 1", c.Get(model.SeverityUnknown))
	}
	if model.CountsFromVulns(nil) != nil {
		t.Error("no vulns should produce no counts, not a map of zeros")
	}
}
