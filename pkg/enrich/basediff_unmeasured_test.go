package enrich

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/basescan"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// preparingScanner is a stubScanner with a database to prepare, failing the first
// prepFails calls, and references the registry reports as gone.
type preparingScanner struct {
	stubScanner
	prepFails int
	missing   map[string]bool

	pmu   sync.Mutex
	preps int
}

func (s *preparingScanner) Prepare(context.Context) error {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	s.preps++
	if s.preps <= s.prepFails {
		return fmt.Errorf("%w: 404 Not Found", basescan.ErrDBUnavailable)
	}
	return nil
}

func (s *preparingScanner) ScanRef(ctx context.Context, ref string) (*basescan.Result, error) {
	if s.missing[ref] {
		return nil, fmt.Errorf("trivy %s: %w", ref, basescan.ErrNotFound)
	}
	return s.stubScanner.ScanRef(ctx, ref)
}

func newPreparing() *preparingScanner {
	return &preparingScanner{stubScanner: stubScanner{byRef: map[string][]string{
		"base@sha256:aaa": {"CVE-1", "CVE-2"},
		"base:new":        {"CVE-2"},
	}, fail: map[string]bool{}}, missing: map[string]bool{}}
}

func TestEnrichMarksWhatThisRunCouldNotMeasure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*preparingScanner)
		// wantError is a substring of BaseDiffError, "" for none.
		wantError      string
		wantDiff       bool
		wantDetermined bool
	}{
		{name: "measured", wantDiff: true, wantDetermined: true},
		{name: "scanner could not be prepared",
			setup:     func(s *preparingScanner) { s.prepFails = 1 },
			wantError: "the base scanner could not run"},
		{name: "base scan failed",
			setup:     func(s *preparingScanner) { s.fail["base@sha256:aaa"] = true },
			wantError: "base scan failed"},
		// Ownership was measured; only what the upgrade clears was not.
		{name: "candidate scan failed",
			setup:     func(s *preparingScanner) { s.fail["base:new"] = true },
			wantError: "candidate base scan failed", wantDiff: true},
		// A base gone from its registry is unmeasurable, not unmeasured: no retry
		// will answer it, and holding on it would hold for ever.
		{name: "base deleted from its registry",
			setup: func(s *preparingScanner) { s.missing["base@sha256:aaa"] = true }},
		{name: "candidate deleted from its registry",
			setup:    func(s *preparingScanner) { s.missing["base:new"] = true },
			wantDiff: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newPreparing()
			if tc.setup != nil {
				tc.setup(s)
			}
			e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}}
			images := []model.AssessedImage{image("CVE-1", "CVE-2", "CVE-3")}
			if err := e.EnrichImages(context.Background(), images); err != nil {
				t.Fatal(err)
			}
			got := images[0]
			if tc.wantError == "" && got.BaseDiffError != "" {
				t.Errorf("BaseDiffError = %q, want none", got.BaseDiffError)
			}
			if tc.wantError != "" && !strings.Contains(got.BaseDiffError, tc.wantError) {
				t.Errorf("BaseDiffError = %q, want it to contain %q", got.BaseDiffError, tc.wantError)
			}
			if (got.BaseDiff != nil) != tc.wantDiff {
				t.Fatalf("BaseDiff = %+v, want present %v", got.BaseDiff, tc.wantDiff)
			}
			if got.BaseDiff != nil && got.BaseDiff.Determined != tc.wantDetermined {
				t.Errorf("Determined = %v, want %v", got.BaseDiff.Determined, tc.wantDetermined)
			}
		})
	}
}

// The incident: the first run after a restart could not fetch the database. The
// process must recover on the next run rather than fail every scan until restarted.
func TestEnrichRecoversOnTheNextRunAfterTheScannerCouldNotBePrepared(t *testing.T) {
	s := newPreparing()
	s.prepFails = 1
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}}

	first := []model.AssessedImage{image("CVE-1", "CVE-2")}
	if err := e.EnrichImages(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if first[0].BaseDiffError == "" || first[0].BaseDiff != nil {
		t.Fatalf("first run should be unmeasured: error %q diff %+v", first[0].BaseDiffError, first[0].BaseDiff)
	}
	if s.count() != 0 {
		t.Errorf("scanned %d references with no database; each would fail for the same reason", s.count())
	}

	second := []model.AssessedImage{image("CVE-1", "CVE-2")}
	if err := e.EnrichImages(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if second[0].BaseDiffError != "" || second[0].BaseDiff == nil || !second[0].BaseDiff.Determined {
		t.Fatalf("second run should measure: error %q diff %+v", second[0].BaseDiffError, second[0].BaseDiff)
	}
}

// A scanner with no Prepare is not asked to, and works as before.
func TestEnrichNeedsNoPreparer(t *testing.T) {
	s := &stubScanner{byRef: map[string][]string{"base@sha256:aaa": {"CVE-1"}, "base:new": {}}}
	var _ basescan.Scanner = s
	if _, ok := any(s).(basescan.Preparer); ok {
		t.Fatal("the plain stub must not be a Preparer for this to test anything")
	}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}}
	images := []model.AssessedImage{image("CVE-1")}
	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].BaseDiff == nil || images[0].BaseDiffError != "" {
		t.Errorf("want a measured differential, got %+v / %q", images[0].BaseDiff, images[0].BaseDiffError)
	}
}
