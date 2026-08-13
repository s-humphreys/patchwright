package enrich

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
)

type stubAgeSource struct {
	seen  map[string]time.Time
	err   error
	asked []string
}

func (s *stubAgeSource) Name() string { return "stub" }

func (s *stubAgeSource) FirstSeen(_ context.Context, ids []string) (map[string]time.Time, error) {
	s.asked = ids
	return s.seen, s.err
}

func TestAgeEnricherStampsKnownCVEs(t *testing.T) {
	jun := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	src := &stubAgeSource{seen: map[string]time.Time{"CVE-1": jun}}
	images := []model.AssessedImage{{Vulns: []model.Vulnerability{
		{ID: "CVE-1"}, {ID: "CVE-2"},
	}}}

	if err := NewAgeEnricher(src).EnrichImages(context.Background(), images); err != nil {
		t.Fatalf("EnrichImages: %v", err)
	}
	if !images[0].Vulns[0].FirstSeen.Equal(jun) {
		t.Errorf("CVE-1 FirstSeen = %v, want %v", images[0].Vulns[0].FirstSeen, jun)
	}
	// A CVE the provider has never seen must stay unknown, not become the epoch,
	// which would sort as the oldest thing in the queue.
	if !images[0].Vulns[1].FirstSeen.IsZero() {
		t.Errorf("CVE-2 was dated despite being unknown: %v", images[0].Vulns[1].FirstSeen)
	}
}

// Ageing is decoration on the queue, not the queue: a source failure must not cost
// the assessment.
func TestAgeEnricherSurfacesSourceFailures(t *testing.T) {
	src := &stubAgeSource{err: errors.New("boom")}
	images := []model.AssessedImage{{Vulns: []model.Vulnerability{{ID: "CVE-1"}}}}
	err := NewAgeEnricher(src).EnrichImages(context.Background(), images)
	if err == nil {
		t.Fatal("a failing source was reported as success")
	}
	if !images[0].Vulns[0].FirstSeen.IsZero() {
		t.Error("a failed lookup left a date behind")
	}
}

// Without a vuln source there are no CVEs, so there is nothing to ask about and no
// request should be made.
func TestAgeEnricherIsANoOpWithoutCVEs(t *testing.T) {
	src := &stubAgeSource{}
	images := []model.AssessedImage{{Counts: model.Counts{"critical": 3}}}
	if err := NewAgeEnricher(src).EnrichImages(context.Background(), images); err != nil {
		t.Fatalf("EnrichImages: %v", err)
	}
	if src.asked != nil {
		t.Errorf("asked the source about %v with no CVEs present", src.asked)
	}
}

// The oldest CVE dates the finding: an image carrying one since June has been exposed
// since June, whatever was added later.
func TestOldestVulnPicksTheEarliestKnown(t *testing.T) {
	jun := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	aug := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	f := model.Finding{Vulns: []model.Vulnerability{
		{ID: "CVE-new", FirstSeen: aug},
		{ID: "CVE-undated"},
		{ID: "CVE-old", FirstSeen: jun},
	}}
	got, ok := f.OldestVuln()
	if !ok || !got.Equal(jun) {
		t.Errorf("OldestVuln = %v, %v; want %v, true", got, ok, jun)
	}

	// No dates at all is unknown, not zero.
	if _, ok := (model.Finding{Vulns: []model.Vulnerability{{ID: "CVE-1"}}}).OldestVuln(); ok {
		t.Error("an undated finding reported an age")
	}
}
