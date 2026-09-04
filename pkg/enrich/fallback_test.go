package enrich_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// countingSource records what it was asked about, which is the point of most of
// these tests: the fallback is bounded by what it does NOT scan.
type countingSource struct {
	asked *[]string
	vulns []model.Vulnerability
	err   error
}

func (c countingSource) Name() string { return "counting" }
func (c countingSource) Scan(_ context.Context, img model.Image) ([]model.Vulnerability, error) {
	*c.asked = append(*c.asked, img.Ref)
	if c.err != nil {
		return nil, c.err
	}
	return c.vulns, nil
}

func assessed(ref string, yes bool) model.AssessedImage {
	return model.AssessedImage{
		Image:       model.ParseImageRef(ref),
		Occurrences: []model.Occurrence{{Assessed: yes}},
	}
}

func TestFallbackScansOnlyUnassessedImages(t *testing.T) {
	var asked []string
	images := []model.AssessedImage{
		assessed("a:1", true),
		assessed("b:1", false),
		assessed("c:1", true),
	}
	s := enrich.NewFallbackScanner(countingSource{asked: &asked,
		vulns: []model.Vulnerability{{ID: "CVE-1", Severity: model.SeverityCritical}}})
	if err := s.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "b:1" {
		t.Fatalf("only the unassessed image should be scanned, got %v", asked)
	}
	if !images[1].FallbackScanned || images[1].CountsSource != "counting" {
		t.Errorf("unassessed image should record the fallback, got %+v", images[1])
	}
	// The assessed ones keep the provider's counts and say nothing about a fallback.
	if images[0].FallbackSource != "" || images[0].CountsSource != "" {
		t.Errorf("assessed image must be untouched, got %+v", images[0])
	}
}

func TestFallbackObeysTheSkipPolicy(t *testing.T) {
	var asked []string
	images := []model.AssessedImage{assessed("skipme:1", false), assessed("b:1", false)}
	s := enrich.NewFallbackScanner(countingSource{asked: &asked})
	s.Skip = func(img model.AssessedImage) bool { return img.Image.Ref == "skipme:1" }
	if err := s.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "b:1" {
		t.Fatalf("a skipped image must not be scanned by the fallback either, got %v", asked)
	}
	// Skipped, not failed: nothing to report on the finding.
	if images[0].FallbackSource != "" || images[0].FallbackError != "" {
		t.Errorf("skipped image should record nothing, got %+v", images[0])
	}
}

func TestFallbackFillsCountsFromWhatItFound(t *testing.T) {
	var asked []string
	images := []model.AssessedImage{assessed("b:1", false)}
	s := enrich.NewFallbackScanner(countingSource{asked: &asked, vulns: []model.Vulnerability{
		{ID: "CVE-1", Severity: model.SeverityCritical},
		{ID: "CVE-2", Severity: model.SeverityCritical},
		{ID: "CVE-3", Severity: model.SeverityHigh},
	}})
	if err := s.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if got := images[0].Counts.Get(model.SeverityCritical); got != 2 {
		t.Errorf("critical count = %d, want 2", got)
	}
	if got := images[0].Counts.Get(model.SeverityHigh); got != 1 {
		t.Errorf("high count = %d, want 1", got)
	}
	// The image the provider never assessed still reports it never did. The
	// fallback answers the question the provider could not; it does not change
	// which question was asked.
	if images[0].ProviderAssessed() {
		t.Error("a fallback scan must not make an image look provider-assessed")
	}
}

func TestFallbackFailureIsRecordedAndNeverFatal(t *testing.T) {
	var asked []string
	images := []model.AssessedImage{assessed("b:1", false)}
	s := enrich.NewFallbackScanner(countingSource{asked: &asked, err: fmt.Errorf("UNAUTHORIZED: authentication required")})
	// Every scan failing is the EXPECTED shape here: these are the images the
	// provider could not read either. It must not take the assessment down.
	if err := s.EnrichImages(context.Background(), images); err != nil {
		t.Fatalf("a failing fallback must not fail the run: %v", err)
	}
	if images[0].FallbackScanned {
		t.Error("a failed scan must not be reported as scanned")
	}
	if images[0].FallbackError == "" || images[0].FallbackSource != "counting" {
		t.Errorf("the failure and its source should be recorded, got %+v", images[0])
	}
	if images[0].CountsSource != "" {
		t.Error("a failed scan must not claim to have produced counts")
	}
}

// failingPreparer fails its one-time setup, which covers every target at once.
type failingPreparer struct{ countingSource }

func (failingPreparer) Prepare(context.Context) error { return fmt.Errorf("db download failed") }

func TestFallbackPrepareFailureIsRecordedOnEveryTarget(t *testing.T) {
	var asked []string
	images := []model.AssessedImage{assessed("a:1", false), assessed("b:1", false), assessed("c:1", true)}
	s := enrich.NewFallbackScanner(failingPreparer{countingSource{asked: &asked}})
	if err := s.EnrichImages(context.Background(), images); err != nil {
		t.Fatalf("a prepare failure must not fail the run: %v", err)
	}
	if len(asked) != 0 {
		t.Errorf("nothing should be scanned when prepare failed, got %v", asked)
	}
	for _, i := range []int{0, 1} {
		if images[i].FallbackError == "" {
			t.Errorf("image %d should carry the prepare failure as its reason", i)
		}
	}
	if images[2].FallbackError != "" {
		t.Error("an assessed image was never a target and must record nothing")
	}
}

func TestFallbackDoesNothingWhenEverythingWasAssessed(t *testing.T) {
	var asked []string
	images := []model.AssessedImage{assessed("a:1", true)}
	s := enrich.NewFallbackScanner(failingPreparer{countingSource{asked: &asked}})
	// Prepare is expensive (a vuln DB download). With no targets it must not run.
	if err := s.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].FallbackError != "" {
		t.Errorf("prepare should not have run at all, got %+v", images[0])
	}
}
