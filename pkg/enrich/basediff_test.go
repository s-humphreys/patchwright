package enrich

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/basescan"
	"github.com/s-humphreys/patchwright/pkg/model"
)

type stubScanner struct {
	byRef map[string][]string // ref -> CVE ids
	fail  map[string]bool

	// Guarded: two different base references are scanned concurrently, so an
	// unsynchronised counter is a race the detector would only sometimes catch.
	mu    sync.Mutex
	calls int
}

func (s *stubScanner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *stubScanner) Name() string { return "stub" }

func (s *stubScanner) ScanRef(_ context.Context, ref string) (*basescan.Result, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.fail[ref] {
		return nil, errors.New("unreachable")
	}
	cves, ok := s.byRef[ref]
	if !ok {
		return nil, errors.New("unknown ref " + ref)
	}
	r := &basescan.Result{Ref: ref, OSFamily: "debian",
		Ecosystems: map[string]bool{"debian": true}, CVEs: map[string][]basescan.Package{}}
	for _, c := range cves {
		r.CVEs[c] = []basescan.Package{{Name: "pkg", Ecosystem: "debian"}}
	}
	return r, nil
}

func image(vulns ...string) model.AssessedImage {
	ai := model.AssessedImage{
		Image:   model.Image{Ref: "app:1"},
		Scanned: true,
		Upgrade: &model.Upgrade{Kind: "base", FromRef: "base@sha256:aaa", ToRef: "base:new"},
	}
	for _, v := range vulns {
		ai.Vulns = append(ai.Vulns, model.Vulnerability{ID: v})
	}
	return ai
}

func TestEnrichAttributesAndCountsWhatTheUpgradeFixes(t *testing.T) {
	s := &stubScanner{byRef: map[string][]string{
		"base@sha256:aaa": {"CVE-1", "CVE-2"},
		"base:new":        {"CVE-2"},
	}}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}}
	images := []model.AssessedImage{image("CVE-1", "CVE-2", "CVE-3")}

	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	d := images[0].BaseDiff
	if d == nil {
		t.Fatal("no differential recorded")
	}
	if d.FromBase != 2 || d.FromApp != 1 || d.Clears != 1 || d.Leaves != 1 {
		t.Errorf("counts wrong: %+v", d)
	}
	if !d.Determined {
		t.Error("a candidate was scanned, so the upgrade question was answered")
	}
	byID := map[string]model.Vulnerability{}
	for _, v := range images[0].Vulns {
		byID[v.ID] = v
	}
	if byID["CVE-3"].Origin != "app" {
		t.Errorf("CVE-3 is not in the base: origin %q", byID["CVE-3"].Origin)
	}
	if !byID["CVE-1"].FixedByUpgrade || byID["CVE-2"].FixedByUpgrade {
		t.Errorf("wrong per-CVE upgrade verdicts: %+v", byID)
	}
}

func TestEnrichLeavesTheUpgradeUndeterminedWithoutACandidate(t *testing.T) {
	// A chained base clears ToRef deliberately: ownership is answerable, "what
	// would this fix" is about a different pair of images.
	s := &stubScanner{byRef: map[string][]string{"base@sha256:aaa": {"CVE-1"}}}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}}
	images := []model.AssessedImage{image("CVE-1")}
	images[0].Upgrade.ToRef = ""

	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	d := images[0].BaseDiff
	if d == nil || d.FromBase != 1 {
		t.Fatalf("ownership should still be established: %+v", d)
	}
	if d.Determined {
		t.Error("no candidate was scanned, so the upgrade question is undetermined")
	}
	if images[0].Vulns[0].OriginDetermined {
		t.Error("per-CVE determination must agree with the summary")
	}
}

func TestUnreadableBaseCostsAttributionNotTheRun(t *testing.T) {
	s := &stubScanner{byRef: map[string][]string{}, fail: map[string]bool{"base@sha256:aaa": true}}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}}
	images := []model.AssessedImage{image("CVE-1")}

	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatalf("one unreadable base must not fail the run: %v", err)
	}
	if images[0].BaseDiff != nil {
		t.Error("a failed scan must not produce a differential")
	}
	if images[0].Vulns[0].Origin != "" {
		t.Errorf("origin should stay unknown, got %q", images[0].Vulns[0].Origin)
	}
}

func TestUnscannedImageIsSkipped(t *testing.T) {
	// Its CVE list is empty for want of a scan, not because it is clean. Diffing
	// would report every base CVE as absent from the application.
	s := &stubScanner{byRef: map[string][]string{"base@sha256:aaa": {"CVE-1"}}}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}}
	images := []model.AssessedImage{image()}
	images[0].Scanned = false

	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if s.count() != 0 {
		t.Errorf("nothing to attribute, so no base should be pulled: %d scans", s.count())
	}
}

func TestBasesAreScannedOncePerReferenceAcrossImages(t *testing.T) {
	// The cost argument: 186 images on one base is one scan of it.
	s := &stubScanner{byRef: map[string][]string{
		"base@sha256:aaa": {"CVE-1"},
		"base:new":        {},
	}}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}}
	var images []model.AssessedImage
	for i := 0; i < 25; i++ {
		images = append(images, image("CVE-1"))
	}
	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if s.count() != 2 {
		t.Errorf("25 images on one base pair should cause 2 scans, got %d", s.count())
	}
	for i := range images {
		if images[i].BaseDiff == nil || images[i].BaseDiff.Clears != 1 {
			t.Fatalf("image %d missed the shared result: %+v", i, images[i].BaseDiff)
		}
	}
}

func TestNonBaseUpgradesAreIgnored(t *testing.T) {
	s := &stubScanner{byRef: map[string][]string{}}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}}
	images := []model.AssessedImage{image("CVE-1")}
	images[0].Upgrade = &model.Upgrade{Kind: "chart", Name: "x"}
	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if s.count() != 0 || images[0].BaseDiff != nil {
		t.Error("a chart upgrade has no base image to diff against")
	}
}
