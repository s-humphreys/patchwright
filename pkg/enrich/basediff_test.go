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

// An exploited CVE the base does not explain is the one a ticket must name a
// package for, so the image itself is scanned, and every unnamed CVE on it gets
// a name from that pull.
func TestExploitedScanNamesPackagesTheBaseCannot(t *testing.T) {
	s := &stubScanner{byRef: map[string][]string{
		"base@sha256:aaa": {"CVE-BASE"},
		"base:new":        {},
		"app:1":           {"CVE-BASE", "CVE-KEV", "CVE-QUIET"},
	}}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}, ScanExploited: true}
	img := image("CVE-BASE", "CVE-KEV", "CVE-QUIET")
	img.Vulns[1].KEV, img.Vulns[1].FixAvailable = true, true
	images := []model.AssessedImage{img}

	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	got := images[0]
	if !got.PackagesScanned {
		t.Fatal("image with an exploited application CVE was not scanned")
	}
	if got.Vulns[1].Origin != "app" || len(got.Vulns[1].Packages) != 1 {
		t.Errorf("exploited CVE = origin %q packages %+v, want app with one named package", got.Vulns[1].Origin, got.Vulns[1].Packages)
	}
	// The pull is paid for; a name on the quiet CVE costs nothing.
	if len(got.Vulns[2].Packages) != 1 {
		t.Errorf("unnamed non-exploited CVE was left unnamed after the image was scanned")
	}
	if s.count() != 3 {
		t.Errorf("scans = %d, want 3 (two bases, one image)", s.count())
	}
}

// Nothing exploited outside the base means nothing a ticket needs naming, and no
// pull. Off means no pull however exploited the image is.
func TestExploitedScanIsGatedOnAnUnexplainedExploitedCVE(t *testing.T) {
	s := &stubScanner{byRef: map[string][]string{
		"base@sha256:aaa": {"CVE-KEV"},
		"base:new":        {},
		"app:1":           {"CVE-KEV"},
	}}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}, ScanExploited: true}
	img := image("CVE-KEV", "CVE-OTHER")
	img.Vulns[0].KEV, img.Vulns[0].FixAvailable = true, true
	images := []model.AssessedImage{img}
	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].PackagesScanned || s.count() != 2 {
		t.Errorf("base explains the only exploited CVE, yet the image was scanned (scans=%d)", s.count())
	}

	off := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: &stubScanner{byRef: map[string][]string{
		"base@sha256:aaa": {}, "base:new": {},
	}}}}
	img2 := image("CVE-KEV")
	img2.Vulns[0].KEV, img2.Vulns[0].FixAvailable = true, true
	images = []model.AssessedImage{img2}
	if err := off.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].PackagesScanned {
		t.Error("scanExploited off, yet the image was scanned")
	}
}

// An EPSS above the threshold qualifies as exploited even off the KEV list, and
// an image with no base upgrade at all is still scanned: a chart-upgrade ticket
// needs the package name as much as a rebuild does.
func TestExploitedScanUsesEPSSAndNeedsNoBase(t *testing.T) {
	s := &stubScanner{byRef: map[string][]string{"app:1": {"CVE-HOT"}}}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}, ScanExploited: true, ExploitedEPSS: 0.7}
	img := model.AssessedImage{Image: model.Image{Ref: "app:1"}, Scanned: true,
		Vulns: []model.Vulnerability{{ID: "CVE-HOT", EPSS: 0.75, FixAvailable: true}}}
	images := []model.AssessedImage{img}
	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if !images[0].PackagesScanned || len(images[0].Vulns[0].Packages) != 1 {
		t.Errorf("EPSS 0.75 against a 0.7 threshold should have named the package: %+v", images[0].Vulns[0])
	}
	if images[0].BaseDiff != nil {
		t.Error("no base upgrade, yet a differential was recorded")
	}
}
