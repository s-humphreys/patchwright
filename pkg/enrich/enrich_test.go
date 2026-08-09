package enrich_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"

	_ "github.com/s-humphreys/patchwright/pkg/enrich/file"
)

// fakeSource is a LiveSource (and optionally LabelSource) returning fixed data.
type fakeSource struct {
	running  map[string]int
	nsLabels map[string]map[string]string
}

func (f fakeSource) Name() string                                          { return "fake" }
func (f fakeSource) RunningImages(context.Context) (map[string]int, error) { return f.running, nil }
func (f fakeSource) NamespaceLabels(context.Context) (map[string]map[string]string, error) {
	return f.nsLabels, nil
}

func occ(ref string) model.Occurrence {
	return model.Occurrence{Image: model.ParseImageRef(ref)}
}

func TestLivenessMarksRunningAndNotRunning(t *testing.T) {
	src := fakeSource{running: map[string]int{
		"acr.io/app:1": 3, // running
		// acr.io/old:2 intentionally absent -> not running
	}}
	occurrences := []model.Occurrence{occ("acr.io/app:1"), occ("acr.io/old:2")}

	if err := enrich.NewLiveness(src).Enrich(context.Background(), occurrences); err != nil {
		t.Fatal(err)
	}

	if !occurrences[0].Reconciled || !occurrences[0].Live {
		t.Errorf("app:1 should be reconciled+live, got reconciled=%v live=%v", occurrences[0].Reconciled, occurrences[0].Live)
	}
	if !occurrences[1].Reconciled || occurrences[1].Live {
		t.Errorf("old:2 should be reconciled and NOT live, got reconciled=%v live=%v", occurrences[1].Reconciled, occurrences[1].Live)
	}
}

func TestNamespaceLabelerAttachesLabelsByNamespace(t *testing.T) {
	src := fakeSource{nsLabels: map[string]map[string]string{
		"orders": {"team": "rewards", "istio-injection": "enabled"},
	}}
	occurrences := []model.Occurrence{
		{Resource: model.Resource{Dimensions: map[string]string{"namespace": "orders"}}},
		{Resource: model.Resource{Dimensions: map[string]string{"namespace": "unlabeled-ns"}}},
	}

	if err := enrich.NewNamespaceLabeler(src).Enrich(context.Background(), occurrences); err != nil {
		t.Fatal(err)
	}

	if got := occurrences[0].Resource.Labels["team"]; got != "rewards" {
		t.Errorf("expected team=rewards attached, got %q", got)
	}
	if len(occurrences[1].Resource.Labels) != 0 {
		t.Errorf("expected no labels for unlabeled namespace, got %v", occurrences[1].Resource.Labels)
	}
}

func TestNamespaceLabelerDoesNotOverwriteExistingLabel(t *testing.T) {
	src := fakeSource{nsLabels: map[string]map[string]string{
		"ns": {"team": "from-namespace"},
	}}
	occurrences := []model.Occurrence{{
		Resource: model.Resource{
			Dimensions: map[string]string{"namespace": "ns"},
			Labels:     map[string]string{"team": "from-workload"},
		},
	}}

	if err := enrich.NewNamespaceLabeler(src).Enrich(context.Background(), occurrences); err != nil {
		t.Fatal(err)
	}
	if got := occurrences[0].Resource.Labels["team"]; got != "from-workload" {
		t.Errorf("existing label should win, got %q", got)
	}
}

// fakeVulnSource returns fixed per-image vulnerabilities.
type fakeVulnSource struct {
	byRef map[string][]model.Vulnerability
}

func (f fakeVulnSource) Name() string { return "fake-vuln" }
func (f fakeVulnSource) Scan(_ context.Context, img model.Image) ([]model.Vulnerability, error) {
	return f.byRef[img.Ref], nil
}

// preparingSource is a VulnSource that also implements Preparer, tracking calls.
type preparingSource struct {
	calls *int
	err   error
}

func (p preparingSource) Name() string { return "preparing" }
func (p preparingSource) Scan(context.Context, model.Image) ([]model.Vulnerability, error) {
	return []model.Vulnerability{{ID: "CVE-1"}}, nil
}
func (p preparingSource) Prepare(context.Context) error { *p.calls++; return p.err }

func TestImageScannerCallsPrepareAndSurfacesErrors(t *testing.T) {
	images := []model.AssessedImage{{Image: model.ParseImageRef("a:1")}}

	// Prepare is invoked once when there is work.
	calls := 0
	if err := enrich.NewImageScanner(preparingSource{calls: &calls}).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("Prepare should be called exactly once, got %d", calls)
	}

	// A Prepare error is surfaced (not swallowed).
	calls = 0
	err := enrich.NewImageScanner(preparingSource{calls: &calls, err: fmt.Errorf("db download failed")}).
		EnrichImages(context.Background(), images)
	if err == nil || !strings.Contains(err.Error(), "db download failed") {
		t.Errorf("expected prepare error surfaced, got %v", err)
	}
}

func TestImageScannerSkipsPrepareWhenNothingToScan(t *testing.T) {
	calls := 0
	scanner := enrich.NewImageScanner(preparingSource{calls: &calls})
	scanner.Skip = func(model.AssessedImage) bool { return true } // skip everything
	images := []model.AssessedImage{{Image: model.ParseImageRef("a:1")}}
	if err := scanner.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Errorf("Prepare should not run when there is nothing to scan, got %d calls", calls)
	}
}

func TestImageScannerSkipsFilteredImages(t *testing.T) {
	src := fakeVulnSource{byRef: map[string][]model.Vulnerability{
		"acr.io/app:1":     {{ID: "CVE-1"}},
		"acr.io/managed:1": {{ID: "CVE-2"}},
	}}
	images := []model.AssessedImage{
		{Image: model.ParseImageRef("acr.io/app:1"), Occurrences: []model.Occurrence{{Owner: model.Owner{Class: "engineering"}}}},
		{Image: model.ParseImageRef("acr.io/managed:1"), Occurrences: []model.Occurrence{{Owner: model.Owner{Class: "cloud-provider"}}}},
	}
	scanner := enrich.NewImageScanner(src)
	scanner.Skip = func(img model.AssessedImage) bool {
		for _, o := range img.Occurrences {
			if o.Owner.Class != "cloud-provider" {
				return false
			}
		}
		return len(img.Occurrences) > 0
	}
	if err := scanner.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if !images[0].Scanned || len(images[0].Vulns) != 1 {
		t.Errorf("engineering image should be scanned, got %+v", images[0])
	}
	if images[1].Scanned || len(images[1].Vulns) != 0 {
		t.Errorf("cloud-provider image should be skipped, got %+v", images[1])
	}
}

func TestImageScannerPopulatesVulns(t *testing.T) {
	src := fakeVulnSource{byRef: map[string][]model.Vulnerability{
		"acr.io/app:1": {{ID: "CVE-1", Severity: model.SeverityCritical, FixAvailable: true, FixedVersion: "1.2"}},
	}}
	images := []model.AssessedImage{
		{Image: model.ParseImageRef("acr.io/app:1")},
		{Image: model.ParseImageRef("acr.io/other:2")},
	}
	if err := enrich.NewImageScanner(src).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if len(images[0].Vulns) != 1 || !images[0].Vulns[0].FixAvailable {
		t.Errorf("app:1 should have 1 fix-available vuln, got %+v", images[0].Vulns)
	}
	if len(images[1].Vulns) != 0 {
		t.Errorf("other:2 should have no vulns, got %+v", images[1].Vulns)
	}
}

// fakeExploitSource returns fixed exploit intel per CVE.
type fakeExploitSource struct{ info map[string]enrich.ExploitInfo }

func (f fakeExploitSource) Name() string { return "fake-exploit" }
func (f fakeExploitSource) Lookup(_ context.Context, ids []string) (map[string]enrich.ExploitInfo, error) {
	out := map[string]enrich.ExploitInfo{}
	for _, id := range ids {
		if x, ok := f.info[id]; ok {
			out[id] = x
		}
	}
	return out, nil
}

func TestExploitEnricherAnnotatesVulns(t *testing.T) {
	images := []model.AssessedImage{
		{Image: model.ParseImageRef("acr.io/app:1"), Vulns: []model.Vulnerability{{ID: "CVE-1"}, {ID: "CVE-2"}}},
		{Image: model.ParseImageRef("acr.io/clean:1")}, // no CVEs
	}
	src := fakeExploitSource{info: map[string]enrich.ExploitInfo{
		"CVE-1": {EPSS: 0.9, KEV: true},
	}}
	if err := enrich.NewExploitEnricher(src).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	v := images[0].Vulns
	if !v[0].KEV || v[0].EPSS != 0.9 {
		t.Errorf("CVE-1 should be KEV with EPSS 0.9, got %+v", v[0])
	}
	if v[1].KEV || v[1].EPSS != 0 {
		t.Errorf("CVE-2 should be unannotated, got %+v", v[1])
	}
	// Both images must be marked checked — even the one with no CVEs — so the
	// report can tell "0 known-exploited" from "not checked".
	if !images[0].ExploitChecked || !images[1].ExploitChecked {
		t.Errorf("all images should be ExploitChecked, got %v / %v", images[0].ExploitChecked, images[1].ExploitChecked)
	}
}

// erroringVulnSource fails for image refs in failRefs, succeeds otherwise.
type erroringVulnSource struct{ failRefs map[string]bool }

func (e erroringVulnSource) Name() string { return "erroring" }
func (e erroringVulnSource) Scan(_ context.Context, img model.Image) ([]model.Vulnerability, error) {
	if e.failRefs[img.Ref] {
		return nil, fmt.Errorf("unauthorized: no pull credentials")
	}
	return []model.Vulnerability{{ID: "CVE-9"}}, nil
}

func TestImageScannerToleratesPartialFailures(t *testing.T) {
	src := erroringVulnSource{failRefs: map[string]bool{"private.io/app:1": true}}
	images := []model.AssessedImage{
		{Image: model.ParseImageRef("private.io/app:1")}, // fails
		{Image: model.ParseImageRef("public.io/app:1")},  // succeeds
	}
	if err := enrich.NewImageScanner(src).EnrichImages(context.Background(), images); err != nil {
		t.Fatalf("partial failure should not error, got %v", err)
	}
	if images[0].Scanned || images[0].ScanError == "" {
		t.Errorf("private image should be unscanned with a ScanError, got %+v", images[0])
	}
	if !images[1].Scanned || len(images[1].Vulns) != 1 {
		t.Errorf("public image should be scanned, got %+v", images[1])
	}
}

func TestImageScannerFailsWhenAllFail(t *testing.T) {
	src := erroringVulnSource{failRefs: map[string]bool{"a:1": true, "b:1": true}}
	images := []model.AssessedImage{
		{Image: model.ParseImageRef("a:1")},
		{Image: model.ParseImageRef("b:1")},
	}
	if err := enrich.NewImageScanner(src).EnrichImages(context.Background(), images); err == nil {
		t.Error("expected an error when every scan fails (systemic)")
	}
}

func TestFileSourceParsesSnapshotAndNormalizes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "live.txt")
	// Includes a comment, a blank line, and refs written in different forms.
	content := "# live images\n\nacr.io/app:1\nopenpolicyagent/gatekeeper:v3.23.0\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	src, err := enrich.NewLiveSource("file", enrich.Options{"path": path})
	if err != nil {
		t.Fatal(err)
	}
	running, err := src.RunningImages(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if running["acr.io/app:1"] != 1 {
		t.Errorf("expected acr.io/app:1 running, got %v", running)
	}
	// docker hub image should be normalized to include the implied registry.
	if running["docker.io/openpolicyagent/gatekeeper:v3.23.0"] != 1 {
		t.Errorf("expected normalized docker.io/openpolicyagent/gatekeeper:v3.23.0, got %v", running)
	}
}

func TestFileSourceRequiresPath(t *testing.T) {
	if _, err := enrich.NewLiveSource("file", enrich.Options{}); err == nil {
		t.Error("expected error when path option is missing")
	}
}

func TestUnknownLiveSource(t *testing.T) {
	if _, err := enrich.NewLiveSource("nope", enrich.Options{}); err == nil {
		t.Error("expected error for unknown live source")
	}
}
