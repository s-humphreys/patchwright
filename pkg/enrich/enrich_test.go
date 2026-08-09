package enrich_test

import (
	"context"
	"os"
	"path/filepath"
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
