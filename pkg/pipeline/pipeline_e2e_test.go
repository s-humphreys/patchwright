package pipeline_test

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/pipeline"
	"github.com/s-humphreys/patchwright/pkg/provider"
	"github.com/s-humphreys/patchwright/pkg/sink"

	// Register the rapid7 provider.
	_ "github.com/s-humphreys/patchwright/pkg/provider/rapid7"
)

// stubVulnSource returns fixed vulnerabilities per image ref.
type stubVulnSource struct {
	byRef map[string][]model.Vulnerability
}

func (s stubVulnSource) Name() string { return "stub" }
func (s stubVulnSource) Scan(_ context.Context, img model.Image) ([]model.Vulnerability, error) {
	return s.byRef[img.Ref], nil
}

// TestImageScanFeedsActionability shows a policy that only fires when a fix is
// available, driven by the (stubbed) image scan.
func TestImageScanFeedsActionability(t *testing.T) {
	occ := []model.Occurrence{{
		Image:    model.ParseImageRef("acr.io/app:1"),
		Resource: model.Resource{Dimensions: map[string]string{"namespace": "team-a", "account": "Production"}},
		Counts:   model.Counts{model.SeverityCritical: 1},
	}}
	cfg := &config.Config{
		Owners:     []config.OwnerRule{{Name: "eng", Match: "true", Class: "engineering", TeamFrom: "dimensions['namespace']"}},
		Actionable: []config.PolicyRule{{Name: "fixable-critical", When: "vulns.exists(v, v.severity == 'critical' && v.fix_available)", Priority: "high"}},
	}

	scan := func(fixAvailable bool) []model.Finding {
		t.Helper()
		src := stubVulnSource{byRef: map[string][]model.Vulnerability{
			"acr.io/app:1": {{ID: "CVE-1", Severity: model.SeverityCritical, FixAvailable: fixAvailable}},
		}}
		scanner := enrich.NewImageScanner(src)
		pl, err := pipeline.New(cfg, pipeline.WithImageScanner(&scanner))
		if err != nil {
			t.Fatal(err)
		}
		findings, err := pl.Run(context.Background(), append([]model.Occurrence(nil), occ...))
		if err != nil {
			t.Fatal(err)
		}
		return findings
	}

	// A fixable critical is actionable.
	f := scan(true)
	if len(f) != 1 || !f[0].Actionable {
		t.Fatalf("fixable critical should be actionable, got %+v", f)
	}

	// The same critical with no fix does not match the fix-requiring rule.
	f = scan(false)
	if len(f) != 1 || f[0].Actionable {
		t.Errorf("critical without a fix should not match the fixable rule, got actionable=%v", f[0].Actionable)
	}
}

var update = flag.Bool("update", false, "update golden files")

// testConfig mirrors the shipped example rules but is defined inline so the
// golden output is stable against edits to config/*.yaml.
func testConfig() *config.Config {
	return &config.Config{
		Owners: []config.OwnerRule{
			{Name: "cloud", Match: "image.registry in ['mcr.microsoft.com', 'registry.k8s.io']", Class: "cloud-provider", Team: "aks"},
			{Name: "platform", Match: "dimensions['namespace'] in ['flux-system', 'kube-system']", Class: "platform", Team: "platform-engineering"},
			{Name: "engineering-by-namespace", Match: "true", Class: "engineering", TeamFrom: "dimensions['namespace']"},
		},
		Actionable: []config.PolicyRule{
			{Name: "production-critical", When: "counts['critical'] > 0 && dimensions['account'].exists(a, a.startsWith('Production'))", Priority: "high"},
			{Name: "any-critical", When: "counts['critical'] > 0", Priority: "low"},
		},
		Suppress: []config.PolicyRule{
			{Name: "cloud-provider-managed", When: "owner['class'] == 'cloud-provider'"},
		},
	}
}

func TestAssessGolden(t *testing.T) {
	p, err := provider.New("rapid7", provider.Options{"input": filepath.Join("..", "..", "testdata", "sample.csv")})
	if err != nil {
		t.Fatalf("provider.New: %v", err)
	}
	occ, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	pl, err := pipeline.New(testConfig())
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}
	findings, err := pl.Run(context.Background(), occ)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var buf bytes.Buffer
	// Emit everything (including suppressed) so the golden captures the full
	// classification, not just the actionable subset.
	if err := (sink.JSON{ShowSuppressed: true, Indent: true}).Emit(&buf, findings); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	got := buf.Bytes()

	golden := filepath.Join("..", "..", "testdata", "sample.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("assess output differs from golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestExampleConfigCompiles(t *testing.T) {
	cfg, err := config.Load(
		filepath.Join("..", "..", "config", "ownership.yaml"),
		filepath.Join("..", "..", "config", "policy.yaml"),
	)
	if err != nil {
		t.Fatalf("load shipped config: %v", err)
	}
	if _, err := pipeline.New(cfg); err != nil {
		t.Fatalf("shipped config failed to compile: %v", err)
	}
}
