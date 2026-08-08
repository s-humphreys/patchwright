package pipeline_test

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/pipeline"
	"github.com/s-humphreys/patchwright/pkg/provider"
	"github.com/s-humphreys/patchwright/pkg/sink"

	// Register the rapid7 provider.
	_ "github.com/s-humphreys/patchwright/pkg/provider/rapid7"
)

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
	findings, err := pl.Run(occ)
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
