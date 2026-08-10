package rapid7

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// InsightCloudSec emits rows for images it has never assessed: severity UNKNOWN,
// zero counts, and an empty last_assessment. Those zeros must not be mistaken
// for a clean result, so the provider records assessment explicitly.
func TestFetchMarksUnassessedRows(t *testing.T) {
	const header = "organization_service_id,cloud,account_id,account,resource_id,resource_type,resource_name,image_id," +
		"critical_count,high_count,medium_count,low_count,none_count,total_count,riskscore,vulnerability_riskscore," +
		"severity,last_assessment,public_accessible\n"
	rows := header +
		// Assessed, with findings.
		"1,AZURE_ARM,acc,Production UK,kubernetesdeployment:1:orders:x:,containerdeployment,orders," +
		"acme.example.com/orders:1.0.0,3,10,5,2,0,20,700,800,CRITICAL,2026-08-07 18:00:00,0\n" +
		// Never assessed: UNKNOWN severity, all-zero counts, empty timestamp.
		"1,AZURE_ARM,acc,Production UK,kubernetesdeployment:1:billing:y:,containerdeployment,billing," +
		"private.azurecr.io/billing:2.0.0,0,0,0,0,0,0,196,0,UNKNOWN,,0\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "export.csv")
	if err := os.WriteFile(path, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &csvProvider{path: path}
	occ, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(occ) != 2 {
		t.Fatalf("got %d occurrences, want 2", len(occ))
	}

	byRepo := map[string]bool{}
	for _, o := range occ {
		byRepo[o.Image.Repository] = o.Assessed
	}
	if !byRepo["orders"] {
		t.Error("orders has a last_assessment and must be marked assessed")
	}
	if byRepo["billing"] {
		t.Error("billing has an empty last_assessment and must NOT be marked assessed")
	}
}
