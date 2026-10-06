package rapid7

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// The server holds one source for its lifetime. Mapped once per process, an image
// deployed after the first run had no resource to ask about, and the share of images
// with CVE detail fell run by run until a restart.
func TestEachRunMapsTheResourcesItScans(t *testing.T) {
	var listings atomic.Int64
	var running atomic.Value
	running.Store(`{"image_id":"acr.io/app:1","resource_id":"res-1","assessment_info":{"status":"COMPLETED"}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/cvm/resource/vulnerabilities" {
			listings.Add(1)
			fmt.Fprintf(w, `{"data":[%s],"page":1,"page_size":1,"total_count":1,"total_pages":1}`, running.Load())
			return
		}
		fmt.Fprint(w, `{"data":[{"cve_id":"CVE-2026-1","severity":"HIGH"}],"page":1,"page_size":1,"total_count":1,"total_pages":1}`)
	}))
	t.Cleanup(srv.Close)
	v := &vulnSource{api: &apiProvider{baseURL: srv.URL, apiKey: "k", client: srv.Client()}}

	run := enrich.WithRunCache(context.Background())
	for _, ref := range []string{"acr.io/app:1", "acr.io/app:1"} {
		if _, err := v.Scan(run, model.ParseImageRef(ref)); err != nil {
			t.Fatalf("first run, %s: %v", ref, err)
		}
	}
	if got := listings.Load(); got != 1 {
		t.Errorf("one run swept the resource listing %d times, want 1", got)
	}

	running.Store(`{"image_id":"acr.io/app:2","resource_id":"res-2","assessment_info":{"status":"COMPLETED"}}`)
	vulns, err := v.Scan(enrich.WithRunCache(context.Background()), model.ParseImageRef("acr.io/app:2"))
	if err != nil || len(vulns) != 1 {
		t.Fatalf("an image deployed after the first run must still be scanned: %v, %+v", err, vulns)
	}
	if got := listings.Load(); got != 2 {
		t.Errorf("two runs swept the resource listing %d times, want 2", got)
	}
}

func TestLookupToleratesTheImpliedDockerHubRegistry(t *testing.T) {
	// The platform records Docker Hub images without a registry, while an image read
	// from a cluster carries the implied one. Matching only the qualified form missed
	// every Docker Hub image in the estate and reported them as having no data.
	resources := map[string]string{
		"n8nio/n8n:2.36.1":                      "res-1",
		"ghcr.io/metalbear-co/operator:3.196.0": "res-2",
		"redis:7.2":                             "res-3",
	}
	cases := map[string]string{
		"n8nio/n8n:2.36.1":                      "res-1",
		"docker.io/n8nio/n8n:2.36.1":            "res-1",
		"index.docker.io/n8nio/n8n:2.36.1":      "res-1",
		"ghcr.io/metalbear-co/operator:3.196.0": "res-2",
		"docker.io/library/redis:7.2":           "res-3",
	}
	for ref, want := range cases {
		got, ok := lookup(resources, model.ParseImageRef(ref))
		if !ok || got != want {
			t.Errorf("lookup(%q) = %q, %v; want %q", ref, got, ok, want)
		}
	}
	if _, ok := lookup(resources, model.ParseImageRef("example.io/absent:1")); ok {
		t.Error("an image the platform does not run must not match")
	}
}

func TestVulnerabilityMapping(t *testing.T) {
	row := cveRow{
		CVEID: "cve-2025-4802", Severity: "HIGH", CVSS: 7,
		RiskScore: 578.512, HasExploits: true,
		FirstFound: "2026-08-15T00:41:45",
	}
	row.Meta.FixedVersion = "2.38-13.azl3"
	v := row.vulnerability()
	if v.ID != "CVE-2025-4802" || v.Severity != "high" {
		t.Errorf("id/severity normalisation: %+v", v)
	}
	if !v.FixAvailable || v.FixedVersion != "2.38-13.azl3" {
		t.Errorf("a stated fixed version means a fix is available: %+v", v)
	}
	if !v.ExploitKnown || v.RiskScore != 578.512 {
		t.Errorf("platform signals lost: %+v", v)
	}
	if v.EPSS != 0 || v.KEV {
		t.Errorf("this API carries neither EPSS nor KEV; inventing them would be a lie: %+v", v)
	}
	if v.FirstSeen.IsZero() {
		t.Error("first_found should be carried, so CVE ageing works without a second source")
	}
}

func TestNoFixedVersionMeansNoFix(t *testing.T) {
	// The whole "fixable" priority tier rests on this distinction.
	v := cveRow{CVEID: "CVE-1", Severity: "critical"}.vulnerability()
	if v.FixAvailable {
		t.Error("no fixed version must not report a fix as available")
	}
}
