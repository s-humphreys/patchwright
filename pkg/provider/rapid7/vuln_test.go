package rapid7

import (
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

func TestLookupToleratesTheImpliedDockerHubRegistry(t *testing.T) {
	// The platform records Docker Hub images without a registry, while an image read
	// from a cluster carries the implied one. Matching only the qualified form missed
	// every Docker Hub image in the estate and reported them as having no data.
	v := &vulnSource{resources: map[string]string{
		"n8nio/n8n:2.36.1":                      "res-1",
		"ghcr.io/metalbear-co/operator:3.196.0": "res-2",
		"redis:7.2":                             "res-3",
	}}
	cases := map[string]string{
		"n8nio/n8n:2.36.1":                      "res-1",
		"docker.io/n8nio/n8n:2.36.1":            "res-1",
		"index.docker.io/n8nio/n8n:2.36.1":      "res-1",
		"ghcr.io/metalbear-co/operator:3.196.0": "res-2",
		"docker.io/library/redis:7.2":           "res-3",
	}
	for ref, want := range cases {
		got, ok := v.lookup(model.ParseImageRef(ref))
		if !ok || got != want {
			t.Errorf("lookup(%q) = %q, %v; want %q", ref, got, ok, want)
		}
	}
	if _, ok := v.lookup(model.ParseImageRef("example.io/absent:1")); ok {
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
