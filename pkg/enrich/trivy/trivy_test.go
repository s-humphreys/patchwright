package trivy

import (
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

const sampleReport = `{
  "Results": [
    {
      "Target": "app (debian 12)",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-0001",
          "PkgName": "libfoo",
          "InstalledVersion": "1.0",
          "FixedVersion": "1.1",
          "Severity": "CRITICAL",
          "Title": "libfoo rce",
          "PrimaryURL": "https://avd.aquasec.com/CVE-2024-0001",
          "CVSS": { "nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 8.1} }
        },
        {
          "VulnerabilityID": "CVE-2024-0002",
          "PkgName": "libbar",
          "InstalledVersion": "2.0",
          "FixedVersion": "",
          "Severity": "HIGH",
          "Title": "libbar dos"
        }
      ]
    },
    {
      "Target": "app (gobinary)",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-0001",
          "PkgName": "otherpkg",
          "FixedVersion": "",
          "Severity": "CRITICAL"
        }
      ]
    }
  ]
}`

func TestParseReport(t *testing.T) {
	vulns, err := parseReport([]byte(sampleReport))
	if err != nil {
		t.Fatal(err)
	}
	// CVE-2024-0001 appears twice (fixed + unfixed); deduped to one, keeping the fix.
	if len(vulns) != 2 {
		t.Fatalf("expected 2 unique CVEs, got %d: %+v", len(vulns), vulns)
	}

	byID := map[string]model.Vulnerability{}
	for _, v := range vulns {
		byID[v.ID] = v
	}

	crit := byID["CVE-2024-0001"]
	if crit.Severity != model.SeverityCritical {
		t.Errorf("severity: got %q, want critical", crit.Severity)
	}
	if !crit.FixAvailable || crit.FixedVersion != "1.1" {
		t.Errorf("expected fix available 1.1, got available=%v version=%q", crit.FixAvailable, crit.FixedVersion)
	}
	if crit.CVSS != 9.8 {
		t.Errorf("expected max CVSS 9.8, got %v", crit.CVSS)
	}
	if len(crit.Links) != 1 {
		t.Errorf("expected a primary URL link, got %v", crit.Links)
	}

	high := byID["CVE-2024-0002"]
	if high.FixAvailable {
		t.Error("CVE-2024-0002 has no fixed version; should not be fix-available")
	}
}

func TestParseReportEmpty(t *testing.T) {
	vulns, err := parseReport([]byte(`{"Results": [{"Target": "x"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected no vulns, got %d", len(vulns))
	}
}
