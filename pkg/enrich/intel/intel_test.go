package intel

import "testing"

func TestParseKEV(t *testing.T) {
	data := []byte(`{"title":"CISA KEV","vulnerabilities":[
		{"cveID":"CVE-2021-44228","vendorProject":"Apache"},
		{"cveID":"CVE-2023-0001"},
		{"cveID":""}
	]}`)
	set, err := parseKEV(data)
	if err != nil {
		t.Fatal(err)
	}
	if !set["CVE-2021-44228"] || !set["CVE-2023-0001"] {
		t.Errorf("expected both CVEs in KEV set, got %v", set)
	}
	if len(set) != 2 {
		t.Errorf("empty cveID should be skipped; got %d entries: %v", len(set), set)
	}
}

func TestParseEPSS(t *testing.T) {
	data := []byte(`{"status":"OK","data":[
		{"cve":"CVE-2021-44228","epss":"0.97565","percentile":"0.99"},
		{"cve":"CVE-2023-0001","epss":"0.00042","percentile":"0.1"},
		{"cve":"CVE-BAD","epss":"n/a"}
	]}`)
	scores, err := parseEPSS(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := scores["CVE-2021-44228"]; got != 0.97565 {
		t.Errorf("epss: got %v, want 0.97565", got)
	}
	if got := scores["CVE-2023-0001"]; got != 0.00042 {
		t.Errorf("epss: got %v, want 0.00042", got)
	}
	if _, ok := scores["CVE-BAD"]; ok {
		t.Error("unparseable epss score should be skipped")
	}
}
