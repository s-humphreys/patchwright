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
	if got := scores["CVE-2021-44228"]; got.Score != 0.97565 {
		t.Errorf("epss: got %v, want 0.97565", got.Score)
	}
	if got := scores["CVE-2023-0001"]; got.Score != 0.00042 {
		t.Errorf("epss: got %v, want 0.00042", got.Score)
	}
	if _, ok := scores["CVE-BAD"]; ok {
		t.Error("unparseable epss score should be skipped")
	}

	// The percentile is what makes a score readable: 0.00042 sounds like nothing
	// and sits in the 10th percentile, which is nothing; 0.08 also sounds like
	// nothing and can be the 94th, because almost every CVE scores near zero.
	if got := scores["CVE-2021-44228"]; got.Percentile != 0.99 {
		t.Errorf("percentile: got %v, want 0.99", got.Percentile)
	}
	if got := scores["CVE-2023-0001"]; got.Percentile != 0.1 {
		t.Errorf("percentile: got %v, want 0.1", got.Percentile)
	}
}

func TestAMissingPercentileStillYieldsAScore(t *testing.T) {
	// The number people threshold on is the score. A feed that stopped carrying
	// percentiles should cost the ranking, not the queue.
	scores, err := parseEPSS([]byte(`{"data":[{"cve":"CVE-1","epss":"0.5"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := scores["CVE-1"]
	if !ok || got.Score != 0.5 {
		t.Fatalf("score = %+v, want 0.5", got)
	}
	if got.Percentile != 0 {
		t.Errorf("percentile = %v, want 0 when the feed omits it", got.Percentile)
	}
}
