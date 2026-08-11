package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEffectiveSkipOwnerClasses(t *testing.T) {
	// Unset -> default.
	if got := (ScanConfig{}).EffectiveSkipOwnerClasses(); !reflect.DeepEqual(got, []string{"cloud-provider"}) {
		t.Errorf("unset: got %v, want [cloud-provider]", got)
	}
	// Explicit empty -> scan everything.
	if got := (ScanConfig{SkipOwnerClasses: []string{}}).EffectiveSkipOwnerClasses(); len(got) != 0 {
		t.Errorf("explicit empty: got %v, want []", got)
	}
	// Explicit -> as given.
	if got := (ScanConfig{SkipOwnerClasses: []string{"managed"}}).EffectiveSkipOwnerClasses(); !reflect.DeepEqual(got, []string{"managed"}) {
		t.Errorf("explicit: got %v, want [managed]", got)
	}
}

// The two scan knobs are independent: a file that sets only one must not blank
// out the other set by an earlier file.
func TestLoadMergesScanFieldsIndependently(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := write("a.yaml", "scan:\n  skipOwnerClasses: [managed]\n")
	b := write("b.yaml", "scan:\n  skipRegistries: [acme.azurecr.io]\n")

	cfg, err := Load(a, b)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Scan.SkipOwnerClasses; !reflect.DeepEqual(got, []string{"managed"}) {
		t.Errorf("skipOwnerClasses: got %v, want [managed]", got)
	}
	if got := cfg.Scan.SkipRegistries; !reflect.DeepEqual(got, []string{"acme.azurecr.io"}) {
		t.Errorf("skipRegistries: got %v, want [acme.azurecr.io]", got)
	}
}

// Without a map every ticket is raised at one priority, which flattens the queue:
// the tracker cannot then tell an urgent, exploited, fixable finding from a low one.
func TestJiraPriorityMapping(t *testing.T) {
	cfg := JiraConfig{
		Priority:    "Medium",
		PriorityMap: map[string]string{"urgent": "Highest", "high": "High", "low": "Low"},
	}
	cases := map[string]string{
		"urgent": "Highest",
		"high":   "High",
		"low":    "Low",
		"medium": "Medium", // unmapped, so the configured fallback
		"":       "Medium", // no priority at all
	}
	for in, want := range cases {
		if got := cfg.JiraPriority(in); got != want {
			t.Errorf("JiraPriority(%q) = %q, want %q", in, got, want)
		}
	}

	// With neither a map entry nor a fallback, Jira's own default stands rather
	// than the tool inventing a priority name that may not exist in the scheme.
	empty := JiraConfig{}
	if got := empty.JiraPriority("urgent"); got != "" {
		t.Errorf("unconfigured: got %q, want empty so Jira decides", got)
	}
}
