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
