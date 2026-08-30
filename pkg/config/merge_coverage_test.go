package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Load merges configs field by field, by hand. That is a trap: a field added to a
// struct is parsed happily and then silently dropped by the merge, so a setting
// somebody wrote in YAML does nothing and reports no error.
//
// It has already happened once - remediation.baseDiff parsed and was never
// copied, so base scanning stayed off however it was configured. This walks the
// remediation config with reflection and fails on any field the merge forgets,
// rather than trusting the next person to remember.
func TestEveryRemediationFieldSurvivesTheMerge(t *testing.T) {
	yaml := `
remediation:
  firstPartyRegistries: [example.azurecr.io]
  supportProducts:
    example.azurecr.io/dotnet/aspnet/10: dotnet
  base:
    refLabels: [my.base.ref]
    digestLabels: [my.base.digest]
    repoLabels: [my.repo]
    maxDepth: 7
  baseDiff:
    enabled: true
    binary: /usr/local/bin/trivy
    timeout: 9m
    concurrency: 6
  upgrade:
    strategy: patch
    rules:
      - name: docker.io/python
        ceiling: "3.12"
  inFlight:
    provider: azuredevops
`
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	// Every field set above must be non-zero after the merge. A zero one means the
	// merge dropped it.
	r := reflect.ValueOf(cfg.Remediation)
	for i := 0; i < r.NumField(); i++ {
		name := r.Type().Field(i).Name
		if r.Field(i).IsZero() {
			t.Errorf("remediation.%s was set in YAML but is zero after Load: the merge in Load drops it", name)
		}
	}

	// And the nested ones the merge copies individually.
	bd := reflect.ValueOf(cfg.Remediation.BaseDiff)
	for i := 0; i < bd.NumField(); i++ {
		if bd.Field(i).IsZero() {
			t.Errorf("remediation.baseDiff.%s was set in YAML but is zero after Load",
				bd.Type().Field(i).Name)
		}
	}
	b := reflect.ValueOf(cfg.Remediation.Base)
	for i := 0; i < b.NumField(); i++ {
		if b.Field(i).IsZero() {
			t.Errorf("remediation.base.%s was set in YAML but is zero after Load",
				b.Type().Field(i).Name)
		}
	}
}
