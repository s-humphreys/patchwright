package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The history backfill reads tickets and never raises one, so it must load a config
// with no template while the ticket command still refuses it.
func TestValidateReadNeedsNoTemplate(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg, err := Load(write("read.yaml", `jira:
  routes:
    - name: a
      when: "true"
      project: A
      board: 1
      imageLabel: true
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := cfg.Jira.ValidateRead(); err != nil {
		t.Errorf("ValidateRead: %v", err)
	}
	if err := cfg.Jira.Validate(); err == nil || !strings.Contains(err.Error(), "defaultTicketTemplate") {
		t.Errorf("Validate = %v, want the template to be required for raising tickets", err)
	}
	// Reading still needs the board's project and image field.
	bare, err := Load(write("bare.yaml", `jira:
  routes:
    - name: a
      when: "true"
      board: 1
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := bare.Jira.ValidateRead(); err == nil || !strings.Contains(err.Error(), "project") {
		t.Errorf("ValidateRead = %v, want project required", err)
	}
}
