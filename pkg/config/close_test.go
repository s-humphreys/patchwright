package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloseNoLongerActionableResolvesAndValidates(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := `jira:
  defaultTicketTemplate: t.tmpl
  closeNoLongerActionable:
    transition: Not To Do
  routes:
    - name: a
      when: "true"
      project: A
      board: 1
      imageLabel: true
    - name: b
      when: "true"
      project: B
      board: 2
      imageLabel: true
      closeNoLongerActionable:
        transition: WON'T BE DONE
        priority: Lowest
`
	cfg, err := Load(write("ok.yaml", base))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	a, b := cfg.Jira.ForProject("A"), cfg.Jira.ForProject("B")
	if a.CloseNoLongerActionable == nil || a.CloseNoLongerActionable.Transition != "Not To Do" || a.CloseNoLongerActionable.Priority != "" {
		t.Errorf("A should inherit the top-level setting: %+v", a.CloseNoLongerActionable)
	}
	if b.CloseNoLongerActionable == nil || b.CloseNoLongerActionable.Transition != "WON'T BE DONE" || b.CloseNoLongerActionable.Priority != "Lowest" {
		t.Errorf("B should use its own: %+v", b.CloseNoLongerActionable)
	}

	bad, err := Load(write("bad.yaml", `jira:
  defaultTicketTemplate: t.tmpl
  routes:
    - name: a
      when: "true"
      project: A
      board: 1
      imageLabel: true
      closeNoLongerActionable:
        priority: Lowest
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Jira validation runs where ticketing is configured, not on every load.
	if err := bad.Jira.Validate(); err == nil || !strings.Contains(err.Error(), "needs a transition") {
		t.Errorf("a block without a transition must fail validation, got %v", err)
	}
}
