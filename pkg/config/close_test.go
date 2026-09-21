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
	cfg, err := Load(write("ok.yaml", `jira:
  defaultTicketTemplate: t.tmpl
  closeTransitionNoLongerActionable: Not To Do
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
      closeTransitionNoLongerActionable: WON'T BE DONE
      closePriorityNoLongerActionable: Lowest
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := cfg.Jira.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	a, b := cfg.Jira.ForProject("A"), cfg.Jira.ForProject("B")
	if a.CloseTransitionNoLongerActionable != "Not To Do" || a.ClosePriorityNoLongerActionable != "" {
		t.Errorf("A should inherit the top-level setting: %q %q", a.CloseTransitionNoLongerActionable, a.ClosePriorityNoLongerActionable)
	}
	if b.CloseTransitionNoLongerActionable != "WON'T BE DONE" || b.ClosePriorityNoLongerActionable != "Lowest" {
		t.Errorf("B should use its own: %q %q", b.CloseTransitionNoLongerActionable, b.ClosePriorityNoLongerActionable)
	}

	bad, err := Load(write("bad.yaml", `jira:
  defaultTicketTemplate: t.tmpl
  routes:
    - name: a
      when: "true"
      project: A
      board: 1
      imageLabel: true
      closePriorityNoLongerActionable: Lowest
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Jira validation runs where ticketing is configured, not on every load.
	if err := bad.Jira.Validate(); err == nil || !strings.Contains(err.Error(), "without closeTransitionNoLongerActionable") {
		t.Errorf("a priority without the transition must fail validation, got %v", err)
	}
}
