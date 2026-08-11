package ticket

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// jsonOf renders a node for assertions that care about structure rather than
// exact Go map shapes.
func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func blocks(t *testing.T, text string) []any {
	t.Helper()
	doc := ADFDocument(text)
	content, ok := doc["content"].([]any)
	if !ok {
		t.Fatalf("document has no content array: %s", jsonOf(t, doc))
	}
	return content
}

func blockType(t *testing.T, node any) string {
	t.Helper()
	m, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("node is not a map: %s", jsonOf(t, node))
	}
	s, _ := m["type"].(string)
	return s
}

// The regression this file exists for: sent as plain paragraphs, a ticket
// rendered "**Business objective/requirements**" with the asterisks visible and
// collapsed each bullet block into one run-on paragraph.
func TestADFRendersHeadingsAndBulletsNotLiteralMarkup(t *testing.T) {
	text := strings.Join([]string{
		"**Business objective/requirements**",
		"",
		"Upgrade nats from 2.10 to 2.14.",
		"",
		"**Technical Requirements & Actions**",
		"",
		"* first item",
		"* second item",
	}, "\n")

	got := blocks(t, text)
	want := []string{"heading", "paragraph", "heading", "bulletList"}
	if len(got) != len(want) {
		t.Fatalf("got %d blocks, want %d: %s", len(got), len(want), jsonOf(t, got))
	}
	for i, w := range want {
		if b := blockType(t, got[i]); b != w {
			t.Errorf("block %d is %q, want %q", i, b, w)
		}
	}

	// No asterisk should survive into rendered text.
	if s := jsonOf(t, got); strings.Contains(s, `**`) || strings.Contains(s, `"* `) {
		t.Errorf("literal markdown survived conversion: %s", s)
	}

	// The bullet list must have one item per line, not one item containing both.
	list := got[3].(map[string]any)["content"].([]any)
	if len(list) != 2 {
		t.Errorf("got %d list items, want 2: %s", len(list), jsonOf(t, list))
	}
}

// A lead-in line followed by bullets is one block in the template but two in
// ADF; flattening it was what produced the run-on paragraph.
func TestADFSplitsLeadInFromItsBullets(t *testing.T) {
	got := blocks(t, "Fixable critical CVEs, most exploitable first:\n* CVE-1\n* CVE-2")
	if len(got) != 2 {
		t.Fatalf("got %d blocks, want 2 (paragraph then list): %s", len(got), jsonOf(t, got))
	}
	if b := blockType(t, got[0]); b != "paragraph" {
		t.Errorf("first block is %q, want paragraph", b)
	}
	if b := blockType(t, got[1]); b != "bulletList" {
		t.Errorf("second block is %q, want bulletList", b)
	}
}

func TestADFBoldWithinAParagraph(t *testing.T) {
	got := jsonOf(t, blocks(t, "Priority is **urgent** today."))
	if !strings.Contains(got, `"strong"`) {
		t.Errorf("inline bold produced no strong mark: %s", got)
	}
	if strings.Contains(got, "**") {
		t.Errorf("asterisks survived: %s", got)
	}
}

// A change target that is not clickable is one the assignee has to copy out by
// hand, which is the whole reason the URL was separated from its path.
func TestADFLinksBareURLs(t *testing.T) {
	got := jsonOf(t, blocks(t, "* Change target: https://dev.example.com/_git/infra (path: bases/app)"))
	if !strings.Contains(got, `"link"`) {
		t.Errorf("no link mark produced: %s", got)
	}
	if !strings.Contains(got, `"href":"https://dev.example.com/_git/infra"`) {
		t.Errorf("href wrong or missing: %s", got)
	}
	// The trailing text must survive as its own node rather than being swallowed
	// into the URL.
	if !strings.Contains(got, "path: bases/app") {
		t.Errorf("text after the URL was lost: %s", got)
	}
}

func TestADFHeadingLevels(t *testing.T) {
	got := blocks(t, "## Section")
	if b := blockType(t, got[0]); b != "heading" {
		t.Fatalf("got %q, want heading", b)
	}
	attrs := got[0].(map[string]any)["attrs"].(map[string]any)
	if attrs["level"] != 2 {
		t.Errorf("level = %v, want 2", attrs["level"])
	}
}

// Multi-line prose keeps its line structure instead of becoming one long line.
func TestADFParagraphKeepsLineBreaks(t *testing.T) {
	got := jsonOf(t, blocks(t, "line one\nline two"))
	if !strings.Contains(got, `"hardBreak"`) {
		t.Errorf("no hard break between lines: %s", got)
	}
}

// Jira rejects a document with no content, so an empty body must still be valid.
func TestADFEmptyBodyIsStillAValidDocument(t *testing.T) {
	doc := ADFDocument("   \n\n  ")
	content, ok := doc["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("empty body produced an invalid document: %s", jsonOf(t, doc))
	}
}

// End to end over the template that actually ships: it is the pairing of
// template notation and converter that has to hold, not either alone.
func TestBundledTemplateConvertsToStructuredADF(t *testing.T) {
	p, err := NewPlanner(configForBundledTemplate())
	if err != nil {
		t.Fatalf("NewPlanner: %v", err)
	}
	plan, err := p.Plan([]sink.FindingView{
		finding("natsio/prometheus-nats-exporter", func(f *sink.FindingView) {
			f.ProviderAssessed = true
			f.Counts["critical"] = 6
			f.Priority = "urgent"
			f.Upgrade.Source = "https://dev.example.com/_git/infra"
			f.Upgrade.SourcePath = "bases/apps/example"
			f.Vulns = []sink.VulnView{
				{ID: "CVE-1", Severity: "critical", CVSS: 9.8, FixAvailable: true, FixedVersion: "1.2.3", EPSS: 0.93},
			}
		}),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Drafts) != 1 {
		t.Fatalf("got %d drafts, want 1", len(plan.Drafts))
	}

	content := blocks(t, plan.Drafts[0].Description)
	var headings, lists int
	for _, b := range content {
		switch blockType(t, b) {
		case "heading":
			headings++
		case "bulletList":
			lists++
		}
	}
	if headings < 4 {
		t.Errorf("got %d headings, want the template's 4 sections: %s", headings, jsonOf(t, content))
	}
	if lists < 2 {
		t.Errorf("got %d bullet lists, want at least 2: %s", lists, jsonOf(t, content))
	}

	// The failure seen on a real ticket: markup rendered as text.
	if s := jsonOf(t, content); strings.Contains(s, "**") {
		t.Errorf("literal ** survived into the document: %s", s)
	}
	// And the change target must be a link.
	if s := jsonOf(t, content); !strings.Contains(s, `"link"`) {
		t.Errorf("change target URL is not linked: %s", s)
	}
}

func configForBundledTemplate() config.JiraConfig {
	return config.JiraConfig{
		Board: 1, Project: "PROJ", ImageField: "customfield_1",
		Template: filepath.Join("..", "..", "config", "templates", "container-vuln.md.tmpl"),
	}
}

// A duplicate check that silently matches nothing is worse than none: it reports
// "would create" for tickets that exist, and a batch run then raises the lot
// again. The "~" operator does exactly that against a multi-value field, so the
// clause must use exact equality.
func TestImageClauseUsesEqualityNotContains(t *testing.T) {
	j := &Jira{cfg: config.JiraConfig{Project: "PROJ", ImageField: "customfield_12345"}}
	got := j.imageClause([]string{"natsio/prometheus-nats-exporter", "nats"})

	if strings.Contains(got, "~") {
		t.Errorf("clause uses the contains operator, which matches nothing on a multi-value field: %s", got)
	}
	if !strings.Contains(got, "cf[12345] IN (") {
		t.Errorf("clause should query the custom field by id with IN: %s", got)
	}
	// Every image in one query: an open ticket on any of them suppresses the group.
	for _, img := range []string{"natsio/prometheus-nats-exporter", "nats"} {
		if !strings.Contains(got, `"`+img+`"`) {
			t.Errorf("clause is missing %q: %s", img, got)
		}
	}
}

func TestImageClauseLabelFallback(t *testing.T) {
	j := &Jira{cfg: config.JiraConfig{Project: "PROJ", ImageLabel: true}}
	got := j.imageClause([]string{"fluxcd/source-controller"})
	if !strings.Contains(got, "labels IN (") {
		t.Errorf("label mode should query labels: %s", got)
	}
	if !strings.Contains(got, ImageLabel("fluxcd/source-controller")) {
		t.Errorf("label value not sanitised into the clause: %s", got)
	}
}

// An odd image name must not be able to break the query or change its meaning.
func TestQuoteJQLEscapes(t *testing.T) {
	if got := quoteJQL(`we"ird`); !strings.Contains(got, `\"`) {
		t.Errorf("quote not escaped: %s", got)
	}
	if got := quoteJQL(`back\slash`); !strings.Contains(got, `\\`) {
		t.Errorf("backslash not escaped: %s", got)
	}
}
