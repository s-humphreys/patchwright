package ticket

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"text/template"
)

// The bundled template is the starting point every deployment copies, so it has
// to survive the converter: a bullet abutting the next heading, or a table with
// no blank line before it, renders its markup literally in Jira.
func TestBundledTemplateThroughADF(t *testing.T) {
	raw, err := os.ReadFile("../../config/templates/container-vuln.md.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	tm := template.Must(template.New("t").Parse(string(raw)))
	var sb strings.Builder
	if err := tm.Execute(&sb, TemplateData{
		ServiceName: "svc", Priority: "urgent", ImageCount: 1, WorkloadCount: 4,
		ProviderAssessed: true, CriticalCount: 2, HighCount: 9,
		Deployments: []Deployment{
			{Tag: "1.2.3", Environment: "production", Namespaces: []string{"a"}, Accounts: []string{"Prod UK"}},
			{Tag: "1.2.2", Namespaces: []string{"a", "b"}, Accounts: []string{"Dev"}},
		},
		Upgrades: []ImageUpgrade{{Repo: "svc", Current: "1.2.3", Latest: "1.3.0", Direct: true}},
	}); err != nil {
		t.Fatal(err)
	}
	body := sb.String()
	body = body[strings.Index(body, "\n")+1:]
	b, _ := json.Marshal(ADFDocument(body))
	if !strings.Contains(string(b), `"type":"table"`) {
		t.Fatalf("bundled template did not produce a table:\n%s", body)
	}
	var doc struct {
		Content []struct {
			Type    string `json:"type"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"content"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, blk := range doc.Content {
		for _, s := range blk.Content {
			// A literal marker in a paragraph means a block was demoted: the
			// notation reached Jira as text instead of becoming a list or heading.
			if blk.Type == "paragraph" && (strings.HasPrefix(s.Text, "* ") || strings.HasPrefix(s.Text, "**") || strings.HasPrefix(s.Text, "|")) {
				t.Errorf("markup rendered literally in a paragraph: %q", s.Text)
			}
		}
	}
}
