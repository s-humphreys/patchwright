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
	base := TemplateData{
		ServiceName: "svc", Priority: "urgent", ImageCount: 1, WorkloadCount: 4,
		ProviderAssessed: true, CriticalCount: 2, HighCount: 9,
		Deployments: []Deployment{
			{Repo: "svc", Tag: "1.2.3", Environment: "production", Namespaces: []string{"a"}, Accounts: []string{"Prod UK"}},
			{Repo: "svc", Tag: "1.2.2", Namespaces: []string{"a", "b"}, Accounts: []string{"Dev"}},
		},
		Upgrades:   []ImageUpgrade{{Repo: "svc", Current: "1.2.3", Latest: "1.3.0", Direct: true}},
		BuildRepos: []string{"org/svc"},
	}
	withUrgent := base
	withUrgent.Upgrade = &UpgradeData{Kind: "base", Name: "example.io/base", Current: "aaa", Latest: "bbb"}
	withUrgent.Urgent = []UrgentVuln{
		{Vuln: Vuln{ID: "CVE-1", KEV: true}, Why: "exploited in the wild", Cleared: true, Measured: true,
			Where: "The base image", Action: "Nothing extra. The rebuild above removes it.", Reference: "https://www.cve.org/CVERecord?id=CVE-1"},
		{Vuln: Vuln{ID: "CVE-2", EPSS: 0.9}, Why: "EPSS 0.90", Cleared: true, Measured: true,
			Where: "The base image (openssl)", Action: "Nothing extra. The rebuild above removes it.", Reference: "https://www.cve.org/CVERecord?id=CVE-2"},
	}
	withUrgent.UrgentCleared = 2
	for name, data := range map[string]TemplateData{"plain": base, "urgent": withUrgent} {
		t.Run(name, func(t *testing.T) { checkBundledADF(t, tm, data) })
	}
}

func checkBundledADF(t *testing.T, tm *template.Template, data TemplateData) {
	var sb strings.Builder
	if err := tm.Execute(&sb, data); err != nil {
		t.Fatal(err)
	}
	body := sb.String()
	body = body[strings.Index(body, "\n")+1:]
	b, _ := json.Marshal(ADFDocument(body))
	if !strings.Contains(string(b), `"type":"table"`) {
		t.Fatalf("bundled template did not produce a table:\n%s", body)
	}
	if len(data.Urgent) > 0 {
		if strings.Count(string(b), `"type":"table"`) < 2 {
			t.Fatalf("urgent rows did not render as a table:\n%s", body)
		}
		if !strings.Contains(body, "measured to clear each of these") {
			t.Errorf("body does not say the rows are what the change clears:\n%s", body)
		}
		if strings.Contains(body, "could not be measured") || strings.Contains(body, " of 2") {
			t.Errorf("body still counts against CVEs it does not list:\n%s", body)
		}
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
