package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

func TestParseOutputs(t *testing.T) {
	got, err := parseOutputs([]string{"json:full=a.json", "table=-", "ndjson:queue=b.ndjson"})
	if err != nil {
		t.Fatalf("parseOutputs: %v", err)
	}
	want := []outputSpec{
		{format: "json", view: viewFull, path: "a.json"},
		{format: "table", view: "", path: "-"},
		{format: "ndjson", view: viewQueue, path: "b.ndjson"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d specs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("spec %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseOutputsRejectsBadSpecs(t *testing.T) {
	for _, v := range []string{
		"json",           // no path
		"json=",          // empty path
		"=a.json",        // no format
		"yaml=a.yaml",    // unknown format
		"json:some=a.js", // unknown view
	} {
		if _, err := parseOutputs([]string{v}); err == nil {
			t.Errorf("parseOutputs(%q): want error, got nil", v)
		}
	}
}

// The point of --output is that one assessment yields differently scoped
// results: the queue view must not contain what the full view keeps.
func TestEmitOutputsAppliesPerOutputView(t *testing.T) {
	findings := []model.Finding{
		{
			Image:      model.Image{Ref: "acme/actionable:1"},
			Actionable: true,
			Priority:   model.PriorityHigh,
		},
		{
			Image:      model.Image{Ref: "acme/suppressed:1"},
			Suppressed: true,
		},
	}

	dir := t.TempDir()
	full := filepath.Join(dir, "full.json")
	queue := filepath.Join(dir, "queue.json")
	specs, err := parseOutputs([]string{"json:full=" + full, "json:queue=" + queue})
	if err != nil {
		t.Fatalf("parseOutputs: %v", err)
	}

	var stdout bytes.Buffer
	// Global display flags are the defaults; the per-output views must override.
	if err := emitOutputs(specs, findings, &stdout, "", false, false); err != nil {
		t.Fatalf("emitOutputs: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout: got %q, want empty (both outputs are files)", stdout.String())
	}

	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		return string(b)
	}
	if body := read(full); !strings.Contains(body, "acme/suppressed:1") || !strings.Contains(body, "acme/actionable:1") {
		t.Errorf("full view is missing findings: %s", body)
	}
	if body := read(queue); strings.Contains(body, "acme/suppressed:1") {
		t.Errorf("queue view leaked a suppressed finding: %s", body)
	} else if !strings.Contains(body, "acme/actionable:1") {
		t.Errorf("queue view is missing the actionable finding: %s", body)
	}
}

// A ticket covering one image of a group suppresses the whole group, which is
// right (they are one change) but can leave most of it unticketed. Reporting only
// "skipped, DVOP-4061 is open" hid that: two urgent nats images with direct fixes
// got no ticket and nothing said so.
func TestCoverageForReportsUncoveredImages(t *testing.T) {
	index := map[string][]ticket.Existing{
		"natsio/prometheus-nats-exporter": {{Key: "DVOP-4061", Status: "NEEDS REFINEMENT"}},
	}
	d := ticket.Draft{
		Summary: "Upgrade event-bus images (3) to their latest versions",
		Images: []string{
			"nats", "natsio/nats-server-config-reloader", "natsio/prometheus-nats-exporter",
		},
	}

	c := coverageFor(index, d)
	if !c.skipped() {
		t.Fatal("an open ticket on any image must suppress the group")
	}
	if len(c.covered) != 1 || c.covered[0] != "natsio/prometheus-nats-exporter" {
		t.Errorf("covered = %v, want just the ticketed image", c.covered)
	}
	want := []string{"nats", "natsio/nats-server-config-reloader"}
	if len(c.uncovered) != len(want) {
		t.Fatalf("uncovered = %v, want %v", c.uncovered, want)
	}
	for i, w := range want {
		if c.uncovered[i] != w {
			t.Errorf("uncovered[%d] = %q, want %q", i, c.uncovered[i], w)
		}
	}

	// The report has to name them, or the gap stays invisible.
	var buf bytes.Buffer
	reportCoverage(&buf, c)
	out := buf.String()
	for _, img := range want {
		if !strings.Contains(out, img) {
			t.Errorf("report does not name the uncovered image %s:\n%s", img, out)
		}
	}
	if !strings.Contains(out, "NOT covered") {
		t.Errorf("report does not flag the gap:\n%s", out)
	}
}

// With nothing open, the draft proceeds and there is no gap to report.
func TestCoverageForFullyUncoveredDraftIsNotSkipped(t *testing.T) {
	c := coverageFor(map[string][]ticket.Existing{}, ticket.Draft{Images: []string{"a/b", "c/d"}})
	if c.skipped() {
		t.Error("no open tickets should not suppress a draft")
	}
	if len(c.uncovered) != 2 {
		t.Errorf("uncovered = %v, want both images", c.uncovered)
	}

	var buf bytes.Buffer
	reportCoverage(&buf, c)
	if strings.Contains(buf.String(), "NOT covered") {
		t.Error("nothing was skipped, so there is no gap to warn about")
	}
}

// Every image ticketed: a skip with no gap, which needs no warning.
func TestCoverageForFullyCoveredDraftReportsNoGap(t *testing.T) {
	index := map[string][]ticket.Existing{
		"a/b": {{Key: "PROJ-1", Status: "To Do"}},
		"c/d": {{Key: "PROJ-1", Status: "To Do"}},
	}
	c := coverageFor(index, ticket.Draft{Images: []string{"a/b", "c/d"}})
	if !c.skipped() || len(c.uncovered) != 0 {
		t.Fatalf("covered=%v uncovered=%v, want all covered", c.covered, c.uncovered)
	}
	// One ticket covering both images must be listed once.
	if len(c.tickets) != 1 {
		t.Errorf("tickets = %+v, want PROJ-1 de-duplicated", c.tickets)
	}
	var buf bytes.Buffer
	reportCoverage(&buf, c)
	if strings.Contains(buf.String(), "NOT covered") {
		t.Errorf("no gap should be reported:\n%s", buf.String())
	}
}
