package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
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
