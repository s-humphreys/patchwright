package server

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// The OpenAPI spec is hand-written, so something has to stop it drifting from the
// routes. These tests compare it against the mux rather than trusting review.

const specPath = "../../docs/api/openapi.yaml"

type openAPISpec struct {
	Paths map[string]map[string]struct {
		Summary string `yaml:"summary"`
	} `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Properties map[string]any `yaml:"properties"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func loadSpec(t *testing.T) openAPISpec {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(specPath))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var spec openAPISpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return spec
}

// routes is the authoritative list, kept beside Handler. A route added there
// without a spec entry fails this test.
func TestSpecCoversEveryRoute(t *testing.T) {
	spec := loadSpec(t)

	var specRoutes []string
	for path, methods := range spec.Paths {
		for method := range methods {
			specRoutes = append(specRoutes, strings.ToUpper(method)+" "+path)
		}
	}
	sort.Strings(specRoutes)

	want := registeredRoutes()
	sort.Strings(want)

	missing := difference(want, specRoutes)
	if len(missing) > 0 {
		t.Errorf("routes served but not in %s: %v", specPath, missing)
	}
	extra := difference(specRoutes, want)
	if len(extra) > 0 {
		t.Errorf("documented in %s but not served: %v", specPath, extra)
	}
}

// Every field of the finding view has to appear in the spec's Finding schema, or a
// consumer reading the docs would not know it exists. Checked by reflection, so a
// new field cannot be added silently.
func TestSpecCoversEveryFindingField(t *testing.T) {
	spec := loadSpec(t)
	schema, ok := spec.Components.Schemas["Finding"]
	if !ok {
		t.Fatal("the spec has no Finding schema")
	}
	for _, field := range jsonFieldNames(reflect.TypeOf(findingViewForSpec())) {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("finding field %q is served but undocumented in %s", field, specPath)
		}
	}
}

func TestSpecCoversEverySummaryField(t *testing.T) {
	spec := loadSpec(t)
	schema, ok := spec.Components.Schemas["Summary"]
	if !ok {
		t.Fatal("the spec has no Summary schema")
	}
	for _, field := range jsonFieldNames(reflect.TypeOf(summaryView{})) {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("summary field %q is served but undocumented in %s", field, specPath)
		}
	}
}

func TestSpecCoversEveryOwnerField(t *testing.T) {
	spec := loadSpec(t)
	schema, ok := spec.Components.Schemas["OwnerStats"]
	if !ok {
		t.Fatal("the spec has no OwnerStats schema")
	}
	for _, field := range jsonFieldNames(reflect.TypeOf(ownerStats{})) {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("owner field %q is served but undocumented in %s", field, specPath)
		}
	}
}

// jsonFieldNames returns the JSON names of a struct's exported fields.
func jsonFieldNames(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		out = append(out, name)
	}
	return out
}

func difference(a, b []string) []string {
	have := map[string]bool{}
	for _, s := range b {
		have[s] = true
	}
	var out []string
	for _, s := range a {
		if !have[s] {
			out = append(out, s)
		}
	}
	return out
}

// findingViewForSpec is the type served on /api/v1/findings, named here so the spec
// test does not depend on the sink package's import path spelling.
func findingViewForSpec() any { return sink.FindingView{} }
