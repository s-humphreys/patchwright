package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/s-humphreys/patchwright/pkg/analytics"
	"github.com/s-humphreys/patchwright/pkg/history"
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

// The Finding guard only ever checked TOP-LEVEL fields, so a whole nested view
// could be served undocumented. These cover the two that carry the base
// differential, which is the part a consumer is most likely to misread if the
// spec does not spell out what an absent value means.
func TestSpecCoversEveryVulnerabilityField(t *testing.T) {
	spec := loadSpec(t)
	schema, ok := spec.Components.Schemas["Vulnerability"]
	if !ok {
		t.Fatal("the spec has no Vulnerability schema")
	}
	for _, field := range jsonFieldNames(reflect.TypeOf(sink.VulnView{})) {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("vulnerability field %q is served but undocumented in %s", field, specPath)
		}
	}
}

func TestSpecCoversEveryBaseDiffField(t *testing.T) {
	spec := loadSpec(t)
	schema, ok := spec.Components.Schemas["BaseDiff"]
	if !ok {
		t.Fatal("the spec has no BaseDiff schema")
	}
	for _, field := range jsonFieldNames(reflect.TypeOf(sink.BaseDiffView{})) {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("base diff field %q is served but undocumented in %s", field, specPath)
		}
	}
}

func TestSpecCoversEveryAffectedPackageField(t *testing.T) {
	spec := loadSpec(t)
	schema, ok := spec.Components.Schemas["AffectedPackage"]
	if !ok {
		t.Fatal("the spec has no AffectedPackage schema")
	}
	for _, field := range jsonFieldNames(reflect.TypeOf(sink.PackageView{})) {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("package field %q is served but undocumented in %s", field, specPath)
		}
	}
}

// The analytics payload was documented by hand and its top-level fields were not
// checked at all, so wins and issues were served undocumented for a while without
// anything noticing. Same lesson as the Finding schema: a guard that only covers
// some schemas covers none of the ones added later.
func TestSpecCoversEveryAnalyticsField(t *testing.T) {
	spec := loadSpec(t)
	for name, typ := range map[string]reflect.Type{
		"Analytics":     reflect.TypeOf(analytics.AnalyticsView{}),
		"Win":           reflect.TypeOf(analytics.Win{}),
		"Issue":         reflect.TypeOf(analytics.Issue{}),
		"TeamAnalytics": reflect.TypeOf(analytics.TeamAnalytics{}),
	} {
		schema, ok := spec.Components.Schemas[name]
		if !ok {
			t.Errorf("the spec has no %s schema", name)
			continue
		}
		for _, field := range jsonFieldNames(typ) {
			if _, ok := schema.Properties[field]; !ok {
				t.Errorf("%s field %q is served but undocumented in %s", name, field, specPath)
			}
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

// The nested schemas, which the finding-level test does not reach.
//
// Added because it should have existed already: three upgrade fields were served
// undocumented, and one of them - support - was read by the page while never being
// emitted by the API at all. A guard that checks only top-level fields lets a whole
// nested object drift.
func TestSpecCoversEveryUpgradeField(t *testing.T) {
	spec := loadSpec(t)
	schema, ok := spec.Components.Schemas["Upgrade"]
	if !ok {
		t.Fatal("the spec has no Upgrade schema")
	}
	for _, field := range jsonFieldNames(reflect.TypeOf(sink.UpgradeView{})) {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("upgrade field %q is served but undocumented in %s", field, specPath)
		}
	}
}

func TestSpecCoversEverySupportField(t *testing.T) {
	spec := loadSpec(t)
	schema, ok := spec.Components.Schemas["Support"]
	if !ok {
		t.Fatal("the spec has no Support schema")
	}
	for _, field := range jsonFieldNames(reflect.TypeOf(sink.SupportView{})) {
		if _, ok := schema.Properties[field]; !ok {
			t.Errorf("support field %q is served but undocumented in %s", field, specPath)
		}
	}
}

// The history report gained tracker fields on four types at once; none of the
// history schemas were guarded, so check them the same way as the rest.
func TestSpecCoversEveryHistoryField(t *testing.T) {
	spec := loadSpec(t)
	for name, typ := range map[string]reflect.Type{
		"HistoryReport":   reflect.TypeOf(history.Report{}),
		"HistoryMovement": reflect.TypeOf(history.Movement{}),
		"HistoryTracker":  reflect.TypeOf(history.TrackerSummary{}),
	} {
		schema, ok := spec.Components.Schemas[name]
		if !ok {
			t.Errorf("the spec has no %s schema", name)
			continue
		}
		for _, field := range jsonFieldNames(typ) {
			if _, ok := schema.Properties[field]; !ok {
				t.Errorf("%s field %q is served but undocumented in %s", name, field, specPath)
			}
		}
	}
	open := historyOpenProperties(t, spec)
	for _, field := range jsonFieldNames(reflect.TypeOf(history.OpenSummary{})) {
		if _, ok := open[field]; !ok {
			t.Errorf("HistoryReport.open field %q is served but undocumented in %s", field, specPath)
		}
	}
}

// The other direction: every tracker field the spec names is what a report with
// tracker data actually emits, so a renamed JSON tag cannot leave the docs behind.
func TestSpecTrackerFieldsAreEmitted(t *testing.T) {
	spec := loadSpec(t)
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	opened := now.AddDate(0, 0, -20)
	created, started, resolved := now.AddDate(0, 0, -15), now.AddDate(0, 0, -10), now.AddDate(0, 0, -5)
	open := []history.State{{OpenedAt: opened, Current: history.Snapshot{Key: "k", Repository: "app"}}}
	rep := history.Aggregate(history.Range{Since: now.AddDate(0, 0, -30), Until: now, Bucket: history.BucketMonth}, nil, nil, open, opened.AddDate(0, 0, -1), now)
	rep.AddTracker([]history.TrackerTicket{{
		Key: "T-1", ItemKey: "k", ItemOpenedAt: &opened, CreatedAt: created,
		StartedAt: &started, StartedFrom: history.StartedFromStatusCategory, ResolvedAt: &resolved,
	}}, history.TicketIndexState{Tickets: 1, FirstCreated: created, LastSynced: now}, open, opened.AddDate(0, 0, -1), now)

	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Movement []map[string]any `json:"movement"`
		Open     map[string]any   `json:"open"`
		Tracker  map[string]any   `json:"tracker"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	emitted := map[string]bool{}
	for _, m := range got.Movement {
		for k := range m {
			emitted[k] = true
		}
	}
	for _, field := range []string{
		"tracker_tickets_raised", "tracker_tickets_closed",
		"median_days_told", "median_days_told_n", "median_days_to_start", "median_days_to_start_n",
		"median_days_worked", "median_days_worked_n",
	} {
		if _, ok := spec.Components.Schemas["HistoryMovement"].Properties[field]; !ok {
			t.Errorf("HistoryMovement.%s is not in the spec", field)
		}
		if !emitted[field] {
			t.Errorf("the spec documents movement.%s but a report with tracker data does not emit it: %s", field, raw)
		}
	}
	for _, field := range []string{"closed_ticket_finding_open", "closed_ticket_age_days"} {
		if _, ok := historyOpenProperties(t, spec)[field]; !ok {
			t.Errorf("HistoryReport.open.%s is not in the spec", field)
		}
		if _, ok := got.Open[field]; !ok {
			t.Errorf("the spec documents open.%s but it is not emitted: %s", field, raw)
		}
	}
	for field := range spec.Components.Schemas["HistoryTracker"].Properties {
		if _, ok := got.Tracker[field]; !ok {
			t.Errorf("the spec documents tracker.%s but it is not emitted: %s", field, raw)
		}
	}
}

func historyOpenProperties(t *testing.T, spec openAPISpec) map[string]any {
	t.Helper()
	open, _ := spec.Components.Schemas["HistoryReport"].Properties["open"].(map[string]any)
	props, _ := open["properties"].(map[string]any)
	if props == nil {
		t.Fatal("the spec's HistoryReport has no open.properties")
	}
	return props
}
