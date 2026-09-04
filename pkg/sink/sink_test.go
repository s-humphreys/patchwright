package sink

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// Report order is the queue order someone works top-down, so the priority
// ladder must hold — including "urgent", which exists to let exploitation
// pressure outrank a merely-severe finding.
func TestSortForReportOrdersByPriority(t *testing.T) {
	in := []model.Finding{
		{Image: model.Image{Ref: "low"}, Actionable: true, Priority: model.PriorityLow},
		{Image: model.Image{Ref: "unranked"}, Actionable: true, Priority: "somethingelse"},
		{Image: model.Image{Ref: "high"}, Actionable: true, Priority: model.PriorityHigh},
		{Image: model.Image{Ref: "urgent"}, Actionable: true, Priority: model.PriorityUrgent},
		{Image: model.Image{Ref: "medium"}, Actionable: true, Priority: model.PriorityMedium},
		{Image: model.Image{Ref: "suppressed"}, Priority: model.PriorityUrgent},
	}

	got := SortForReport(in)
	want := []string{"urgent", "high", "medium", "low", "unranked", "suppressed"}
	for i, w := range want {
		if got[i].Image.Ref != w {
			t.Errorf("position %d: got %q, want %q (full order: %v)", i, got[i].Image.Ref, w, refs(got))
			break
		}
	}

	// SortForReport must not reorder its input.
	if in[0].Image.Ref != "low" {
		t.Errorf("input was mutated: first element is now %q", in[0].Image.Ref)
	}
}

func refs(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Image.Ref
	}
	return out
}

// The FIX column exists to answer "can I act, and how?" — the distinction
// between a direct bump and a chart/operator-managed one is the whole point,
// and "none" (on latest, nothing to move to) must stay visible rather than
// reading as "no action needed".
func TestFixPathMark(t *testing.T) {
	cases := []struct {
		name string
		u    *model.Upgrade
		want string
	}{
		{"no remediation run", nil, "?"},
		{"on latest", &model.Upgrade{Resolved: true, Available: false}, "none"},
		{"direct bump", &model.Upgrade{Resolved: true, Available: true, Actionable: true}, "direct"},
		{"operator-managed", &model.Upgrade{Resolved: true, Available: true, Actionable: false, Managed: "operator"}, "managed"},
		// An unreachable registry must never claim the image is up to date.
		{"versions unresolved", &model.Upgrade{Resolved: false, Available: false}, "unknown"},
	}
	for _, c := range cases {
		if got := fixPathMark(model.Finding{Upgrade: c.u}); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// Suppression used to be carried by the ACT column. PRIORITY took it over, so
// suppressed findings must not be confusable with ones that merely matched no
// actionable rule.
func TestPriorityMarkDistinguishesSuppressed(t *testing.T) {
	if got := priorityMark(model.Finding{Suppressed: true}); got != "supp" {
		t.Errorf("suppressed: got %q, want \"supp\"", got)
	}
	if got := priorityMark(model.Finding{}); got != "-" {
		t.Errorf("no priority: got %q, want \"-\"", got)
	}
	if got := priorityMark(model.Finding{Priority: model.PriorityUrgent}); got != "urgent" {
		t.Errorf("urgent: got %q, want \"urgent\"", got)
	}
}

func TestEpssMark(t *testing.T) {
	// Not checked -> "-", so "0%" unambiguously means "checked, no pressure".
	if got := epssMark(model.Finding{}); got != "-" {
		t.Errorf("unchecked: got %q, want \"-\"", got)
	}
	f := model.Finding{ExploitChecked: true, Vulns: []model.Vulnerability{
		{ID: "a", EPSS: 0.01}, {ID: "b", EPSS: 0.933}, {ID: "c", EPSS: 0.5},
	}}
	// A percentage, matching the status page: as 0-1 it reads as a rating out of
	// one and invites comparison with CVSS, which is a different scale.
	if got := epssMark(f); got != "93%" {
		t.Errorf("max EPSS: got %q, want \"93%%\"", got)
	}
	if got := epssMark(model.Finding{ExploitChecked: true}); got != "0%" {
		t.Errorf("checked, no vulns: got %q, want \"0%%\"", got)
	}
	// Most scores live at the small end, where a naive round would print "0%" on
	// a CVE that has real pressure.
	low := model.Finding{ExploitChecked: true, Vulns: []model.Vulnerability{{ID: "a", EPSS: 0.0004}}}
	if got := epssMark(low); got != "<0.1%" {
		t.Errorf("small EPSS: got %q, want \"<0.1%%\"", got)
	}
	if got := epssMark(model.Finding{ScanError: "no creds"}); got != "err" {
		t.Errorf("scan error: got %q, want \"err\"", got)
	}
}

// The group header's "N actionable" is a policy verdict, not a count of things
// with a fix. The breakdown exists so the two are not confused.
func TestFixSummary(t *testing.T) {
	group := []model.Finding{
		{Actionable: true, Upgrade: &model.Upgrade{Resolved: true, Available: true, Actionable: true}},
		{Actionable: true, Upgrade: &model.Upgrade{Resolved: true, Available: true, Actionable: true}},
		{Actionable: true, Upgrade: &model.Upgrade{Resolved: true, Available: true, Managed: "operator"}},
		{Actionable: true, Upgrade: &model.Upgrade{Resolved: true, Available: false}},
		{Actionable: true, Upgrade: &model.Upgrade{Resolved: false}},                                   // registry unreachable
		{Actionable: true, RemediationChecked: true},                                                   // ran, nothing resolved
		{Suppressed: true, Upgrade: &model.Upgrade{Resolved: true, Available: true, Actionable: true}}, // excluded
	}
	if got, want := fixSummary(group), ": 2 direct, 1 managed, 1 none, 2 unknown"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// Nothing actionable -> no breakdown, so the header stays terse.
	if got := fixSummary([]model.Finding{{Suppressed: true}}); got != "" {
		t.Errorf("no actionable: got %q, want empty", got)
	}
}

// The whole point of ProviderAssessed: an unassessed image reports zero counts,
// and rendering that as "0" is the most misleading thing a vulnerability report
// can do. It must read "?" instead.
func TestCountMarkDistinguishesUnassessedFromClean(t *testing.T) {
	assessedClean := model.Finding{
		Occurrences: []model.Occurrence{{Assessed: true}},
		Counts:      model.Counts{},
	}
	if got := countMark(assessedClean, model.SeverityCritical); got != "0" {
		t.Errorf("assessed and clean: got %q, want \"0\"", got)
	}

	unassessed := model.Finding{Occurrences: []model.Occurrence{{Assessed: false}}}
	if got := countMark(unassessed, model.SeverityCritical); got != "?" {
		t.Errorf("never assessed: got %q, want \"?\"", got)
	}

	withCounts := model.Finding{
		Occurrences: []model.Occurrence{{Assessed: true}},
		Counts:      model.Counts{model.SeverityCritical: 3},
	}
	if got := countMark(withCounts, model.SeverityCritical); got != "3" {
		t.Errorf("assessed with counts: got %q, want \"3\"", got)
	}

	// An optional vuln source not having run is NOT a coverage gap, so a scanned
	// or unscanned image that WAS assessed still shows its real counts.
	scannedUnassessed := model.Finding{
		Occurrences: []model.Occurrence{{Assessed: false}},
		Scanned:     true,
	}
	if got := countMark(scannedUnassessed, model.SeverityCritical); got != "?" {
		t.Errorf("scanned but provider never assessed: got %q, want \"?\" (counts are still the provider's)", got)
	}
}

// A fallback scan replaces the "?" with what it found, marked so the number is not
// silently compared against the provider's in the same column.
func TestCountMarkMarksFallbackCounts(t *testing.T) {
	fallback := model.Finding{
		Occurrences:     []model.Occurrence{{Assessed: false}},
		Counts:          model.Counts{model.SeverityCritical: 12},
		FallbackScanned: true,
		CountsSource:    "trivy",
	}
	if got := countMark(fallback, model.SeverityCritical); got != "12~" {
		t.Errorf("fallback counts: got %q, want \"12~\"", got)
	}
	// Zero from a fallback scan is a real zero - it looked and found none - so it
	// must not fall back to "?".
	fallback.Counts = model.Counts{}
	if got := countMark(fallback, model.SeverityCritical); got != "0~" {
		t.Errorf("fallback scanned and clean: got %q, want \"0~\"", got)
	}
	// Asked and failed is still nothing known.
	failed := model.Finding{
		Occurrences:   []model.Occurrence{{Assessed: false}},
		FallbackError: "UNAUTHORIZED",
	}
	if got := countMark(failed, model.SeverityCritical); got != "?" {
		t.Errorf("fallback failed: got %q, want \"?\"", got)
	}
}

// Mixed occurrences: if any workload was assessed, the counts mean something.
func TestProviderAssessedAcrossOccurrences(t *testing.T) {
	mixed := model.Finding{Occurrences: []model.Occurrence{{Assessed: false}, {Assessed: true}}}
	if !mixed.ProviderAssessed() {
		t.Error("any assessed occurrence should make the finding assessed")
	}
	none := model.Finding{Occurrences: []model.Occurrence{{}, {}}}
	if none.ProviderAssessed() {
		t.Error("no assessed occurrences should report unassessed")
	}
	if (model.Finding{}).ProviderAssessed() {
		t.Error("no occurrences at all should report unassessed")
	}
}

// "No upgrade found" and "we never looked" must not render the same, because a
// consumer that skips findings without an upgrade would otherwise silently skip
// images whose versions merely could not be resolved.
func TestFixPathMarkSeparatesUnknownFromNotRun(t *testing.T) {
	notRun := model.Finding{RemediationChecked: false}
	if got := fixPathMark(notRun); got != "?" {
		t.Errorf("detection not run: got %q, want \"?\"", got)
	}
	unresolved := model.Finding{RemediationChecked: true}
	if got := fixPathMark(unresolved); got != "unknown" {
		t.Errorf("ran but unresolved: got %q, want \"unknown\"", got)
	}
	onLatest := model.Finding{RemediationChecked: true, Upgrade: &model.Upgrade{Resolved: true, Available: false}}
	if got := fixPathMark(onLatest); got != "none" {
		t.Errorf("on latest: got %q, want \"none\"", got)
	}
}

// ToFindingView is hand-written field-by-field, so a newly added view field can
// silently stay at its zero value while the table shows the true one. That
// happened with upgrade.resolved: the JSON reported false for every finding
// while the report rendered correctly. Assert the mapping for the fields whose
// whole purpose is to distinguish "no data" from "no problem".
func TestToFindingViewCarriesDataProvenanceFields(t *testing.T) {
	f := model.Finding{
		Occurrences:        []model.Occurrence{{Assessed: true}},
		Scanned:            true,
		ExploitChecked:     true,
		RemediationChecked: true,
		Upgrade: &model.Upgrade{
			Kind: "image", Name: "acme/app", Current: "1.0.0", Latest: "1.1.0",
			Available: true, Resolved: true, Actionable: true,
		},
	}
	v := ToFindingView(f)

	if !v.ProviderAssessed {
		t.Error("provider_assessed not carried into the view")
	}
	if !v.Scanned {
		t.Error("scanned not carried into the view")
	}
	if !v.ExploitChecked {
		t.Error("exploit_checked not carried into the view")
	}
	if !v.RemediationChecked {
		t.Error("remediation_checked not carried into the view")
	}
	if v.Upgrade == nil {
		t.Fatal("upgrade not carried into the view")
	}
	if !v.Upgrade.Resolved {
		t.Error("upgrade.resolved not carried into the view")
	}
	if !v.Upgrade.Available || !v.Upgrade.Actionable {
		t.Error("upgrade available/actionable not carried into the view")
	}

	// And the false case must survive too, not just default to false by accident.
	unresolved := model.Finding{Upgrade: &model.Upgrade{Resolved: false, Available: false}}
	if uv := ToFindingView(unresolved).Upgrade; uv == nil || uv.Resolved {
		t.Error("unresolved upgrade should report resolved=false")
	}
}

// The legend is the only place the four unknown-states are explained. Without it
// "?" reads as "probably fine", which is the reading the marks exist to prevent.
func TestEmitWritesLegendExplainingUnknownStates(t *testing.T) {
	var buf bytes.Buffer
	tbl := Table{}
	err := tbl.Emit(&buf, []model.Finding{{
		Image:      model.Image{Ref: "acme/app:1"},
		Owner:      model.Owner{Class: "engineering"},
		Actionable: true,
		Priority:   model.PriorityHigh,
	}})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"LEGEND",
		"NEVER ASSESSED", // the CRIT "?" case, the most dangerous to misread
		"versions could not be resolved",
		"upgrade detection did not run",
		"exploit intel not gathered",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("legend is missing %q\n--- got ---\n%s", want, out)
		}
	}
	// The legend must precede the data, not trail it.
	if strings.Index(out, "LEGEND") > strings.Index(out, "owner class") {
		t.Error("legend should be written above the table")
	}
}

// An empty report should stay empty rather than printing a legend for nothing.
func TestEmitNoFindingsSkipsLegend(t *testing.T) {
	var buf bytes.Buffer
	tbl := Table{}
	if err := tbl.Emit(&buf, nil); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := buf.String(); got != "no findings\n" {
		t.Errorf("got %q, want \"no findings\\n\"", got)
	}
}

// ToFindingView maps fields by hand, and a field that is declared but never
// assigned is silent: it compiles, no test notices, and the JSON quietly reports
// a zero value while the report shows the truth. That has now happened twice
// (upgrade.resolved, then upgrade.manager), so assert the invariant rather than
// the fields I happen to remember: given a fully-populated Upgrade, EVERY field
// of the view must be non-zero.
func TestUpgradeViewMapsEveryField(t *testing.T) {
	u := model.Upgrade{
		Kind: "image", Name: "acme/app", Current: "1.0.0", Latest: "2.0.0",
		Available: true, Resolved: true, Source: "https://example.com/repo",
		SourcePath: "bases/app", Actionable: true, Managed: "operator",
		Manager: "acme-operator",
		// Not a realistic combination — Reason accompanies an unresolved upgrade —
		// but this asserts field mapping, not semantics, and a field left out here is
		// a field that can silently stop being copied.
		Reason: "could not list tags", Comparison: "version",
		Newest: "3.14.7", Strategy: "patch", Ceiling: "3.12",
		CeilingReason: "dependencies are not 3.14 ready", CeilingExpired: true, HeldBack: true,
		Rule: "docker.io/python", OutOfTrack: true,
		Support: &model.Support{
			Product: "nodejs", Cycle: "20", EOL: "2026-04-30", Known: true, Supported: true,
			Recommended: "24", Nearest: "22", Newest: "26", Source: "endoflife.date",
		},
	}
	v := ToFindingView(model.Finding{Upgrade: &u}).Upgrade
	if v == nil {
		t.Fatal("upgrade view not produced")
	}
	rv := reflect.ValueOf(*v)
	for i := 0; i < rv.NumField(); i++ {
		if rv.Field(i).IsZero() {
			t.Errorf("UpgradeView.%s is zero: ToFindingView does not assign it", rv.Type().Field(i).Name)
		}
	}
}

// A base upgrade must say it is the base, and which one. A bare version range on a
// first-party image reads as the application's own version moving, which is the
// confusion this kind of upgrade exists to remove.
func TestUpgradeMarkNamesTheBaseImage(t *testing.T) {
	f := model.Finding{Upgrade: &model.Upgrade{
		Kind: "base", Name: "dotnet/aspnet/10", Current: "1.0.2", Latest: "1.1.1",
		Available: true, Resolved: true, Actionable: true,
	}}
	got := upgradeMark(f)
	for _, want := range []string{"base", "dotnet/aspnet/10", "1.0.2→1.1.1"} {
		if !strings.Contains(got, want) {
			t.Errorf("upgradeMark = %q, want it to contain %q", got, want)
		}
	}
}

// An unresolved base upgrade is still "?" in the column — the reason belongs in the
// legend and the JSON, not squeezed into a cell.
func TestUpgradeMarkUnresolvedStaysUnknown(t *testing.T) {
	f := model.Finding{Upgrade: &model.Upgrade{
		Kind: "base", Resolved: false, Reason: "image records no base image",
	}}
	if got := upgradeMark(f); got != "?" {
		t.Errorf("upgradeMark = %q, want ?", got)
	}
}

// A digest comparison must name the tag that moved. Two opaque hashes say nothing;
// "mcr.microsoft.com/dotnet/aspnet:10.0-alpine moved" points at a Dockerfile line.
func TestUpgradeMarkNamesTheFloatingTagThatMoved(t *testing.T) {
	f := model.Finding{Upgrade: &model.Upgrade{
		Kind: "base", Name: "mcr.microsoft.com/dotnet/aspnet",
		Source:  "mcr.microsoft.com/dotnet/aspnet:10.0-alpine",
		Current: "1e37a8236c55", Latest: "c4b29bf36800",
		Comparison: "digest", Available: true, Resolved: true, Actionable: true,
	}}
	got := upgradeMark(f)
	for _, want := range []string{"mcr.microsoft.com/dotnet/aspnet:10.0-alpine", "moved", "1e37a8236c55→c4b29bf36800"} {
		if !strings.Contains(got, want) {
			t.Errorf("upgradeMark = %q, want it to contain %q", got, want)
		}
	}
}

// A version comparison keeps the registry-qualified name: "dotnet/aspnet" alone is
// ambiguous between an internal mirror and the upstream it was copied from.
func TestUpgradeMarkQualifiesTheBaseRegistry(t *testing.T) {
	f := model.Finding{Upgrade: &model.Upgrade{
		Kind: "base", Name: "mcr.microsoft.com/dotnet/aspnet",
		Current: "8.0.17", Latest: "8.0.22", Comparison: "version",
		Available: true, Resolved: true, Actionable: true,
	}}
	if got := upgradeMark(f); !strings.Contains(got, "mcr.microsoft.com/dotnet/aspnet 8.0.17→8.0.22") {
		t.Errorf("upgradeMark = %q", got)
	}
}
