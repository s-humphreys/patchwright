package group_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/group"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// The page groups findings in the browser, for filtering that responds instantly, and
// this package groups them in Go, for consumers that should not have to. Two
// implementations of one set of rules drift, and the drift would be silent: both would
// keep returning plausible numbers.
//
// So both read one fixture and both are checked against one expected file. A change to
// either implementation that is not made to the other fails here, in whichever language
// the change was made.
//
// Regenerate with: go test ./pkg/group -update

const fixture = "../../testdata/grouping.json"
const expected = "../../testdata/grouping.expected"

var update = os.Getenv("UPDATE_GOLDEN") != ""

func loadFixture(t *testing.T) []sink.FindingView {
	t.Helper()
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Findings []sink.FindingView `json:"findings"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Findings) == 0 {
		t.Fatal("fixture has no findings")
	}
	return body.Findings
}

// summarise renders the aggregations both implementations must agree on, in a form a
// human can read in a diff. Deliberately the interesting fields only: this is a
// cross-language contract, not a serialisation test.
func summarise(items []group.Item) string {
	lines := make([]string, 0, len(items))
	for _, it := range items {
		lines = append(lines, fmt.Sprintf(
			"%s/%s target=%s priority=%s where=%s rule=%s crit=%d high=%d deployments=%d assessed=%d exposure=%s signals=%s inflight_checked=%t tags=%s",
			it.Team, it.Repository, target(it), it.Priority, it.PriorityWhere, it.Rule,
			it.Critical, it.High, it.Deployments, it.AssessedImages, it.Exposure,
			strings.Join(it.Signals, "+"), it.InFlightChecked, strings.Join(it.Tags, ",")))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func target(it group.Item) string {
	if it.Upgrade == nil {
		return "none"
	}
	return it.Upgrade.Name + "@" + it.Upgrade.Latest
}

func TestGroupingMatchesTheSharedExpectation(t *testing.T) {
	got := summarise(group.Items(loadFixture(t)))
	if update {
		if err := os.WriteFile(filepath.Clean(expected), []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("updated " + expected)
		return
	}
	want, err := os.ReadFile(expected)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("grouping differs from %s.\n--- got ---\n%s\n--- want ---\n%s", expected, got, want)
	}
}

func TestGroupingKeepsTeamsApart(t *testing.T) {
	// The fixture holds one repository owned by two teams. Merging them would produce
	// an item belonging to nobody and break every team-scoped query.
	items := group.Items(loadFixture(t))
	for _, it := range items {
		if it.Repository != "ledger" {
			continue
		}
		if it.Deployments != 1 {
			t.Errorf("ledger item for %s covers %d deployments; the teams must stay apart",
				it.Team, it.Deployments)
		}
	}
}

func TestPartialCoverageIsVisible(t *testing.T) {
	// storefront has three deployments and one the provider never assessed. The counts
	// must be the worst KNOWN, and the shortfall must be reportable.
	for _, it := range group.Items(loadFixture(t)) {
		if it.Repository != "storefront" {
			continue
		}
		if it.Deployments != 3 || it.AssessedImages != 2 {
			t.Fatalf("want 3 deployments with 2 assessed, got %d and %d", it.Deployments, it.AssessedImages)
		}
		if it.Critical != 296 {
			t.Errorf("critical = %d, want the worst known (296)", it.Critical)
		}
		if it.InFlightChecked {
			t.Error("one deployment was never checked, so the item must not claim it was")
		}
		if it.Exposure != "public" {
			t.Errorf("exposure = %q; exposed anywhere is exposed", it.Exposure)
		}
		if it.Priority != "urgent" || it.PriorityWhere != "Production NA" {
			t.Errorf("worst verdict = %q in %q, want urgent in Production NA", it.Priority, it.PriorityWhere)
		}
	}
}
