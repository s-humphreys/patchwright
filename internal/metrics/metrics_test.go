package metrics

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// scrape renders the registry the way Prometheus sees it, so these tests assert
// the exported surface rather than the Go variables behind it.
func scrape(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape returned %d", rec.Code)
	}
	return rec.Body.String()
}

// gathered returns every metric family patchwright registers, excluding the
// runtime collectors, which are not ours to name.
func gathered(t *testing.T) []string {
	t.Helper()
	families, err := Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var names []string
	for _, f := range families {
		name := f.GetName()
		if strings.HasPrefix(name, "go_") || strings.HasPrefix(name, "process_") {
			continue
		}
		names = append(names, name)
	}
	return names
}

// The prefix is a contract with whoever writes the alerts, so it is asserted
// rather than left to reviewers to notice.
func TestEveryMetricIsPrefixed(t *testing.T) {
	Observe(Snapshot{Findings: 1, Owners: []OwnerSnapshot{{Class: "platform"}},
		Reasons: []ReasonCount{{Reason: "x", Findings: 1}}})
	JiraRequest("get issue", 200, nil)
	TicketAction("create", "applied")
	ImageScan("ok")
	ProviderFetch("success")
	AssessmentStarted()(nil)

	names := gathered(t)
	if len(names) == 0 {
		t.Fatal("no metrics registered, so this asserts nothing")
	}
	for _, name := range names {
		if !strings.HasPrefix(name, Namespace+"_") {
			t.Errorf("metric %q is not prefixed %q", name, Namespace+"_")
		}
	}
}

// The runtime collectors are worth having: a leak in a long-running service is
// invisible from domain metrics.
func TestRuntimeCollectorsArePresent(t *testing.T) {
	out := scrape(t)
	for _, want := range []string{"go_goroutines", "process_open_fds"} {
		if !strings.Contains(out, want) {
			t.Errorf("%s is missing from the scrape", want)
		}
	}
}

// Coverage is the point of the tool, so the states have to survive to the scrape
// with the right values.
func TestObservePublishesCoverage(t *testing.T) {
	Observe(Snapshot{
		Findings: 297, Actionable: 18, Suppressed: 546,
		ProviderAssessed: 31, ProviderUnassessed: 266,
		Scanned: 0, ExploitChecked: 0, UniqueImages: 839,
		ProviderDataNewest: time.Now().Add(-2 * time.Hour),
	})
	out := scrape(t)
	for _, want := range []string{
		`patchwright_findings 297`,
		`patchwright_findings_by_state{state="actionable"} 18`,
		`patchwright_findings_by_state{state="provider_unassessed"} 266`,
		`patchwright_findings_by_state{state="scanned"} 0`,
		`patchwright_images_unique 839`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape is missing %q", want)
		}
	}
	// Roughly two hours, allowing for test execution time.
	if !strings.Contains(out, "patchwright_provider_data_age_seconds 72") {
		t.Errorf("provider data age not published as ~7200s:\n%s", grepPrefix(out, "patchwright_provider_data_age"))
	}
}

// A provider that reports no assessment times must not read as perfectly fresh,
// and must not read as decades stale either — both would be lies, one of them
// loud enough to page someone.
func TestMissingProviderTimestampIsNotZeroAge(t *testing.T) {
	Observe(Snapshot{Findings: 1})
	out := grepPrefix(scrape(t), "patchwright_provider_data_age_seconds")
	if !strings.Contains(out, "-1") {
		t.Errorf("age with no provider timestamp = %q, want -1", out)
	}
}

// A team that disappears from the estate must stop being reported, not freeze at
// its last value — a stale gauge is a lie that never expires.
func TestOwnersAreResetBetweenObservations(t *testing.T) {
	Observe(Snapshot{Owners: []OwnerSnapshot{
		{Class: "platform", Team: "cpo", Findings: 68},
		{Class: "engineering", Team: "gone", Findings: 12},
	}})
	if out := scrape(t); !strings.Contains(out, `team="gone"`) {
		t.Fatalf("first observation did not publish the team:\n%s", grepPrefix(out, "patchwright_owner_findings"))
	}
	Observe(Snapshot{Owners: []OwnerSnapshot{
		{Class: "platform", Team: "cpo", Findings: 70},
	}})
	out := scrape(t)
	if strings.Contains(out, `team="gone"`) {
		t.Errorf("a team that left the estate is still reported:\n%s",
			grepPrefix(out, "patchwright_owner_findings"))
	}
	if !strings.Contains(out, `patchwright_owner_findings{class="platform",state="total",team="cpo"} 70`) {
		t.Errorf("surviving team not updated:\n%s", grepPrefix(out, "patchwright_owner_findings"))
	}
}

// An unattributed owner is a real state, and an empty label renders as a blank row
// that reads like a bug.
func TestUnattributedOwnerIsLabelled(t *testing.T) {
	Observe(Snapshot{Owners: []OwnerSnapshot{{Class: "engineering", Team: "", Findings: 5}}})
	if out := scrape(t); !strings.Contains(out, `team="unattributed"`) {
		t.Errorf("empty team was not labelled:\n%s", grepPrefix(out, "patchwright_owner_findings"))
	}
}

// Reasons come from the provider as free text, so the label has to be bounded or
// one unlucky provider mints a series per image.
func TestReasonsAreNormalisedAndCapped(t *testing.T) {
	reasons := []ReasonCount{
		{Reason: "Can't authenticate to ACR. Unable to obtain refresh token. Operation returned 'Forbidden'", Findings: 700},
		{Reason: "Unable to pull an image from this registry. This registry is not supported.", Findings: 20},
	}
	// Plus more distinct reasons than the cap allows.
	for i := 0; i < maxReasons+5; i++ {
		reasons = append(reasons, ReasonCount{Reason: fmt.Sprintf("reason number %d", i), Findings: 1})
	}
	Observe(Snapshot{Reasons: reasons})
	out := grepPrefix(scrape(t), "patchwright_findings_unassessed_by_reason")

	// The long sentence is trimmed to its diagnostic first clause.
	if !strings.Contains(out, `reason="Can't authenticate to ACR"} 700`) {
		t.Errorf("reason not normalised to its first sentence:\n%s", out)
	}
	// The tail is summed rather than dropped, so the total still adds up.
	if !strings.Contains(out, `reason="other"`) {
		t.Errorf("the capped tail was dropped instead of folded into other:\n%s", out)
	}
	if n := strings.Count(out, "patchwright_findings_unassessed_by_reason{"); n > maxReasons+1 {
		t.Errorf("published %d reason series, want at most %d", n, maxReasons+1)
	}
}

// The failure the user asked for by name: invalid credentials must be
// distinguishable from every other kind of failure.
func TestJiraOutcomeSeparatesAuthFailures(t *testing.T) {
	for _, tc := range []struct {
		status int
		err    error
		want   string
	}{
		{http.StatusUnauthorized, nil, "auth_error"},
		{http.StatusForbidden, nil, "auth_error"},
		{http.StatusTooManyRequests, nil, "rate_limited"},
		{http.StatusBadRequest, nil, "client_error"},
		{http.StatusInternalServerError, nil, "server_error"},
		{0, errors.New("dial tcp: timeout"), "network_error"},
		{http.StatusOK, nil, "ok"},
		{http.StatusCreated, nil, "ok"},
	} {
		if got := jiraOutcome(tc.status, tc.err); got != tc.want {
			t.Errorf("status %d err %v -> %q, want %q", tc.status, tc.err, got, tc.want)
		}
	}
}

func TestJiraRequestsAreCountedByOutcome(t *testing.T) {
	before := counterValue(t, "patchwright_jira_requests_total", map[string]string{
		"operation": "get issue", "outcome": "auth_error",
	})
	JiraRequest("get issue", http.StatusUnauthorized, nil)
	after := counterValue(t, "patchwright_jira_requests_total", map[string]string{
		"operation": "get issue", "outcome": "auth_error",
	})
	if after != before+1 {
		t.Errorf("auth_error count went %v -> %v, want +1", before, after)
	}
}

// grepPrefix returns the scrape lines starting with prefix, for readable failures.
func grepPrefix(scrape, prefix string) string {
	var out []string
	for _, line := range strings.Split(scrape, "\n") {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// counterValue reads one labelled counter out of the registry.
func counterValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if labelsMatch(m.GetLabel(), labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func labelsMatch(got []*dto.LabelPair, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, l := range got {
		if want[l.GetName()] != l.GetValue() {
			return false
		}
	}
	return true
}
