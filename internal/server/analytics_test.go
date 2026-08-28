package server

import (
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
)

var analyticsNow = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

func daysAgo(d int) time.Time { return analyticsNow.AddDate(0, 0, -d) }

// finding builds an actionable finding with an available upgrade and one CVE.
func aFinding(team string, ageDays int, opts ...func(*model.Finding)) model.Finding {
	f := model.Finding{
		Image:      model.Image{Ref: "reg/" + team + ":1", Repository: team},
		Owner:      model.Owner{Class: "engineering", Team: team},
		Actionable: true,
		Vulns:      []model.Vulnerability{{ID: "CVE-1", FirstSeen: daysAgo(ageDays)}},
		Upgrade:    &model.Upgrade{Kind: "base", Available: true, Actionable: true},
	}
	for _, o := range opts {
		o(&f)
	}
	return f
}

func TestStaleUnstartedIsTheHeadlineSignal(t *testing.T) {
	// An available fix, no pull request, no ticket, and older than the threshold.
	// That is a statement about the team rather than about the software, and it is
	// what the page sorts on.
	findings := []model.Finding{
		aFinding("slow", 90),
		aFinding("slow", 45),
		aFinding("slow", 3), // available, unstarted, but not yet stale
	}
	v := buildAnalytics(findings, nil, analyticsNow)
	if len(v.Teams) != 1 {
		t.Fatalf("expected one team, got %d", len(v.Teams))
	}
	got := v.Teams[0]
	if got.Unstarted != 3 {
		t.Errorf("unstarted = %d, want 3", got.Unstarted)
	}
	if got.StaleUnstarted != 2 {
		t.Errorf("stale unstarted = %d, want 2 (the 3-day-old one is not stale)", got.StaleUnstarted)
	}
}

func TestAnOpenPullRequestOrTicketMeansStarted(t *testing.T) {
	// "Nobody has started" must mean nobody has started. Counting a finding with an
	// open pull request against a team is how a dashboard loses its audience.
	withPR := aFinding("busy", 90, func(f *model.Finding) {
		f.InFlight = &model.InFlight{Opened: daysAgo(10)}
	})
	withTicket := aFinding("busy", 90)
	tickets := map[string][]ticketRef{"busy": {{Key: "OPS-1", Category: "indeterminate"}}}

	v := buildAnalytics([]model.Finding{withPR, withTicket}, tickets, analyticsNow)
	got := v.Teams[0]
	if got.StaleUnstarted != 0 {
		t.Errorf("stale unstarted = %d, want 0: both are started", got.StaleUnstarted)
	}
	if got.InFlight != 1 || got.TicketsOpen != 2 {
		t.Errorf("in flight = %d, tickets = %d", got.InFlight, got.TicketsOpen)
	}
	if got.InFlightMedianDays == nil || *got.InFlightMedianDays != 10 {
		t.Errorf("in-flight median = %v, want 10", got.InFlightMedianDays)
	}
}

func TestUndatedFindingsAreNotCountedAsStale(t *testing.T) {
	// Without an age source nothing is dated. Treating that as old would
	// manufacture the page's headline signal out of missing data.
	f := aFinding("nodates", 0)
	f.Vulns = []model.Vulnerability{{ID: "CVE-1"}} // no FirstSeen
	v := buildAnalytics([]model.Finding{f}, nil, analyticsNow)
	got := v.Teams[0]
	if got.StaleUnstarted != 0 {
		t.Errorf("stale unstarted = %d, want 0 with no dates", got.StaleUnstarted)
	}
	if got.Unstarted != 1 {
		t.Errorf("unstarted = %d, want 1: it is still unstarted", got.Unstarted)
	}
	if got.MedianAgeDays != nil {
		t.Errorf("median age = %v, want nil: nothing was dated", *got.MedianAgeDays)
	}
}

func TestMedianIsNilNotZeroWhenNothingIsDated(t *testing.T) {
	// Zero reads as "found today", which is the opposite of "we do not know".
	if got := percentile(nil, 50); got != nil {
		t.Errorf("percentile of nothing = %v, want nil", *got)
	}
	v := percentile([]int{10, 20, 30, 40}, 50)
	if v == nil || *v != 20 {
		t.Errorf("median = %v, want 20 (nearest-rank, no interpolation)", v)
	}
	p90 := percentile([]int{10, 20, 30, 40}, 90)
	if p90 == nil || *p90 != 40 {
		t.Errorf("p90 = %v, want 40", p90)
	}
}

func TestSuppressedFindingsAreExcluded(t *testing.T) {
	// A suppressed finding is a decision already taken. Counting it against a team
	// reports somebody's accepted risk as their negligence.
	f := aFinding("team", 90)
	f.Suppressed = true
	v := buildAnalytics([]model.Finding{f}, nil, analyticsNow)
	if len(v.Teams) != 0 {
		t.Errorf("suppressed findings should not create a row: %+v", v.Teams)
	}
}

func TestTeamsSortWorstFirst(t *testing.T) {
	// The page exists to say who to talk to. If that is not the first row it is a
	// table, not an answer.
	findings := []model.Finding{
		aFinding("quiet", 2),
		aFinding("bad", 200), aFinding("bad", 190),
		aFinding("middling", 100),
	}
	v := buildAnalytics(findings, nil, analyticsNow)
	if v.Teams[0].Team != "bad" {
		t.Errorf("first team = %q, want \"bad\"", v.Teams[0].Team)
	}
}

func TestKEVAndBaseLeverageAreCountedOverAllFindings(t *testing.T) {
	// KEV matters whether or not policy called the finding actionable, and base
	// leverage describes the image rather than the verdict.
	f := aFinding("t", 10)
	f.Actionable = false
	f.Vulns = []model.Vulnerability{{ID: "CVE-1", KEV: true, FirstSeen: daysAgo(10)}}
	f.BaseDiff = &model.BaseDiff{Total: 100, Clears: 80}
	v := buildAnalytics([]model.Finding{f}, nil, analyticsNow)
	got := v.Teams[0]
	if got.KEV != 1 || got.KEVFixable != 1 {
		t.Errorf("kev = %d, fixable = %d, want 1/1", got.KEV, got.KEVFixable)
	}
	if got.BaseClears != 80 || got.BaseTotal != 100 {
		t.Errorf("base leverage = %d/%d, want 80/100", got.BaseClears, got.BaseTotal)
	}
	if got.Actionable != 0 {
		t.Errorf("actionable = %d, want 0", got.Actionable)
	}
}

func TestEstateSumsEveryTeam(t *testing.T) {
	v := buildAnalytics([]model.Finding{
		aFinding("a", 90), aFinding("b", 90), aFinding("b", 1),
	}, nil, analyticsNow)
	if v.Estate.Actionable != 3 {
		t.Errorf("estate actionable = %d, want 3", v.Estate.Actionable)
	}
	if v.Estate.StaleUnstarted != 2 {
		t.Errorf("estate stale unstarted = %d, want 2", v.Estate.StaleUnstarted)
	}
}

func TestAgeBucketsCoverTheWholeRange(t *testing.T) {
	v := buildAnalytics([]model.Finding{
		aFinding("t", 1), aFinding("t", 20), aFinding("t", 60),
		aFinding("t", 120), aFinding("t", 400),
	}, nil, analyticsNow)
	got := v.Teams[0]
	total := 0
	for _, n := range got.AgeBuckets {
		total += n
	}
	if total != 5 {
		t.Errorf("buckets hold %d findings, want all 5: %+v", total, got.AgeBuckets)
	}
	if got.AgeBuckets["180d+"] != 1 {
		t.Errorf("the 400-day finding should land in the open-ended bucket: %+v", got.AgeBuckets)
	}
}

func TestNotesTravelWithThePayload(t *testing.T) {
	// A consumer building its own dashboard needs to know what is missing as much
	// as the page does. Ticket resolution time is the one people assume is here.
	v := buildAnalytics(nil, nil, analyticsNow)
	if len(v.Notes) == 0 {
		t.Fatal("no notes in the payload")
	}
	found := false
	for _, n := range v.Notes {
		if len(n) > 0 && containsFold(n, "resolution time") {
			found = true
		}
	}
	if !found {
		t.Error("the notes should say that ticket resolution time is not measured")
	}
}

func containsFold(hay, needle string) bool {
	return len(hay) >= len(needle) && (indexFold(hay, needle) >= 0)
}

func indexFold(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			a, b := hay[i+j], needle[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
