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

func TestWinsRankBaseUpgradesByWhatTheyClear(t *testing.T) {
	// The leverage is not per team: one rebuild fixes every image on that base, so
	// that is what a security engineer should be handed first.
	mk := func(team, from string, clears, total int) model.Finding {
		f := aFinding(team, 10)
		f.Image = model.Image{Ref: "reg/" + team + "-" + from + ":1", Digest: "sha256:" + team + from}
		f.BaseDiff = &model.BaseDiff{
			FromRef: from, ToRef: from + ":new", Determined: true,
			Clears: clears, Total: total,
		}
		return f
	}
	v := buildAnalytics([]model.Finding{
		mk("a", "python", 100, 120),
		mk("b", "python", 100, 120),
		mk("c", "node", 500, 600),
	}, nil, analyticsNow)

	if len(v.Wins) != 2 {
		t.Fatalf("expected two bases, got %d: %+v", len(v.Wins), v.Wins)
	}
	// node clears 500 on one image; python clears 200 across two. Ranked by total
	// cleared, node comes first.
	if v.Wins[0].FromRef != "node" || v.Wins[0].Clears != 500 {
		t.Errorf("first win = %+v, want node clearing 500", v.Wins[0])
	}
	if v.Wins[1].Clears != 200 || v.Wins[1].Images != 2 || v.Wins[1].Teams != 2 {
		t.Errorf("python win = %+v, want 200 cleared over 2 images and 2 teams", v.Wins[1])
	}
}

func TestAWinCountsAnImageOnceEvenWhenSeveralTeamsOwnIt(t *testing.T) {
	// One image is one rebuild. Counting it per owner would treble the headline,
	// which is the number somebody schedules work against.
	shared := func(team string) model.Finding {
		f := aFinding(team, 10)
		f.Image = model.Image{Ref: "reg/shared:1", Digest: "sha256:shared"}
		f.BaseDiff = &model.BaseDiff{FromRef: "base", ToRef: "base:2", Determined: true, Clears: 50, Total: 60}
		return f
	}
	v := buildAnalytics([]model.Finding{shared("a"), shared("b"), shared("c")}, nil, analyticsNow)
	if len(v.Wins) != 1 {
		t.Fatalf("expected one win, got %+v", v.Wins)
	}
	if v.Wins[0].Clears != 50 || v.Wins[0].Images != 1 {
		t.Errorf("win = %+v, want 50 cleared over 1 image", v.Wins[0])
	}
	if v.Wins[0].Teams != 3 {
		t.Errorf("teams = %d, want 3: the rebuild still spans three owners", v.Wins[0].Teams)
	}
}

func TestUndeterminedDifferentialsAreNotRankedAsWins(t *testing.T) {
	// Clears is zero when no candidate was scanned. Ranking that as a win of zero
	// is noise; presenting it as measured would be worse.
	f := aFinding("a", 10)
	f.BaseDiff = &model.BaseDiff{FromRef: "base", Determined: false, Total: 100}
	v := buildAnalytics([]model.Finding{f}, nil, analyticsNow)
	if len(v.Wins) != 0 {
		t.Errorf("an unmeasured base should not be a win: %+v", v.Wins)
	}
}

func TestIssuesGroupByProblemAndDropEmptyCategories(t *testing.T) {
	// A page of zeroes trains people to skim past the ones that are not zero.
	kevNoFix := aFinding("a", 10)
	kevNoFix.Upgrade = nil
	kevNoFix.Vulns = []model.Vulnerability{{ID: "CVE-1", KEV: true, FirstSeen: daysAgo(10)}}

	v := buildAnalytics([]model.Finding{kevNoFix}, nil, analyticsNow)
	keys := map[string]Issue{}
	for _, i := range v.Issues {
		keys[i.Key] = i
	}
	if got, ok := keys["kev-no-fix"]; !ok || got.Count != 1 {
		t.Errorf("kev-no-fix = %+v, want one", got)
	}
	if _, ok := keys["stale-fix"]; ok {
		t.Error("an empty category should not be rendered at zero")
	}
	if got := keys["kev-no-fix"]; got.Why == "" {
		t.Error("an issue needs a reading; a bare count is left to interpretation")
	}
	// Every affected image, not a sample: a count somebody cannot expand is a
	// number they have to take on trust.
	if got := keys["kev-no-fix"]; len(got.Images) != 1 || got.Images[0] != kevNoFix.Image.Ref {
		t.Errorf("images = %v, want the affected image named", got.Images)
	}
}

func TestKEVWithAFixNobodyStartedIsItsOwnIssue(t *testing.T) {
	// Confirmed exploitation with an upgrade sitting there is the top of the list,
	// and must not be diluted into the general unstarted count.
	f := aFinding("a", 60)
	f.Vulns = []model.Vulnerability{{ID: "CVE-1", KEV: true, FirstSeen: daysAgo(60)}}
	v := buildAnalytics([]model.Finding{f}, nil, analyticsNow)
	found := false
	for _, i := range v.Issues {
		if i.Key == "kev-unstarted" && i.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a kev-unstarted issue: %+v", v.Issues)
	}
}

func TestStartedWorkIsNotReportedAsAnIssue(t *testing.T) {
	f := aFinding("a", 90, func(f *model.Finding) {
		f.InFlight = &model.InFlight{Opened: daysAgo(2)}
	})
	v := buildAnalytics([]model.Finding{f}, nil, analyticsNow)
	for _, i := range v.Issues {
		if i.Key == "stale-fix" {
			t.Errorf("work in progress reported as untouched: %+v", i)
		}
	}
}

func TestAnIssueNamesEachImageOnce(t *testing.T) {
	// One image with several findings is one image to go and look at. Listing it
	// per finding turns an expandable list into a wall of duplicates.
	a := aFinding("a", 10)
	a.Upgrade = nil
	a.Vulns = []model.Vulnerability{{ID: "CVE-1", KEV: true, FirstSeen: daysAgo(10)}}
	b := a
	b.Owner = model.Owner{Class: "engineering", Team: "other"}

	v := buildAnalytics([]model.Finding{a, b}, nil, analyticsNow)
	for _, i := range v.Issues {
		if i.Key != "kev-no-fix" {
			continue
		}
		if len(i.Images) != 1 {
			t.Errorf("images = %v, want the image listed once", i.Images)
		}
		if i.Count != 2 {
			t.Errorf("count = %d, want 2: it is still two findings", i.Count)
		}
	}
}

func TestWinsNameTheImagesOnTheBase(t *testing.T) {
	// A rebuild has to be scoped to something. "3 images" with no list is a number
	// somebody has to go and reconstruct by hand.
	mk := func(name string) model.Finding {
		f := aFinding("a", 10)
		f.Image = model.Image{Ref: "reg/" + name + ":1", Digest: "sha256:" + name}
		f.BaseDiff = &model.BaseDiff{FromRef: "base", ToRef: "base:2", Determined: true, Clears: 10, Total: 12}
		return f
	}
	v := buildAnalytics([]model.Finding{mk("b"), mk("a")}, nil, analyticsNow)
	if len(v.Wins) != 1 {
		t.Fatalf("wins = %+v", v.Wins)
	}
	got := v.Wins[0].ImageRefs
	if len(got) != 2 || got[0] != "reg/a:1" || got[1] != "reg/b:1" {
		t.Errorf("image refs = %v, want both, sorted so two runs render the same", got)
	}
}
