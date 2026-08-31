package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/s-humphreys/patchwright/pkg/analytics"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// fixture is one service at two tags: one scanned with a measured base
// differential, one the provider never assessed. That combination is the point -
// most of the guarantees here are about the second row not disappearing into the
// first one's numbers.
func fixture() Assessment {
	base := sink.FindingView{
		Image: "reg.example/apps/topnotch:1.4.0", Repository: "apps/topnotch",
		Tag: "1.4.0", Owner: sink.OwnerView{Team: "payments", Class: "product"},
		Priority: "urgent", Exposure: "public", Scanned: true, ProviderAssessed: true,
		Counts:     map[string]int{"critical": 3, "high": 5},
		Dimensions: map[string][]string{"namespace": {"prod"}},
		Signals:    []string{"exposed", "kev"},
		Upgrade: &sink.UpgradeView{
			Kind: "base", Name: "dotnet/aspnet", Current: "9.0", Latest: "10.0",
			Available: true, Resolved: true, Actionable: true,
		},
		// The differential and the CVE list agree, deliberately: 2 cleared, 2 left in the
		// base, 1 from the application, 1 unattributed, total 6. An earlier fixture
		// claimed 6 clears while listing one clearable CVE, and nothing noticed until
		// the counts started being derived from the list.
		BaseDiff: &sink.BaseDiffView{
			FromRef: "mcr/dotnet/aspnet:9.0", ToRef: "mcr/dotnet/aspnet:10.0",
			Total: 6, FromBase: 4, FromApp: 1, Unknown: 1, Clears: 2, Leaves: 2,
			Introduces: 1, Determined: true,
		},
		Vulns: []sink.VulnView{
			{ID: "CVE-2026-1", Severity: "critical", KEV: true, EPSS: 0.91,
				EPSSPercentile: 0.99, FixAvailable: true, FixedVersion: "1.2.3",
				Origin: "base", OriginDetermined: true, FixedByUpgrade: true},
			{ID: "CVE-2026-4", Severity: "critical", EPSS: 0.02,
				Origin: "base", OriginDetermined: true, FixedByUpgrade: true},
			{ID: "CVE-2026-2", Severity: "high", Origin: "base", OriginDetermined: true,
				Packages: []sink.PackageView{{Name: "zlib", Ecosystem: "debian"}}},
			{ID: "CVE-2026-5", Severity: "medium", Origin: "base", OriginDetermined: true,
				Packages: []sink.PackageView{{Name: "zlib", Ecosystem: "debian"}}},
			{ID: "CVE-2026-3", Severity: "high", Origin: "app", OriginDetermined: true},
			{ID: "CVE-2026-6", Severity: "low"},
		},
	}
	unassessed := sink.FindingView{
		Image: "reg.example/apps/topnotch:1.5.0-rc1", Repository: "apps/topnotch",
		Tag: "1.5.0-rc1", Owner: sink.OwnerView{Team: "payments", Class: "product"},
		Priority: "medium", Exposure: "unknown",
		Counts:  map[string]int{},
		Upgrade: base.Upgrade,
	}
	return Assessment{
		GeneratedAt:        ts("2026-08-30T09:00:00Z"),
		ProviderDataNewest: ts("2026-08-20T09:00:00Z"),
		Version:            "v1.29.0",
		Sources: model.Sources{
			Provider: "rapid7", VulnSource: "trivy", ExploitSource: "public",
			LiveSource: "kube", Remediation: true, BaseDiff: true, InFlight: true,
			Exposure: true,
		},
		Findings: []sink.FindingView{base, unassessed},
		Analytics: analytics.AnalyticsView{
			Wins: []analytics.Win{{
				FromRef: "mcr/dotnet/aspnet:9.0", ToRef: "mcr/dotnet/aspnet:10.0",
				Clears: 6, Introduces: 1, KEVCleared: 1,
				Services: []analytics.ServiceCount{{Service: "apps/topnotch", Team: "payments"}},
			}},
			Issues: []analytics.Issue{{
				Key: "stale-fix", Title: "Fixes available and untouched", Count: 1,
				Why:      "A fix has existed for over a month and nothing has moved.",
				Services: []analytics.ServiceCount{{Service: "apps/topnotch", Team: "payments"}},
			}},
		},
	}
}

func TestServiceReportSplitsTheRemainderByWhoOwnsIt(t *testing.T) {
	r, ok := serviceReport(fixture(), "topnotch")
	if !ok {
		t.Fatal("no report for a service that is present")
	}
	if r.Service != "apps/topnotch" || r.Team != "payments" {
		t.Fatalf("wrong service identity: %+v", r)
	}
	if len(r.Deployments) != 2 {
		t.Fatalf("want both tags reported, got %d", len(r.Deployments))
	}
	u := r.Upgrade
	if u == nil || !u.Measured {
		t.Fatalf("want a measured upgrade, got %+v", u)
	}
	if u.Clears != 2 || u.Leaves != 2 || u.Introduces != 1 {
		t.Errorf("differential not carried through: %+v", u)
	}
	if u.Remainder.StillInBase != 2 || u.Remainder.FromApplication != 1 || u.Remainder.Unattributed != 1 {
		t.Errorf("remainder split wrong: %+v", u.Remainder)
	}
	if len(u.Remainder.Packages) != 1 || u.Remainder.Packages[0].Name != "zlib" ||
		u.Remainder.Packages[0].CVEs != 2 {
		t.Errorf("want the surviving base CVEs' package with a distinct count: %+v", u.Remainder.Packages)
	}
	if u.Move != "version change to 10.0" {
		t.Errorf("a version change must not read as a rebuild: %q", u.Move)
	}
}

// The whole point of the caveats: an unassessed deployment must not vanish into the
// assessed one's numbers.
func TestServiceReportStatesPartialCoverage(t *testing.T) {
	r, _ := serviceReport(fixture(), "apps/topnotch")
	if r.Vulnerabilities.ScannedOf != [2]int{1, 2} {
		t.Errorf("want 1 of 2 scanned, got %v", r.Vulnerabilities.ScannedOf)
	}
	joined := strings.Join(r.Caveats, " ")
	if !strings.Contains(joined, "not zero") && !strings.Contains(joined, "rather than none") {
		t.Errorf("coverage gap not stated in caveats: %v", r.Caveats)
	}
}

func TestServiceReportMissesCleanly(t *testing.T) {
	if _, ok := serviceReport(fixture(), "nothing-like-this"); ok {
		t.Error("want a miss for an unknown service, not an empty report")
	}
}

// Suppressed findings must be out of the counts and IN the answer. Counting them
// put 721 in a caveat beside 706 in an issue on the same payload, which is how a
// tool stops being believed.
func TestSuppressedIsExcludedFromCountsAndStated(t *testing.T) {
	a := fixture()
	a.Findings[1].Suppressed = true
	s := estateSummary(a)
	if s.Deployments != 1 || s.Suppressed != 1 {
		t.Errorf("want one active and one suppressed, got %d / %d", s.Deployments, s.Suppressed)
	}
	if s.Coverage.Total != 1 {
		t.Errorf("coverage must be over active deployments: %+v", s.Coverage)
	}
	if !strings.Contains(strings.Join(s.Caveats, " "), "suppressed by policy") {
		t.Errorf("suppression must be stated: %v", s.Caveats)
	}

	// The service view keeps them, because somebody asking about a service wants all
	// of it - a hidden deployment is how a suppression rule outlives its reason.
	r, ok := serviceReport(a, "topnotch")
	if !ok || len(r.Deployments) != 2 {
		t.Fatalf("want both deployments on the service answer, got %d", len(r.Deployments))
	}
	if !r.Deployments[1].Suppressed {
		t.Error("want the suppressed deployment marked")
	}
}

func TestEstateSummaryCountsCVEsOnceAndReportsCoverage(t *testing.T) {
	s := estateSummary(fixture())
	if s.Vulnerabilities != 6 || s.KnownExploited != 1 {
		t.Errorf("want 6 distinct CVEs and 1 KEV, got %d / %d", s.Vulnerabilities, s.KnownExploited)
	}
	if s.ClearedByRebuilds == nil || *s.ClearedByRebuilds != 2 {
		t.Errorf("want the measured rebuild benefit, got %v", s.ClearedByRebuilds)
	}
	if s.Coverage.Assessed != 1 || s.Coverage.Total != 2 {
		t.Errorf("coverage wrong: %+v", s.Coverage)
	}
	if len(s.Caveats) == 0 {
		t.Error("want the coverage gap stated")
	}
	if len(s.BiggestWins) != 1 || s.BiggestWins[0].Introduces != 1 {
		t.Errorf("a win must carry what it introduces: %+v", s.BiggestWins)
	}
	if s.Freshness.ProviderDataAgeDays == nil || *s.Freshness.ProviderDataAgeDays != 10 {
		t.Errorf("want provider data age, got %v", s.Freshness.ProviderDataAgeDays)
	}
}

// An unassessed image is not a clean image, and a summary of nothing is not a
// summary of an empty estate.
func TestNothingAssessedYetIsNotAnEmptyEstate(t *testing.T) {
	var a Assessment
	if a.ready() {
		t.Fatal("a zero assessment must not read as ready")
	}
}

func TestWorstFirstFiltersAndSaysSo(t *testing.T) {
	q := worstFirst(fixture(), "payments", "urgent", "", 10)
	if q.Total != 1 {
		t.Fatalf("want one urgent payments item, got %d", q.Total)
	}
	if q.Filtered != "team=payments, priority=urgent" {
		t.Errorf("filters not stated back: %q", q.Filtered)
	}
	if q.Items[0].Clears == nil || *q.Items[0].Clears != 2 {
		t.Errorf("want the measured benefit on the row: %+v", q.Items[0])
	}
	none := worstFirst(fixture(), "nobody", "", "", 10)
	if none.Total != 0 {
		t.Errorf("want no items for an unknown team, got %d", none.Total)
	}
	if !strings.Contains(strings.Join(none.Caveats, " "), "payments") {
		t.Errorf("an empty filtered list must name the real teams: %v", none.Caveats)
	}
}

func TestCVEReportSeparatesClearedFromSurviving(t *testing.T) {
	r, ok := cveReport(fixture(), "cve-2026-1")
	if !ok {
		t.Fatal("want a report for a CVE that is present, case-insensitively")
	}
	if !r.KnownExploited || r.ClearedByRebuild != 1 || r.StaysAfterRebuild != 0 {
		t.Errorf("wrong verdict: %+v", r)
	}
	if len(r.ExposedServices) != 1 {
		t.Errorf("want the exposed service named: %+v", r.ExposedServices)
	}
	if !strings.HasSuffix(r.Reference, "CVE-2026-1") {
		t.Errorf("want a public reference: %q", r.Reference)
	}

	stays, _ := cveReport(fixture(), "CVE-2026-2")
	if stays.ClearedByRebuild != 0 || stays.StaysAfterRebuild != 1 {
		t.Errorf("a CVE the upgrade does not fix must say so: %+v", stays)
	}
	if _, ok := cveReport(fixture(), "CVE-1999-0001"); ok {
		t.Error("want a miss for an absent CVE")
	}
}

func TestTeamReportCountsWhatTheTeamOwns(t *testing.T) {
	r, _, ok := teamReport(fixture(), "PAYMENTS")
	if !ok {
		t.Fatal("team lookup must be case-insensitive")
	}
	if r.Services != 1 || r.Urgent != 1 || r.Exposed != 1 {
		t.Errorf("wrong team position: %+v", r)
	}
	if _, _, ok := teamReport(fixture(), "platform"); ok {
		t.Error("want a miss for a team owning nothing here")
	}
}

// A miss has to be recoverable in one more call, not a dead end that sends the
// caller back to the human to ask what the team is called.
func TestTeamMissHandsBackTheRealNames(t *testing.T) {
	_, candidates, ok := teamReport(fixture(), "platform")
	if ok {
		t.Fatal("want a miss")
	}
	if len(candidates) != 1 || candidates[0] != "payments" {
		t.Errorf("want the actual team names back, got %v", candidates)
	}
}

// "payments" should find "payments-platform": people say the short name.
func TestTeamMatchesOnSubstringWhenUnambiguous(t *testing.T) {
	a := fixture()
	for i := range a.Findings {
		a.Findings[i].Owner.Team = "payments-platform"
	}
	resolved, _ := matchTeam(a.items(), "payments")
	if resolved != "payments-platform" {
		t.Errorf("want the substring match, got %q", resolved)
	}
}

// Two candidates must NOT resolve: answering for one of them would look
// authoritative and describe somebody else's queue.
func TestAmbiguousTeamRefusesToGuess(t *testing.T) {
	a := fixture()
	a.Findings[0].Owner.Team = "payments-uk"
	a.Findings[1].Owner.Team = "payments-us"
	resolved, candidates := matchTeam(a.items(), "payments")
	if resolved != "" {
		t.Errorf("want no resolution for an ambiguous name, got %q", resolved)
	}
	if len(candidates) != 2 {
		t.Errorf("want both candidates offered, got %v", candidates)
	}
}

func TestFacetsNameTheVocabulary(t *testing.T) {
	f := facets(fixture())
	if len(f.Teams) != 1 || f.Teams[0].Value != "payments" || f.Teams[0].Items != 1 {
		t.Errorf("wrong teams: %+v", f.Teams)
	}
	// One work item, not two: both tags share an owner, service and upgrade target,
	// so they are one piece of work carrying the worse of the two priorities.
	if len(f.Priorities) != 1 || f.Priorities[0].Value != "urgent" {
		t.Errorf("want the item's worst priority: %+v", f.Priorities)
	}
	if f.Unattributed != 0 {
		t.Errorf("nothing here is unowned: %+v", f)
	}
}

// The regression this exists for: a run with no vuln source must blame the command
// line, not the scan provider. A model read "0 of 817 scanned" and advised finding
// out why the provider was assessing nothing, when nothing had been asked to scan.
func TestUnconfiguredStagesBlameTheConfigurationNotTheProvider(t *testing.T) {
	a := fixture()
	a.Sources = model.Sources{Provider: "rapid7"} // nothing else configured
	for i := range a.Findings {
		a.Findings[i].Scanned = false
		a.Findings[i].BaseDiff = nil
	}
	s := estateSummary(a)

	if s.Freshness.Ran.VulnSource != "none" || s.Freshness.Ran.BaseDifferential {
		t.Errorf("configuration not reported: %+v", s.Freshness.Ran)
	}
	joined := strings.Join(s.Caveats, " ")
	if !strings.Contains(joined, "--vuln-source") {
		t.Errorf("want the missing flag named: %v", s.Caveats)
	}
	if !strings.Contains(joined, "not by measurement") {
		t.Errorf("want zero explained as configuration: %v", s.Caveats)
	}
	if strings.Contains(joined, "worth investigating") {
		t.Errorf("must not blame the provider for a stage nobody enabled: %v", s.Caveats)
	}
}

// The opposite case, which needs the opposite advice: the stage WAS configured and
// still produced nothing, so somebody should go and look.
func TestConfiguredStagesThatProduceNothingAreAFault(t *testing.T) {
	a := fixture()
	a.Sources = model.Sources{Provider: "rapid7", VulnSource: "trivy", Remediation: true, BaseDiff: true}
	for i := range a.Findings {
		a.Findings[i].Scanned = false
		a.Findings[i].BaseDiff = nil
	}
	joined := strings.Join(estateSummary(a).Caveats, " ")
	if !strings.Contains(joined, "worth investigating") {
		t.Errorf("want a configured-but-empty stage flagged as a fault: %q", joined)
	}
	if strings.Contains(joined, "--vuln-source") {
		t.Errorf("must not tell somebody to set a flag they already set: %q", joined)
	}
}

// scan.disabled looks identical to no source at all unless it is reported.
func TestScanningDisabledInConfigSaysSo(t *testing.T) {
	a := fixture()
	a.Sources = model.Sources{VulnSource: "trivy", ScanDisabled: true}
	joined := strings.Join(estateSummary(a).Caveats, " ")
	if !strings.Contains(joined, "scan.disabled") {
		t.Errorf("want the config setting named: %q", joined)
	}
}

func TestUnassessedReasonsAreCountedWorstFirst(t *testing.T) {
	a := fixture()
	a.Findings[1].AssessmentIssues = []string{"no registry credential"}
	a.Findings[0].ProviderAssessed = false
	a.Findings[0].AssessmentIssues = []string{"no registry credential", "unsupported image type"}
	got := unassessedReasons(a.Findings)
	if len(got) != 2 || got[0].Reason != "no registry credential" || got[0].Deployments != 2 {
		t.Errorf("want the commonest cause first with its count: %+v", got)
	}
}

// Every tool carries freshness, including the configuration. A service answer that
// omitted it would be the one most likely to be read in isolation.
func TestServiceReportCarriesFreshnessAndConfiguration(t *testing.T) {
	r, _ := serviceReport(fixture(), "topnotch")
	if r.Freshness.AssessedAt == "" || r.Freshness.Version == "" {
		t.Errorf("want freshness on a service answer: %+v", r.Freshness)
	}
	if r.Freshness.Ran.VulnSource == "" {
		t.Error("want the configuration on a service answer")
	}
}

// End to end over the real transport: the tools are only useful if a client can
// call them, and the schemas are generated rather than written, so this is where a
// bad argument type would show up.
func TestToolsAnswerOverStreamableHTTP(t *testing.T) {
	a := fixture()
	srv := httptest.NewServer(Handler("patchwright", "test", func() Assessment { return a }))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	want := map[string]bool{
		"estate_summary": true, "service_report": true, "worst_first": true,
		"team_report": true, "explain_cve": true,
	}
	for _, tool := range tools.Tools {
		delete(want, tool.Name)
	}
	if len(want) > 0 {
		t.Errorf("tools not registered: %v", want)
	}

	res, err := session.CallTool(ctx, &sdk.CallToolParams{
		Name: "service_report", Arguments: map[string]any{"service": "topnotch"},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	text, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatalf("want text content, got %T", res.Content[0])
	}
	var got ServiceReport
	if err := json.Unmarshal([]byte(text.Text), &got); err != nil {
		t.Fatalf("tool text must be parseable JSON: %v", err)
	}
	if got.Upgrade == nil || got.Upgrade.Clears != 2 {
		t.Errorf("wrong answer over the wire: %+v", got.Upgrade)
	}
}

// Before the first assessment every tool must say so rather than return an empty
// result a model would summarise as "nothing to worry about".
func TestToolsRefuseToAnswerBeforeTheFirstAssessment(t *testing.T) {
	srv := httptest.NewServer(Handler("patchwright", "test", func() Assessment { return Assessment{} }))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "estate_summary"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	text := res.Content[0].(*sdk.TextContent).Text
	if !strings.Contains(text, "not an empty estate") {
		t.Errorf("want an explicit not-ready answer, got %q", text)
	}
}

// The no-op upgrade, reported live: wiremock/wiremock came back "urgent" with
// "1.11.0 -> 1.11.0". A chart already on its newest version reports that version as
// Latest with Available false, and reading Latest alone rendered a move. An urgent row
// asking for a pull request that changes nothing is worse than no advice, because the
// real answer - this needs a decision, not a bump - is what it hides.
func TestAnUpgradeWithNothingToMoveToIsNotReportedAsAMove(t *testing.T) {
	a := fixture()
	for i := range a.Findings {
		a.Findings[i].Upgrade = &sink.UpgradeView{
			Kind: "chart", Name: "wiremock", Current: "1.11.0", Latest: "1.11.0",
			Resolved: true, Available: false,
		}
		a.Findings[i].BaseDiff = nil
	}

	q := worstFirst(a, "", "", "", 10)
	if len(q.Items) == 0 {
		t.Fatal("want the item")
	}
	if strings.Contains(q.Items[0].Upgrade, "1.11.0 -> 1.11.0") {
		t.Errorf("a no-op move was reported: %q", q.Items[0].Upgrade)
	}
	if !strings.Contains(q.Items[0].Upgrade, "newest available") {
		t.Errorf("want the state named, got %q", q.Items[0].Upgrade)
	}

	r, ok := serviceReport(a, "topnotch")
	if !ok {
		t.Fatal("want a report")
	}
	if r.Upgrade.To != "" {
		t.Errorf("To = %q, want empty: there is no version to move to", r.Upgrade.To)
	}
	if r.Upgrade.State != "latest" {
		t.Errorf("State = %q, want \"latest\"", r.Upgrade.State)
	}
}

// The other three states have to be distinguishable from each other, since only one of
// them is a pull request.
func TestUpgradeStatesAreKeptApart(t *testing.T) {
	cases := []struct {
		name  string
		up    *sink.UpgradeView
		state string
		says  string
	}{
		{"a real upgrade", &sink.UpgradeView{
			Current: "9.0", Latest: "10.0", Resolved: true, Available: true},
			"upgrade", "9.0 -> 10.0"},
		{"held back by policy", &sink.UpgradeView{
			Current: "3.12.14", Newest: "3.14.7", Rule: "python-ceiling",
			Resolved: true, HeldBack: true},
			"held", "held at 3.12.14 by policy"},
		{"the lookup could not answer", &sink.UpgradeView{
			Current: "1.0.0", Resolved: false, Reason: "could not list tags"},
			"unresolved", "not established: could not list tags"},
		{"already newest", &sink.UpgradeView{
			Current: "1.11.0", Latest: "1.11.0", Resolved: true},
			"latest", "already on the newest available version"},
	}
	for _, c := range cases {
		if got := upgradeState(c.up); got != c.state {
			t.Errorf("%s: state = %q, want %q", c.name, got, c.state)
		}
		if got := describeUpgrade(c.up); !strings.Contains(got, c.says) {
			t.Errorf("%s: described as %q, want it to mention %q", c.name, got, c.says)
		}
	}
	if describeUpgrade(nil) != "" {
		t.Error("no upgrade at all must describe as nothing, not as a state")
	}
}

// The arithmetic has to close. This is the guard the tool needed and did not have.
//
// Reported live: topnotch, deployed at three tags of one build, was told it had 6,746
// vulnerabilities and that upgrading would clear 17,571 of them. Every per-deployment
// count was being summed while the CVE total was deduped, so the same CVEs were counted
// once per tag. A team cannot act on a number that is impossible on its face, and the
// figure they would have put in a ticket was three times the truth.
func TestTheCountsReconcileAcrossDeployments(t *testing.T) {
	a := fixture()
	// The case that broke it: the same service at three tags, carrying the same CVEs.
	first := a.Findings[0]
	for _, tag := range []string{"1.4.1", "1.4.2"} {
		copy := first
		copy.Image = "reg.example/apps/topnotch:" + tag
		copy.Tag = tag
		a.Findings = append(a.Findings, copy)
	}

	r, ok := serviceReport(a, "topnotch")
	if !ok {
		t.Fatal("want a report")
	}
	if len(r.Deployments) != 4 {
		t.Fatalf("want the four deployments, got %d", len(r.Deployments))
	}
	v, u := r.Vulnerabilities, r.Upgrade

	// One unit throughout: distinct CVEs on this service. Three tags of one build carry
	// one set of CVEs, so nothing may triple.
	if v.Total != 6 {
		t.Errorf("total = %d, want 6 distinct CVEs however many tags carry them", v.Total)
	}
	if u.Clears != 2 || u.Leaves != 2 {
		t.Errorf("clears/leaves = %d/%d, want 2/2 - summing across tags is what tripled them",
			u.Clears, u.Leaves)
	}
	if u.Introduces != 1 {
		t.Errorf("introduces = %d, want 1: the worst deployment, not a sum", u.Introduces)
	}

	// And the split accounts for every CVE exactly once.
	got := u.Clears + u.Remainder.StillInBase + u.Remainder.FromApplication + u.Remainder.Unattributed
	if got != v.Total {
		t.Errorf("clears(%d) + still_in_base(%d) + from_application(%d) + unattributed(%d) = %d, want the total %d",
			u.Clears, u.Remainder.StillInBase, u.Remainder.FromApplication,
			u.Remainder.Unattributed, got, v.Total)
	}
	// Clears can never exceed the total. It did, which is how this was noticed.
	if u.Clears > v.Total {
		t.Errorf("an upgrade cannot clear %d of %d vulnerabilities", u.Clears, v.Total)
	}

	// A package's count is distinct CVEs in it, so it cannot exceed the remainder.
	for _, p := range u.Remainder.Packages {
		if p.CVEs > u.Remainder.StillInBase {
			t.Errorf("package %s reports %d CVEs, more than the %d left in the base",
				p.Name, p.CVEs, u.Remainder.StillInBase)
		}
	}
}

// The estate figure has to be comparable with the estate total, since they are printed
// beside each other: 77,699 cleared against 10,198 vulnerabilities was two units in
// adjacent fields, and the larger one impossible.
func TestTheEstateRebuildFigureIsComparableWithTheTotal(t *testing.T) {
	a := fixture()
	first := a.Findings[0]
	for _, tag := range []string{"1.4.1", "1.4.2"} {
		copy := first
		copy.Image = "reg.example/apps/topnotch:" + tag
		copy.Tag = tag
		a.Findings = append(a.Findings, copy)
	}
	s := estateSummary(a)
	if s.ClearedByRebuilds == nil {
		t.Fatal("want a measured figure")
	}
	if *s.ClearedByRebuilds > s.Vulnerabilities {
		t.Errorf("rebuilds cannot clear %d of %d distinct vulnerabilities",
			*s.ClearedByRebuilds, s.Vulnerabilities)
	}
	if *s.ClearedByRebuilds != 2 {
		t.Errorf("cleared_by_rebuilds = %d, want 2 distinct CVEs", *s.ClearedByRebuilds)
	}

	// Same for the queue row a team reads.
	q := worstFirst(a, "", "", "", 10)
	if q.Items[0].Clears == nil || *q.Items[0].Clears != 2 {
		t.Errorf("queue row clears = %v, want 2 distinct CVEs", q.Items[0].Clears)
	}

	// And for the team rollup.
	tr, _, ok := teamReport(a, "payments")
	if !ok {
		t.Fatal("want a team report")
	}
	if tr.ClearedByRebuilds == nil || *tr.ClearedByRebuilds != 2 {
		t.Errorf("team clears = %v, want 2 distinct CVEs", tr.ClearedByRebuilds)
	}
}

// EPSS score and percentile describe one CVE, so they must come from the same one.
func TestTheTopEPSSPercentileBelongsToTheTopScore(t *testing.T) {
	a := fixture()
	a.Findings[0].Vulns = []sink.VulnView{
		{ID: "CVE-A", EPSS: 0.90, EPSSPercentile: 0.97, Origin: "base", OriginDetermined: true},
		{ID: "CVE-B", EPSS: 0.20, EPSSPercentile: 0.99, Origin: "base", OriginDetermined: true},
	}
	r, _ := serviceReport(a, "topnotch")
	if r.Vulnerabilities.TopEPSS != 0.90 {
		t.Errorf("top_epss = %v, want the highest score", r.Vulnerabilities.TopEPSS)
	}
	if r.Vulnerabilities.TopPercentile != 0.97 {
		t.Errorf("top_epss_percentile = %v, want 0.97 - the percentile of the worst-scoring "+
			"CVE, not the highest percentile present, which belongs to a quieter one",
			r.Vulnerabilities.TopPercentile)
	}
}

// An invariant sweep over a synthetic estate the shape of a real one: many services,
// each deployed at several tags carrying overlapping CVEs.
//
// This is the shape that broke the counts. A fixture with one deployment per service
// cannot tell a sum from a distinct count, because they are equal - which is why the
// tripling reached production with a green suite.
func realisticEstate() Assessment {
	teams := []string{"payments", "orders", "platform", ""}
	var findings []sink.FindingView
	for svc := 0; svc < 40; svc++ {
		repo := fmt.Sprintf("apps/service-%d", svc)
		// One CVE set per service, shared by every tag of it, as a real build is.
		var vulns []sink.VulnView
		for j := 0; j < 20; j++ {
			id := fmt.Sprintf("CVE-2026-%04d", (svc*7+j)%120) // deliberate overlap between services
			v := sink.VulnView{ID: id, Severity: []string{"critical", "high", "medium", "low"}[j%4]}
			switch j % 4 {
			case 0:
				v.Origin, v.OriginDetermined, v.FixedByUpgrade = "base", true, true
			case 1:
				v.Origin, v.OriginDetermined = "base", true
				v.Packages = []sink.PackageView{{Name: "zlib", Ecosystem: "debian"}}
			case 2:
				v.Origin, v.OriginDetermined = "app", true
			default: // undetermined
			}
			if j == 0 {
				v.KEV, v.EPSS, v.EPSSPercentile = true, 0.91, 0.99
			}
			vulns = append(vulns, v)
		}
		for tag := 0; tag < 3; tag++ {
			findings = append(findings, sink.FindingView{
				Image:      fmt.Sprintf("reg.example/%s:1.%d.0", repo, tag),
				Repository: repo, Tag: fmt.Sprintf("1.%d.0", tag),
				Owner:            sink.OwnerView{Team: teams[svc%len(teams)], Class: "engineering"},
				Priority:         []string{"urgent", "high", "medium", "low"}[svc%4],
				Exposure:         []string{"public", "internal", "unknown"}[svc%3],
				Scanned:          true,
				ProviderAssessed: true,
				Counts:           map[string]int{"critical": 5, "high": 5},
				Upgrade: &sink.UpgradeView{
					Kind: "base", Name: "base/image", Current: "1.0", Latest: "2.0",
					Available: true, Resolved: true,
				},
				BaseDiff: &sink.BaseDiffView{
					FromRef: "base/image:1.0", ToRef: "base/image:2.0",
					Total: 20, Clears: 5, Leaves: 5, FromApp: 5, Unknown: 5,
					Introduces: 2, Determined: true,
				},
				Vulns: vulns,
			})
		}
	}
	return Assessment{
		GeneratedAt: ts("2026-08-31T09:00:00Z"), Version: "test", Findings: findings,
		Sources: model.Sources{Provider: "rapid7", VulnSource: "trivy", Remediation: true, BaseDiff: true},
	}
}

func TestEveryAnswerReconcilesOnARealisticEstate(t *testing.T) {
	a := realisticEstate()
	estate := estateSummary(a)

	if estate.ClearedByRebuilds == nil {
		t.Fatal("want a measured figure")
	}
	if *estate.ClearedByRebuilds > estate.Vulnerabilities {
		t.Errorf("estate: clears %d of %d distinct CVEs", *estate.ClearedByRebuilds, estate.Vulnerabilities)
	}
	if estate.Coverage.Scanned > estate.Coverage.Total {
		t.Errorf("coverage: scanned %d of %d", estate.Coverage.Scanned, estate.Coverage.Total)
	}

	// Every service's split must account for its total exactly, and nothing may exceed it.
	for svc := 0; svc < 40; svc++ {
		repo := fmt.Sprintf("apps/service-%d", svc)
		r, ok := serviceReport(a, repo)
		if !ok {
			t.Fatalf("%s: no report", repo)
		}
		u, total := r.Upgrade, r.Vulnerabilities.Total
		if u == nil || !u.Measured {
			t.Fatalf("%s: want a measured differential", repo)
		}
		sum := u.Clears + u.Remainder.StillInBase + u.Remainder.FromApplication + u.Remainder.Unattributed
		if sum != total {
			t.Errorf("%s: split sums to %d, total is %d", repo, sum, total)
		}
		if u.Clears > total {
			t.Errorf("%s: clears %d of %d", repo, u.Clears, total)
		}
		if r.Vulnerabilities.KnownExploited > total || r.Vulnerabilities.EPSSHigh > total {
			t.Errorf("%s: kev(%d) or epss(%d) exceeds the total %d",
				repo, r.Vulnerabilities.KnownExploited, r.Vulnerabilities.EPSSHigh, total)
		}
		for _, p := range u.Remainder.Packages {
			if p.CVEs > u.Remainder.StillInBase {
				t.Errorf("%s: package %s has %d CVEs, more than the %d left in the base",
					repo, p.Name, p.CVEs, u.Remainder.StillInBase)
			}
		}
	}

	// Teams roll up to no more than the estate.
	for _, team := range facets(a).Teams {
		r, _, ok := teamReport(a, team.Value)
		if !ok {
			t.Errorf("%s: in facets but has no report", team.Value)
			continue
		}
		if r.ClearedByRebuilds != nil && *r.ClearedByRebuilds > *estate.ClearedByRebuilds {
			t.Errorf("%s: clears %d, the estate clears %d",
				team.Value, *r.ClearedByRebuilds, *estate.ClearedByRebuilds)
		}
		if r.Urgent+r.High > r.WorkItems {
			t.Errorf("%s: urgent+high exceeds work items", team.Value)
		}
	}

	// And a CVE cannot be cleared on more deployments than carry it.
	for _, id := range []string{"CVE-2026-0000", "CVE-2026-0007", "CVE-2026-0014"} {
		r, ok := cveReport(a, id)
		if !ok {
			continue
		}
		if r.ClearedByRebuild+r.StaysAfterRebuild > r.Deployments {
			t.Errorf("%s: cleared+stays exceeds %d deployments", id, r.Deployments)
		}
		if len(r.Services) > r.ServicesAffected {
			t.Errorf("%s: lists more services than it counts", id)
		}
	}
}

// Partial coverage, which the live pod produces daily: a base image whose recorded digest
// or tag has been deleted from its registry cannot be scanned, so a service can have some
// deployments measured and some not. Fifteen services on the real estate are in that
// state.
//
// The CVEs of an unmeasured deployment must still be accounted for. Classifying only from
// the measured ones left them out of the split while the total counted them, so the four
// numbers stopped adding up - visible to a team as arithmetic that does not work.
func TestPartlyMeasuredServicesStillReconcile(t *testing.T) {
	a := fixture()
	// A second deployment with its OWN extra CVE and no differential: the base it was
	// built on is gone from the registry.
	extra := a.Findings[0]
	extra.Image = "reg.example/apps/topnotch:preview"
	extra.Tag = "preview"
	extra.BaseDiff = nil
	extra.Vulns = append([]sink.VulnView{{ID: "CVE-2026-99", Severity: "high"}}, extra.Vulns...)
	a.Findings = append(a.Findings, extra)

	r, ok := serviceReport(a, "topnotch")
	if !ok {
		t.Fatal("want a report")
	}
	u, v := r.Upgrade, r.Vulnerabilities
	if !u.Measured {
		t.Fatal("one deployment was measured, so the differential is partial rather than absent")
	}
	if u.DeploymentsMeasured != 1 {
		t.Errorf("deployments_measured = %d, want 1 of %d", u.DeploymentsMeasured, len(r.Deployments))
	}
	if v.Total != 7 {
		t.Errorf("total = %d, want 7: the six shared CVEs plus the preview's own", v.Total)
	}

	sum := u.Clears + u.Remainder.StillInBase + u.Remainder.FromApplication + u.Remainder.Unattributed
	if sum != v.Total {
		t.Errorf("clears(%d)+base(%d)+app(%d)+unattributed(%d) = %d, want the total %d",
			u.Clears, u.Remainder.StillInBase, u.Remainder.FromApplication,
			u.Remainder.Unattributed, sum, v.Total)
	}
	// The extra CVE has no established origin, so that is where it must sit: 1 already
	// undetermined in the fixture, plus this one.
	if u.Remainder.Unattributed != 2 {
		t.Errorf("unattributed = %d, want 2", u.Remainder.Unattributed)
	}
	// And the reader is told the coverage is partial rather than left to infer it.
	if !strings.Contains(strings.Join(r.Caveats, " "), "differential ran for 1 of 3 deployments") {
		t.Errorf("want the partial coverage stated: %v", r.Caveats)
	}
}
