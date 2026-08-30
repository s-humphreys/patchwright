package mcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/s-humphreys/patchwright/pkg/analytics"
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
		BaseDiff: &sink.BaseDiffView{
			FromRef: "mcr/dotnet/aspnet:9.0", ToRef: "mcr/dotnet/aspnet:10.0",
			Total: 10, FromBase: 8, FromApp: 2, Clears: 6, Leaves: 2, Introduces: 1,
			Determined: true,
		},
		Vulns: []sink.VulnView{
			{ID: "CVE-2026-1", Severity: "critical", KEV: true, EPSS: 0.91,
				EPSSPercentile: 0.99, FixAvailable: true, FixedVersion: "1.2.3",
				Origin: "base", OriginDetermined: true, FixedByUpgrade: true},
			{ID: "CVE-2026-2", Severity: "high", Origin: "base", OriginDetermined: true,
				Packages: []sink.PackageView{{Name: "zlib", Ecosystem: "debian"}}},
			{ID: "CVE-2026-3", Severity: "high", Origin: "app", OriginDetermined: true},
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
		Findings:           []sink.FindingView{base, unassessed},
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
	if u.Clears != 6 || u.Leaves != 2 || u.Introduces != 1 {
		t.Errorf("differential not carried through: %+v", u)
	}
	if u.Remainder.StillInBase != 2 || u.Remainder.FromApplication != 2 {
		t.Errorf("remainder split wrong: %+v", u.Remainder)
	}
	if len(u.Remainder.Packages) != 1 || u.Remainder.Packages[0].Name != "zlib" {
		t.Errorf("want the surviving base CVE's package named: %+v", u.Remainder.Packages)
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

func TestEstateSummaryCountsCVEsOnceAndReportsCoverage(t *testing.T) {
	s := estateSummary(fixture())
	if s.Vulnerabilities != 3 || s.KnownExploited != 1 {
		t.Errorf("want 3 distinct CVEs and 1 KEV, got %d / %d", s.Vulnerabilities, s.KnownExploited)
	}
	if s.ClearedByRebuilds == nil || *s.ClearedByRebuilds != 6 {
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
	if q.Items[0].Clears == nil || *q.Items[0].Clears != 6 {
		t.Errorf("want the measured benefit on the row: %+v", q.Items[0])
	}
	if none := worstFirst(fixture(), "nobody", "", "", 10); none.Total != 0 {
		t.Errorf("want no items for an unknown team, got %d", none.Total)
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
	r, ok := teamReport(fixture(), "PAYMENTS")
	if !ok {
		t.Fatal("team lookup must be case-insensitive")
	}
	if r.Services != 1 || r.Urgent != 1 || r.Exposed != 1 {
		t.Errorf("wrong team position: %+v", r)
	}
	if _, ok := teamReport(fixture(), "platform"); ok {
		t.Error("want a miss for a team owning nothing here")
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
	if got.Upgrade == nil || got.Upgrade.Clears != 6 {
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
