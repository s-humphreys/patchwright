package group

import (
	"fmt"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Benchmarks at the size of a real estate, because the API aggregates on every
// request and "fast enough" was never measured at this scale.
//
// The shape is taken from a live deployment: 612 findings carrying 208,697 CVEs
// between them, around 10,000 of them distinct, spread over 400 services and a
// handful of teams. The distinctness matters more than the total - the CVE rollup
// allocates per distinct CVE and appends per occurrence, so an estate where every
// image carries the same 300 base-image CVEs behaves quite differently from one where
// they are all unique.
//
// Run with:
//
//	go test ./pkg/group/ -bench . -benchmem -run XXX
const (
	benchFindings = 612
	benchPerImage = 341
	benchDistinct = 10000
)

func benchEstate() []sink.FindingView {
	teams := []string{"payments", "orders", "platform", "data", ""}
	out := make([]sink.FindingView, 0, benchFindings)
	for i := 0; i < benchFindings; i++ {
		// Several tags per service, as deployed: an rc, a preview and a release of the
		// same thing are three findings and one piece of work.
		service := fmt.Sprintf("apps/service-%d", i/2)
		f := sink.FindingView{
			Image:      fmt.Sprintf("reg.example/%s:1.%d.0", service, i%7),
			Registry:   "reg.example",
			Repository: service,
			Tag:        fmt.Sprintf("1.%d.0", i%7),
			Owner: sink.OwnerView{
				Class: "engineering", Team: teams[i%len(teams)], Rule: "by-namespace",
			},
			Counts:           map[string]int{"critical": i % 9, "high": i % 30},
			Priority:         []string{"urgent", "high", "medium", "low"}[i%4],
			Exposure:         []string{"public", "internal", "unknown"}[i%3],
			Scanned:          true,
			ProviderAssessed: true,
			ExploitChecked:   true,
			Dimensions: map[string][]string{
				"namespace": {fmt.Sprintf("ns-%d", i%40)},
				"account":   {fmt.Sprintf("acct-%d", i%6)},
			},
			Upgrade: &sink.UpgradeView{
				Kind: "base", Name: "dotnet/aspnet",
				Current: "9.0", Latest: "10.0", Available: true, Resolved: true,
			},
			Vulns: make([]sink.VulnView, 0, benchPerImage),
		}
		for j := 0; j < benchPerImage; j++ {
			// Overlapping ids across images: the same base-image CVEs recur, which is
			// what makes 208,697 occurrences into roughly 10,000 rows.
			id := fmt.Sprintf("CVE-2026-%05d", (i*benchPerImage+j)%benchDistinct)
			f.Vulns = append(f.Vulns, sink.VulnView{
				ID:             id,
				Severity:       []string{"critical", "high", "medium", "low"}[j%4],
				CVSS:           float64(j%10) + 0.1,
				EPSS:           float64(j%100) / 100,
				EPSSPercentile: float64(j%100) / 100,
				KEV:            j%97 == 0,
				FixAvailable:   j%3 == 0,
				FixedVersion:   "1.2.3",
				RiskScore:      float64(j % 900),
			})
		}
		out = append(out, f)
	}
	return out
}

func BenchmarkItems(b *testing.B) {
	findings := benchEstate()
	b.ReportAllocs()
	for b.Loop() {
		_ = Items(findings)
	}
}

func BenchmarkCVEs(b *testing.B) {
	findings := benchEstate()
	b.ReportAllocs()
	for b.Loop() {
		_ = CVEs(findings, false)
	}
}

// withAffected is what the detail view needs, and it carries a list per CVE of every
// image affected - so it allocates per occurrence rather than per distinct CVE.
func BenchmarkCVEsWithAffected(b *testing.B) {
	findings := benchEstate()
	b.ReportAllocs()
	for b.Loop() {
		_ = CVEs(findings, true)
	}
}

// One CVE, which is what the detail view asks for. It used to build the whole rollup
// with every affected image and pick one row out of it.
func BenchmarkFindCVE(b *testing.B) {
	findings := benchEstate()
	b.ReportAllocs()
	for b.Loop() {
		if FindCVE(findings, "CVE-2026-05000") == nil {
			b.Fatal("the fixture should carry this CVE")
		}
	}
}
