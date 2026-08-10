// Package sink renders findings for consumption. A Sink writes findings to an
// io.Writer in a particular format; the table and json sinks cover human and
// machine consumers respectively. Later phases add sinks that create Jira
// tickets or GitOps pull requests behind the same interface.
package sink

import (
	"io"
	"sort"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// Sink renders findings to w.
type Sink interface {
	Emit(w io.Writer, findings []model.Finding) error
}

// fixableCriticals counts a finding's critical vulnerabilities that have a fix
// available — the cheapest, highest-impact work. Zero unless a vuln source
// (e.g. Trivy) has scanned the image.
func fixableCriticals(f model.Finding) int {
	n := 0
	for _, v := range f.Vulns {
		if v.FixAvailable && v.Severity == model.SeverityCritical {
			n++
		}
	}
	return n
}

// SortForReport orders findings for presentation: actionable first, then by
// priority, then by critical count, then risk, then image reference for
// stability. It sorts a copy and returns it, leaving the input untouched.
func SortForReport(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Actionable != b.Actionable {
			return a.Actionable // actionable first
		}
		if ra, rb := model.PriorityRank(a.Priority), model.PriorityRank(b.Priority); ra != rb {
			return ra > rb
		}
		if ca, cb := a.Counts.Get(model.SeverityCritical), b.Counts.Get(model.SeverityCritical); ca != cb {
			return ca > cb
		}
		if a.RiskScore != b.RiskScore {
			return a.RiskScore > b.RiskScore
		}
		return a.Image.Ref < b.Image.Ref
	})
	return out
}
