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

// priorityRank orders the conventional priority labels; unknown labels sort
// last. Priorities are free-form in config, so this is a best-effort ordering
// for display only.
func priorityRank(p string) int {
	switch p {
	case model.PriorityHigh:
		return 3
	case model.PriorityMedium:
		return 2
	case model.PriorityLow:
		return 1
	default:
		return 0
	}
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
		if ra, rb := priorityRank(a.Priority), priorityRank(b.Priority); ra != rb {
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
