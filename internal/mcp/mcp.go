// Package mcp exposes an assessment as Model Context Protocol tools.
//
// The tools answer questions rather than mirroring endpoints. An LLM given a REST
// client asks three calls and a join to find out what a page shows in one glance,
// and gets the join wrong often enough to matter. So each tool here is one question
// somebody actually asks, answered completely.
//
// Two rules hold everywhere, and both exist because prose loses what a table keeps.
//
// Every answer states when the assessment ran and how old the scan provider's own
// data is. "Nothing is exploitable in production" means something different against
// data from an hour ago and from a fortnight ago, and a model asked to summarise
// will drop that unless it is in front of it.
//
// And absence never renders as zero. An image nobody scanned is not a clean image,
// the page is careful to say so, and a tool that answered "0 vulnerabilities" for an
// unassessed service would undo that at the point it matters most - because nobody
// re-reads a sentence a chatbot produced.
package mcp

import (
	"time"

	"github.com/s-humphreys/patchwright/pkg/analytics"
	"github.com/s-humphreys/patchwright/pkg/group"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Assessment is everything the tools answer from: one cached assessment, plus when
// it was taken.
//
// Passed in rather than fetched, so the same tools serve the API server's cache and
// a one-shot command-line run without either knowing about the other.
type Assessment struct {
	// GeneratedAt is when this assessment completed. Zero when none has.
	GeneratedAt time.Time
	// ProviderDataNewest is the newest timestamp in the scan provider's own data,
	// which ages independently of when this ran: a service refreshing hourly over a
	// stale export reports a fresh assessment of ancient data forever.
	ProviderDataNewest time.Time
	// Version is the build that produced it.
	Version string

	Findings  []sink.FindingView
	Analytics analytics.AnalyticsView

	// Sources is what the run was configured to do. Without it "0 scanned" reads as
	// a broken scan provider when the truth is that no vuln source was named - which
	// is exactly what a model concluded, confidently, on the first real session.
	Sources model.Sources
}

// Source provides the current assessment. The server implements this over its
// cache; the CLI over a single run.
type Source func() Assessment

// items groups the findings into work items - the unit a team owns and a ticket
// covers - using the same code the API and the page use, so a tool answer and a
// queue row cannot disagree about what a service owes.
//
// Over ACTIVE findings only. Suppressed ones are policy decisions that this is not
// work, and counting them here put a different total in front of the same reader as
// the page: one answer said 721 unassessed deployments while the issue beside it
// said 706, which is the sort of disagreement that costs a tool its credibility.
func (a Assessment) items() []group.Item { return group.Items(a.active()) }

// active is the findings that are somebody's work: everything policy has not
// suppressed. Suppression is never silent - whatever counts these reports how many
// were left out.
func (a Assessment) active() []sink.FindingView {
	out := make([]sink.FindingView, 0, len(a.Findings))
	for _, f := range a.Findings {
		if !f.Suppressed {
			out = append(out, f)
		}
	}
	return out
}

// ready reports whether there is anything to answer from.
func (a Assessment) ready() bool { return !a.GeneratedAt.IsZero() }
