package history

import (
	"fmt"
	"sort"
	"time"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// DefaultDecommissionAfter is how long an item must have been gone before its
// removal is credited as remediation, when none is configured. A week outlasts a
// weekend, a scaled-to-zero preview environment and a cluster rebuilt over a few
// days, all of which look exactly like a decommission while they last.
const DefaultDecommissionAfter = 7 * 24 * time.Hour

// DecommissionLookback is how far back Decommissions needs events and assessments:
// the window itself, again for a run that came late, and a day for the grace
// period between an item disappearing and lapsing.
func DecommissionLookback(after time.Duration) time.Duration {
	if after <= 0 {
		after = DefaultDecommissionAfter
	}
	return 2*after + 24*time.Hour
}

// DecommissionInput is what Decommissions decides from.
type DecommissionInput struct {
	// After is the window. Zero means DefaultDecommissionAfter.
	After time.Duration
	// Events are the record's events over DecommissionLookback, oldest first.
	Events []Event
	// Assessments are the recorded assessments over the same span, without items.
	Assessments []Assessment
	// Current, Views and Partial are this run: its work items, every finding
	// (suppressed and not actionable included) and whether it read every source.
	Current []Snapshot
	Views   []sink.FindingView
	Partial bool
	Now     time.Time
}

// Decommissions credits lapsed items whose workloads were removed. An item lapsed
// as no longer running is decommissioned once it has been gone for the window, if
// every assessment in that span read every source, it has not come back under its
// own key, and nothing in the estate runs its repository under any other: the same
// image live somewhere else is a move or a rename, not a removal. An item lapsed
// because the provider stopped reporting it is never a candidate; that is coverage
// lost while the workload may still run.
//
// Each lapse is judged once, by the first assessment at or after its deadline, so a
// verdict cannot flip on a later run. The event is dated when the workloads
// disappeared, so a report credits the period in which that happened.
func Decommissions(in DecommissionInput) []Event {
	after := in.After
	if after <= 0 {
		after = DefaultDecommissionAfter
	}
	earliest := in.Now.Add(-DecommissionLookback(after))

	done := map[int64]bool{}
	for _, e := range in.Events {
		if e.Kind == KindDecommissioned {
			done[e.ItemID] = true
		}
	}
	current := map[string]bool{}
	repos := map[string]bool{}
	for _, s := range in.Current {
		current[s.Key] = true
		repos[s.Repository] = true
	}
	var out []Event
	for _, lapse := range in.Events {
		if lapse.Kind != KindLapsed || done[lapse.ItemID] || lapse.Payload.Closed == nil ||
			lapseClass(lapse.Payload.Reason) != "no longer running" {
			continue
		}
		since := lapse.At
		if lapse.Payload.MissingSince != nil {
			since = *lapse.Payload.MissingSince
		}
		deadline := since.Add(after)
		if since.Before(earliest) || in.Now.Before(deadline) || judgedBefore(in.Assessments, deadline, in.Now) {
			continue
		}
		closed := lapse.Payload.Closed
		if current[closed.Key] || repos[closed.Repository] || in.Partial ||
			partialSince(in.Assessments, since, in.Now) || runsElsewhere(closed.Repository, in.Views) ||
			cameBack(lapse, closed.Repository, since, in.Events) {
			continue
		}
		done[lapse.ItemID] = true
		out = append(out, decommissioned(lapse, since, after))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// judgedBefore reports whether an assessment already recorded fell at or after the
// deadline: that run judged the lapse, whatever it decided.
func judgedBefore(assessments []Assessment, deadline, now time.Time) bool {
	for _, a := range assessments {
		if !a.FinishedAt.Before(deadline) && a.FinishedAt.Before(now) {
			return true
		}
	}
	return false
}

func partialSince(assessments []Assessment, since, now time.Time) bool {
	for _, a := range assessments {
		if a.Partial && !a.FinishedAt.Before(since) && a.FinishedAt.Before(now) {
			return true
		}
	}
	return false
}

// runsElsewhere reports a finding on the repository that is running, or whose
// liveness is unknown and so cannot vouch that it is not.
func runsElsewhere(repo string, views []sink.FindingView) bool {
	for _, v := range views {
		if v.Repository == repo && (v.Liveness == nil || v.Liveness.Live) {
			return true
		}
	}
	return false
}

// cameBack reports the key reopening, or the repository being in the queue under
// another item, at any point since the workloads disappeared.
func cameBack(lapse Event, repo string, since time.Time, events []Event) bool {
	for _, e := range events {
		if e.At.Before(since) || e.ItemID == lapse.ItemID {
			continue
		}
		switch e.Kind {
		case KindOpened, KindChanged, KindReassigned:
			if e.Key == lapse.Key || (e.Payload.Snapshot != nil && e.Payload.Snapshot.Repository == repo) {
				return true
			}
		}
	}
	return false
}

func decommissioned(lapse Event, since time.Time, after time.Duration) Event {
	p := lapse.Payload
	s := since
	out := Payload{
		Opened: p.Opened, OpenedAt: p.OpenedAt, Closed: p.Closed, MissingSince: &s,
		Ticketed: p.Ticketed, Tickets: p.Closed.Tickets,
		Evidence: fmt.Sprintf("%s: nothing has run it since %s, at least %s; every assessment in that time read every source, and it runs nowhere else.",
			p.Closed.Repository, since.UTC().Format(time.RFC3339), DurationWords(after)),
	}
	if p.OpenedAt != nil {
		days := int(since.Sub(*p.OpenedAt).Hours() / 24)
		out.DaysOpen = &days
	}
	return Event{ItemID: lapse.ItemID, Key: lapse.Key, Kind: KindDecommissioned, At: since, Payload: out}
}

// DurationWords says a window in days when it is a whole number of them.
func DurationWords(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		n := int(d / (24 * time.Hour))
		if n == 1 {
			return "a day"
		}
		return fmt.Sprintf("%d days", n)
	}
	return d.String()
}

// DecommissionedRepositories lists the repositories of the decommissioned events
// given, which ticket reconciliation may close tickets for.
func DecommissionedRepositories(events []Event) map[string]bool {
	out := map[string]bool{}
	for _, e := range events {
		if e.Kind == KindDecommissioned && e.Payload.Closed != nil {
			out[e.Payload.Closed.Repository] = true
		}
	}
	return out
}
