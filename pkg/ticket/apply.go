package ticket

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/s-humphreys/patchwright/internal/metrics"
)

// Applier performs the Jira side of reconciliation. *Jira satisfies it; tests
// provide a recorder so what would happen can be asserted without a Jira.
type Applier interface {
	Create(ctx context.Context, d Draft) (string, error)
	AddImages(ctx context.Context, key string, images []string) error
	Comment(ctx context.Context, key, body string) error
	// Update rewrites an existing ticket's summary and description from a fresh
	// draft. Used only on tickets nobody has picked up; see Existing.Untouched.
	Update(ctx context.Context, key string, d Draft) error
	// Close transitions a ticket into a done status, with a comment explaining why.
	// Only called when the work is provably finished.
	Close(ctx context.Context, req CloseRequest) error
	// CommentOnce posts a comment unless one with the same dedupe reference is
	// already present, reporting whether it posted. An empty dedupe always posts.
	CommentOnce(ctx context.Context, key, dedupe, body string) (bool, error)
}

// CloseRequest is everything closing a ticket needs. A struct rather than a
// widening parameter list, so adding a condition cannot silently reorder arguments.
type CloseRequest struct {
	Key     string
	Comment string
	// Unworked marks a ticket nobody picked up, which widens the transitions that
	// may be used. See config.CloseTransitionUnworked.
	Unworked bool
}

// Result records what an Apply run did, per action, so a caller can report it
// rather than inferring it from logs.
type Result struct {
	Action Action
	// Key is the ticket acted on: newly created for ActionCreate, otherwise the
	// existing one.
	Key string
	// Err is set when this action failed. Applying continues: one ticket failing
	// should not strand the rest, unlike creation from scratch where a failure is
	// usually systematic.
	Err error
	// NoOp is set when the action was correct but nothing needed doing — a comment
	// already present, say. Distinguished from success so a log does not claim a
	// write that did not happen.
	NoOp bool
}

// Apply performs the actions. ActionSkip does nothing by design, and is returned
// so the caller can report "already correct" rather than silence.
func Apply(ctx context.Context, a Applier, actions []Action) []Result {
	out := make([]Result, 0, len(actions))
	for _, act := range actions {
		r := Result{Action: act, Key: act.TicketKey}
		switch act.Kind {
		case ActionCreate:
			key, err := a.Create(ctx, act.Draft)
			r.Key, r.Err = key, err
		case ActionExtend:
			// Add the images first, then explain why: if the comment fails the
			// ticket is still correct, whereas the reverse leaves an explanation
			// for something that did not happen.
			if r.Err = a.AddImages(ctx, act.TicketKey, act.Images); r.Err == nil && act.Message != "" {
				r.Err = a.Comment(ctx, act.TicketKey, act.Message)
			}
		case ActionUpdate:
			r.Err = a.Update(ctx, act.TicketKey, act.Draft)
		case ActionClose:
			r.Err = a.Close(ctx, CloseRequest{
				Key: act.TicketKey, Comment: act.Message, Unworked: act.Unworked,
			})
		case ActionNoteStale, ActionNoteDone:
			var posted bool
			posted, r.Err = a.CommentOnce(ctx, act.TicketKey, act.Dedupe, act.Message)
			r.NoOp = r.Err == nil && !posted
		case ActionSkip:
			// Nothing to do.
		default:
			r.Err = fmt.Errorf("unknown action %q", act.Kind)
		}
		// Recorded here rather than at either call site, so the CLI and the server
		// cannot drift on what counts as applied.
		metrics.TicketAction(string(act.Kind), actionResult(r))
		if r.Err != nil {
			slog.WarnContext(ctx, "reconciliation action failed",
				"kind", act.Kind, "ticket", act.TicketKey, "error", r.Err)
		}
		out = append(out, r)
	}
	return out
}

// actionResult classifies one result for the metric: a no-op is neither a write
// nor a failure, and collapsing it into "applied" would report work that did not
// happen.
func actionResult(r Result) string {
	switch {
	case r.Err != nil:
		return "failed"
	case r.NoOp:
		return "noop"
	default:
		return "applied"
	}
}

// Summarize counts results that actually changed something, by action kind.
//
// Failures are excluded, and so are no-ops: counting a comment that was already
// present as a comment posted would report work that did not happen, which is the
// same error as counting an unassessed image as clean.
func Summarize(results []Result) map[ActionKind]int {
	counts := map[ActionKind]int{}
	for _, r := range results {
		if r.Err != nil || r.NoOp {
			continue
		}
		counts[r.Action.Kind]++
	}
	return counts
}

// NoOps counts results that needed nothing doing, so a report can say "already
// said that" rather than implying either a write or a failure.
func NoOps(results []Result) int {
	n := 0
	for _, r := range results {
		if r.Err == nil && r.NoOp {
			n++
		}
	}
	return n
}
