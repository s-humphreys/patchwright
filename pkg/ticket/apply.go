package ticket

import (
	"context"
	"fmt"
	"log/slog"
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
	// Close transitions a ticket into a done status, with a comment explaining
	// why. Only called when the work is provably finished.
	Close(ctx context.Context, key, comment string) error
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
			r.Err = a.Close(ctx, act.TicketKey, act.Message)
		case ActionNoteStale, ActionNoteDone:
			r.Err = a.Comment(ctx, act.TicketKey, act.Message)
		case ActionSkip:
			// Nothing to do.
		default:
			r.Err = fmt.Errorf("unknown action %q", act.Kind)
		}
		if r.Err != nil {
			slog.WarnContext(ctx, "reconciliation action failed",
				"kind", act.Kind, "ticket", act.TicketKey, "error", r.Err)
		}
		out = append(out, r)
	}
	return out
}

// Summarize counts successful results by action kind, for a one-line report.
// Failures are excluded: they are reported separately rather than counted as done.
func Summarize(results []Result) map[ActionKind]int {
	counts := map[ActionKind]int{}
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		counts[r.Action.Kind]++
	}
	return counts
}
