package history

import (
	"context"
	"errors"
	"time"
)

// ErrDisabled is returned by the nil store: history was not configured. Callers
// report it as "not enabled" rather than as a failure.
var ErrDisabled = errors.New("history is not enabled")

// Store is where the record lives. The only implementation is postgres; a nil
// Store means history is off and the tool behaves as it did before it existed.
type Store interface {
	// Open returns every item currently open.
	Open(ctx context.Context) ([]State, error)
	// Record writes one assessment and the events its diff produced, atomically.
	// Opened events create items; resolved and lapsed close them; changed and
	// reassigned update their state. It returns the assessment's id so ticket events
	// recorded later can be attributed to the same run.
	Record(ctx context.Context, a Assessment, events []Event) (assessmentID int64, err error)
	// Append writes events against an assessment already recorded.
	Append(ctx context.Context, assessmentID int64, events []Event) error
	// Events returns events in [since, until), oldest first.
	Events(ctx context.Context, since, until time.Time) ([]Event, error)
	// Assessments returns assessment rows in [since, until), oldest first, without
	// their Items, which are read one run at a time.
	Assessments(ctx context.Context, since, until time.Time) ([]Assessment, error)
	// AssessmentItems returns the work items recorded for one assessment.
	AssessmentItems(ctx context.Context, assessmentID int64) ([]Snapshot, error)
	// Item returns the history of one key: every item row that carried it and their
	// events, oldest first. Nil, nil when the key was never seen.
	Item(ctx context.Context, key string) (*ItemHistory, error)
	// First is when the record begins, and false when it is empty.
	First(ctx context.Context) (time.Time, bool, error)
	// Prune removes events and closed items older than before, and assessments
	// older than before. It reports what it removed.
	Prune(ctx context.Context, before time.Time) (Pruned, error)
	Close()
}

// ItemHistory is one key's record.
type ItemHistory struct {
	Key    string    `json:"key"`
	Items  []ItemRow `json:"items"`
	Events []Event   `json:"events"`
}

// ItemRow is one open-to-close span of a key.
type ItemRow struct {
	ID         int64      `json:"id"`
	Key        string     `json:"key"`
	OpenedAt   time.Time  `json:"opened_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	ClosedKind Kind       `json:"closed_kind,omitempty"`
	Opened     Snapshot   `json:"opened"`
	Current    Snapshot   `json:"current"`
}

// Pruned is what a retention pass removed.
type Pruned struct {
	Events      int64 `json:"events"`
	Items       int64 `json:"items"`
	Assessments int64 `json:"assessments"`
}
