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
	Record(ctx context.Context, a Assessment, events []Event, marks []Mark) (assessmentID int64, err error)
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
	// Prune removes events and closed items older than before, assessments older
	// than before, and tracker tickets resolved before it. It reports what it
	// removed.
	Prune(ctx context.Context, before time.Time) (Pruned, error)
	// UpsertTickets writes tickets read from the tracker, keyed by issue key. The
	// item a ticket was first matched to is held: a later write neither clears it
	// nor moves it to another item.
	UpsertTickets(ctx context.Context, tickets []TrackerTicket) error
	// Tickets returns the tickets created or resolved in [since, until), and every
	// resolved ticket matched to an item, whose close the open summary dates.
	Tickets(ctx context.Context, since, until time.Time) ([]TrackerTicket, error)
	// TicketsIndexed says how many tickets are held, the oldest, and when the
	// tracker was last read. Zero Tickets means it never has been.
	TicketsIndexed(ctx context.Context) (TicketIndexState, error)
	// SaveServed stores the assessment the server is serving and keeps only the
	// newest keep rows, in one transaction.
	SaveServed(ctx context.Context, a ServedAssessment, keep int) error
	// LatestServed returns the newest served assessment generated after after, or
	// nil when there is none. The zero time means any.
	LatestServed(ctx context.Context, after time.Time) (*ServedAssessment, error)
	// WorkerState returns what the assessment worker last reported, and the zero
	// value when it never has.
	WorkerState(ctx context.Context) (WorkerState, error)
	// SaveWorkerState records the worker's report. It leaves RefreshRequested alone,
	// so a request made while the worker writes is never lost.
	SaveWorkerState(ctx context.Context, st WorkerState) error
	// RequestRefresh records that a fresh assessment was asked for at at. A request
	// never moves the recorded time backwards.
	RequestRefresh(ctx context.Context, at time.Time) error
	Close()
}

// WorkerState is how a split deployment's web replicas learn what the worker is
// doing, and how they ask it for an assessment. One row: the worker writes
// everything but RefreshRequested, the web replicas write only that.
type WorkerState struct {
	// Heartbeat is when the worker last reported. A web replica treats a stale one as
	// a worker that is not there, whatever the rest of the row says.
	Heartbeat time.Time
	Version   string
	Running   bool
	// StartedAt is when the in-flight assessment began, set while Running.
	StartedAt *time.Time
	// LastError is set when the worker's most recent assessment failed.
	LastError string
	// RefreshRequested is the newest request for an assessment, and RefreshHandled the
	// newest the worker has acted on. A request is pending while the first is newer.
	RefreshRequested *time.Time
	RefreshHandled   *time.Time
	// HistoryRecorded and HistoryError are the worker's history recorder status, which
	// a web replica cannot observe for itself because it records nothing.
	HistoryRecorded *time.Time
	HistoryError    string
}

// ServedAssessment is the whole assessment a server was serving, kept so a
// restarted process can serve it at once rather than answer 503 until a fresh run
// completes. The payload is opaque here: the server owns its encoding and says
// which one it wrote in SchemaVersion, so a build that cannot read it can say so
// and ignore it rather than misread it.
type ServedAssessment struct {
	ID            int64
	GeneratedAt   time.Time
	Version       string
	SchemaVersion int
	Payload       []byte
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
	Tickets     int64 `json:"tickets"`
}
