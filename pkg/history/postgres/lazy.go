package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
)

// Lazy is a history.Store that connects on first use and retries on later uses
// after a failure. It exists so a database that is unreachable when the pod starts
// costs the history, not the assessment: the queue and the page come up, the
// record says it is unavailable, and the next refresh tries again.
type Lazy struct {
	opts Options

	mu      sync.Mutex
	store   *Store
	lastTry time.Time
	lastErr error
}

// retryAfter is how long a failed connection is held before the next attempt, so a
// page that polls the history endpoint does not turn into a connection storm.
const retryAfter = 30 * time.Second

// NewLazy returns a store that has not yet connected.
func NewLazy(opts Options) *Lazy { return &Lazy{opts: opts} }

func (l *Lazy) get(ctx context.Context) (*Store, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.store != nil {
		return l.store, nil
	}
	if l.lastErr != nil && time.Since(l.lastTry) < retryAfter {
		return nil, l.lastErr
	}
	l.lastTry = time.Now()
	s, err := Open(ctx, l.opts)
	if err != nil {
		l.lastErr = fmt.Errorf("history store unavailable: %w", err)
		slog.WarnContext(ctx, "history: store unavailable; will retry", "error", err)
		return nil, l.lastErr
	}
	l.store, l.lastErr = s, nil
	slog.InfoContext(ctx, "history: store connected")
	return s, nil
}

func (l *Lazy) Open(ctx context.Context) ([]history.State, error) {
	s, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return s.Open(ctx)
}

func (l *Lazy) Record(ctx context.Context, a history.Assessment, events []history.Event) (int64, error) {
	s, err := l.get(ctx)
	if err != nil {
		return 0, err
	}
	return s.Record(ctx, a, events)
}

func (l *Lazy) Append(ctx context.Context, assessmentID int64, events []history.Event) error {
	s, err := l.get(ctx)
	if err != nil {
		return err
	}
	return s.Append(ctx, assessmentID, events)
}

func (l *Lazy) Events(ctx context.Context, since, until time.Time) ([]history.Event, error) {
	s, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return s.Events(ctx, since, until)
}

func (l *Lazy) Assessments(ctx context.Context, since, until time.Time) ([]history.Assessment, error) {
	s, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return s.Assessments(ctx, since, until)
}

func (l *Lazy) AssessmentItems(ctx context.Context, assessmentID int64) ([]history.Snapshot, error) {
	s, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return s.AssessmentItems(ctx, assessmentID)
}

func (l *Lazy) Item(ctx context.Context, key string) (*history.ItemHistory, error) {
	s, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return s.Item(ctx, key)
}

func (l *Lazy) First(ctx context.Context) (time.Time, bool, error) {
	s, err := l.get(ctx)
	if err != nil {
		return time.Time{}, false, err
	}
	return s.First(ctx)
}

func (l *Lazy) Prune(ctx context.Context, before time.Time) (history.Pruned, error) {
	s, err := l.get(ctx)
	if err != nil {
		return history.Pruned{}, err
	}
	return s.Prune(ctx, before)
}

func (l *Lazy) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.store != nil {
		l.store.Close()
		l.store = nil
	}
}

var _ history.Store = (*Lazy)(nil)
