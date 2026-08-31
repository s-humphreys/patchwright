package enrich

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMemoFetchesOncePerRun(t *testing.T) {
	ctx := WithRunCache(context.Background())
	var calls atomic.Int64
	fetch := func() (int, error) {
		calls.Add(1)
		return 42, nil
	}
	for i := 0; i < 5; i++ {
		got, err := Memo(ctx, "k", fetch)
		if err != nil || got != 42 {
			t.Fatalf("Memo = %v, %v", got, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("fetched %d times, want 1", calls.Load())
	}
}

// The point of scoping it to the run: nothing carries over.
func TestEachRunStartsEmpty(t *testing.T) {
	var calls atomic.Int64
	fetch := func() (int, error) {
		calls.Add(1)
		return 1, nil
	}
	for i := 0; i < 3; i++ {
		if _, err := Memo(WithRunCache(context.Background()), "k", fetch); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 3 {
		t.Errorf("fetched %d times, want one per run", calls.Load())
	}
}

// Without a cache on the context - a one-off command, a test - the memo must be
// transparent rather than a silent no-op that returns nothing.
func TestWithoutACacheItJustFetches(t *testing.T) {
	var calls atomic.Int64
	got, err := Memo(context.Background(), "k", func() (string, error) {
		calls.Add(1)
		return "v", nil
	})
	if err != nil || got != "v" || calls.Load() != 1 {
		t.Errorf("Memo = %q, %v after %d calls", got, err, calls.Load())
	}
}

func TestKeysAreIndependent(t *testing.T) {
	ctx := WithRunCache(context.Background())
	a, _ := Memo(ctx, "a", func() (string, error) { return "A", nil })
	b, _ := Memo(ctx, "b", func() (string, error) { return "B", nil })
	if a != "A" || b != "B" {
		t.Errorf("got %q and %q", a, b)
	}
}

// A failure is remembered for the run: both callers want the same answer, and the
// second must not spend another two minutes discovering the same refusal.
func TestAFailureIsRememberedForTheRun(t *testing.T) {
	ctx := WithRunCache(context.Background())
	var calls atomic.Int64
	want := errors.New("platform refused")
	fetch := func() (int, error) {
		calls.Add(1)
		return 0, want
	}
	for i := 0; i < 3; i++ {
		if _, err := Memo(ctx, "k", fetch); !errors.Is(err, want) {
			t.Fatalf("err = %v, want the original", err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("retried %d times; the failure should be reported once", calls.Load())
	}
}

// Concurrent callers wait for the first fetch rather than starting duplicates of it -
// the whole cost this avoids is a duplicate fetch.
func TestConcurrentCallersShareOneFetch(t *testing.T) {
	ctx := WithRunCache(context.Background())
	var calls atomic.Int64
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = Memo(ctx, "k", func() (int, error) {
				calls.Add(1)
				<-release
				return 7, nil
			})
		}()
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Errorf("fetched %d times concurrently, want 1", calls.Load())
	}
}
