package enrich

import (
	"context"
	"sync"
)

// A memo scoped to one assessment, for work two enrichment stages both need.
//
// It exists because of a measured duplication. On a real estate the age source and the
// exploit source each swept the scan platform's entire vulnerability catalogue - the
// same endpoint, the same pages, minutes apart - and each sweep took about two minutes
// of a ten-minute run. They decode different fields from identical responses.
//
// Scoped to the RUN rather than to the process, and that is the whole point. A cache
// with a lifetime of its own needs a time-to-live, and any value chosen is a guess
// about how stale is acceptable: too long and an assessment reports last hour's
// exploit intelligence as this hour's, too short and it stops coalescing anything.
// Tied to the run there is nothing to guess - the second stage of a run reuses what
// the first fetched, and the next run starts empty because it starts with a new
// context.

type runCacheKey struct{}

type runCache struct {
	mu      sync.Mutex
	entries map[string]*runCacheEntry
}

// runCacheEntry is one memoised value, with its own lock so a second caller waits for
// the first fetch rather than starting a duplicate of it.
type runCacheEntry struct {
	once sync.Once
	val  any
	err  error
}

// WithRunCache attaches a memo to ctx for the duration of one assessment. The pipeline
// does this once per run; nothing else needs to.
func WithRunCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, runCacheKey{}, &runCache{entries: map[string]*runCacheEntry{}})
}

// Memo returns the value for key, fetching it once per run.
//
// With no cache on the context it simply calls fetch, so a source used outside a
// pipeline - a one-off command, a test - behaves exactly as it did before.
//
// A failed fetch is remembered for the rest of the run rather than retried by the next
// caller. Both callers want the same answer, and a platform that has just refused one
// two-minute sweep is not more likely to satisfy a second: the failure is reported
// once, both stages degrade the way they already do, and the run does not spend four
// minutes discovering it twice.
func Memo[T any](ctx context.Context, key string, fetch func() (T, error)) (T, error) {
	cache, ok := ctx.Value(runCacheKey{}).(*runCache)
	if !ok {
		return fetch()
	}

	cache.mu.Lock()
	entry := cache.entries[key]
	if entry == nil {
		entry = &runCacheEntry{}
		cache.entries[key] = entry
	}
	cache.mu.Unlock()

	entry.once.Do(func() { entry.val, entry.err = fetch() })
	if entry.err != nil {
		var zero T
		return zero, entry.err
	}
	val, ok := entry.val.(T)
	if !ok {
		// Two callers asked for the same key with different types, which is a
		// programming error rather than a runtime condition. Fetching is the safe
		// response: the caller gets correct data and pays for it.
		return fetch()
	}
	return val, nil
}
