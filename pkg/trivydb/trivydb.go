// Package trivydb holds the policy for fetching Trivy's vulnerability database:
// how often to try, how long to wait, and where to fall back to.
//
// Both Trivy callers need it - the vuln source that scans the estate and the base
// scanner behind the differential - and an outage of the default mirror took the
// second down for the life of a process while the first carried on, because only
// one of them retried. One policy, so they cannot drift apart again. Running the
// binary stays with each caller, since they word its failures differently.
package trivydb

import (
	"context"
	"log/slog"
	"time"
)

// Attempts is how many times Download tries to fetch the database.
//
// Downloading it is the one step in a run that depends on a public CDN, and it
// is observably flaky: mirror.gcr.io serves a 404 for a layer it has just
// advertised in its own manifest, and the same command succeeds seconds later.
// Trivy does not retry that itself.
const Attempts = 3

// Backoff is the wait before each retry. Short: a mirror 404 clears
// immediately, and anything that does not is not worth waiting minutes for.
// A variable so tests need not wait it out.
var Backoff = []time.Duration{2 * time.Second, 5 * time.Second}

// FallbackRepository is tried when the default mirror list fails and the caller
// has not named a repository of its own. This is the upstream source rather than
// a cache of it, so it is not subject to the mirror's staleness.
const FallbackRepository = "ghcr.io/aquasecurity/trivy-db:2"

// Download calls fetch until it succeeds or Attempts run out, and returns the
// last error.
//
// configured is the repository the caller was told to use, empty for Trivy's own
// default. fetch receives the repository for each attempt, empty meaning Trivy's
// default.
func Download(ctx context.Context, configured string, fetch func(ctx context.Context, repo string) error) error {
	var lastErr error
	for attempt := 1; attempt <= Attempts; attempt++ {
		// Stick with the configured repository when there is one: the caller
		// naming a repository usually means the default is unreachable (an
		// air-gapped mirror), so silently reaching past it to the internet
		// would be wrong.
		repo := configured
		if repo == "" && attempt > 1 {
			repo = FallbackRepository
		}
		if err := fetch(ctx, repo); err == nil {
			return nil
		} else if lastErr = err; ctx.Err() != nil {
			// A cancelled context will not heal, so stop rather than burning
			// the remaining attempts on it.
			return lastErr
		}
		if attempt < Attempts {
			slog.WarnContext(ctx, "trivy vulnerability DB download failed, retrying",
				"attempt", attempt, "of", Attempts, "error", lastErr)
			select {
			case <-time.After(Backoff[min(attempt, len(Backoff))-1]):
			case <-ctx.Done():
				return lastErr
			}
		}
	}
	return lastErr
}
