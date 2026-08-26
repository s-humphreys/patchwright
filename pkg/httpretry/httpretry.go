// Package httpretry retries the HTTP failures that mean "not now" rather than "no".
//
// Every remote this tool reads is somebody else's service having an ordinary day. On one
// run a single 502 from the EPSS feed — one request of a hundred and four — discarded a
// completed scan of 791 images, and five Rapid7 pages returned 502 and cost those images
// their CVE detail. Neither was a real answer about the estate; both were a shrug from a
// load balancer.
//
// Only transient failures are retried: a 429, a 5xx, or a connection that did not
// complete. A 401, 403 or 404 is a real answer and repeating it wastes time and hides the
// cause — an expired credential should be reported as one, immediately.
package httpretry

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

// Attempts is the default number of tries, including the first.
const Attempts = 4

// Do sends a request, retrying transient failures with exponential backoff and jitter.
//
// When the retries are exhausted the LAST RESPONSE is returned as it is, not an error.
// That matters: callers explain a rejection from the response body — this API answers
// "400 Bad Request" with {"messages":{...}} naming the field — and a wrapper that
// collapsed the response into "after 4 attempts: status 500" would throw away the only
// actionable part. An error is returned only when there is no response at all.
//
// The request body is read once and replayed, so a caller does not have to rebuild the
// request per attempt. Bodies here are small (a JSON "{}" or nothing at all), which is
// what makes that safe.
//
// Backoff is jittered because the failures arrive in bursts: four workers hitting one
// API all get the 502, and retrying in lockstep reproduces the burst that caused it.
func Do(ctx context.Context, client *http.Client, req *http.Request, attempts int) (*http.Response, error) {
	if attempts < 1 {
		attempts = Attempts
	}
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		body = b
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		r := req.Clone(ctx)
		if body != nil {
			r.Body = io.NopCloser(bytesReader(body))
			r.ContentLength = int64(len(body))
		}
		resp, err := client.Do(r)
		switch {
		case err == nil && !transientStatus(resp.StatusCode):
			return resp, nil
		case err == nil && attempt == attempts:
			// Out of attempts: hand back the response so the caller can explain the
			// failure in the API's own words.
			return resp, nil
		case err == nil:
			// Not the answer, and an unread body leaks the connection.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		default:
			lastErr = err
			if attempt == attempts {
				return nil, fmt.Errorf("after %d attempts: %w", attempts, lastErr)
			}
		}
		if err := sleep(ctx, backoff(attempt)); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("after %d attempts: %w", attempts, lastErr)
}

// transientStatus reports whether a status means "try again" rather than "no".
func transientStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// backoff grows the wait per attempt, with jitter.
func backoff(attempt int) time.Duration {
	base := time.Duration(1<<uint(attempt-1)) * 500 * time.Millisecond
	if base > 8*time.Second {
		base = 8 * time.Second
	}
	// Up to half the base again, so simultaneous workers spread out instead of
	// retrying together and recreating the burst.
	return base + time.Duration(rand.Int64N(int64(base/2)))
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// bytesReader avoids importing bytes for one call.
func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct {
	b []byte
	i int
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.i >= len(s.b) {
		return 0, io.EOF
	}
	n := copy(p, s.b[s.i:])
	s.i += n
	return n, nil
}
