package httpretry_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/httpretry"
)

func request(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestATransientFailureIsRetried(t *testing.T) {
	// The failure this exists for: one 502 out of a hundred requests used to discard a
	// completed scan of every image in the estate.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	resp, err := httpretry.Do(context.Background(), srv.Client(), request(t, srv.URL), 4)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d after retries", resp.StatusCode)
	}
	if calls != 3 {
		t.Errorf("made %d attempts, expected to retry twice then succeed", calls)
	}
}

func TestARealAnswerIsNotRetried(t *testing.T) {
	// A 401, 403 or 404 is an answer. Repeating it wastes time and buries the cause: an
	// expired credential should be reported as one immediately, not four attempts later.
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusBadRequest} {
		var calls int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(code)
		}))
		resp, err := httpretry.Do(context.Background(), srv.Client(), request(t, srv.URL), 4)
		if err != nil {
			t.Fatalf("%d: %v", code, err)
		}
		_ = resp.Body.Close()
		if calls != 1 {
			t.Errorf("status %d was attempted %d times; it is an answer, not a delay", code, calls)
		}
		srv.Close()
	}
}

func TestAnExhaustedRetryReturnsTheResponseNotAnError(t *testing.T) {
	// Callers explain a rejection using the API's own words from the body. Collapsing
	// the response into "after 4 attempts: status 500" throws away the only actionable
	// part of it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"messages":{"error":"upstream exploded"}}`))
	}))
	defer srv.Close()

	resp, err := httpretry.Do(context.Background(), srv.Client(), request(t, srv.URL), 2)
	if err != nil {
		t.Fatalf("want the response, got an error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !contains(string(body), "upstream exploded") {
		t.Errorf("the API's own message was lost: %q", body)
	}
}

func TestACancelledContextStopsRetrying(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := httpretry.Do(ctx, srv.Client(), request(t, srv.URL), 4); err == nil {
		t.Fatal("a cancelled context must not keep retrying")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
