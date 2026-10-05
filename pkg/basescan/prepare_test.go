package basescan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/s-humphreys/patchwright/pkg/trivydb"
)

// fakeTrivy writes a stub trivy that logs its arguments. A database download exits
// with dbCodes in turn (the last repeats); a scan writes scanStderr and fails when
// it is set, and prints an empty report otherwise.
func fakeTrivy(t *testing.T, scanStderr string, dbCodes ...int) (binary, logPath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "trivy")
	logPath = filepath.Join(dir, "calls.log")
	counter := filepath.Join(dir, "count")
	codes := make([]string, len(dbCodes))
	for i, c := range dbCodes {
		codes[i] = fmt.Sprint(c)
	}
	script := `#!/bin/sh
echo "$@" >> ` + logPath + `
case "$*" in
*--download-db-only*)
  n=$(cat ` + counter + ` 2>/dev/null || echo 0)
  n=$((n + 1))
  echo "$n" > ` + counter + `
  codes="` + strings.Join(codes, ",") + `"
  code=$(echo "$codes" | cut -d, -f"$n")
  [ -n "$code" ] || code=$(echo "$codes" | rev | cut -d, -f1 | rev)
  if [ "$code" != "0" ]; then
    echo "FATAL	Fatal error	run error: DB error: 404 Not Found" >&2
  fi
  exit "$code"
  ;;
esac
if [ -n "` + scanStderr + `" ]; then
  echo "` + scanStderr + `" >&2
  exit 1
fi
echo '{"Results": []}'
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return binary, logPath
}

func dbCalls(t *testing.T, logPath string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.Contains(line, "--download-db-only") {
			out = append(out, line)
		}
	}
	return out
}

func anonymous(string) (*authn.AuthConfig, bool, error) { return nil, false, nil }

func fastBackoff(t *testing.T) {
	t.Helper()
	was := trivydb.Backoff
	trivydb.Backoff = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { trivydb.Backoff = was })
}

// The incident: one bad mirror response on the first run after a restart failed
// every base scan until the process was restarted. A later call must try again.
func TestPrepareFailureIsNotStickyAndRecovers(t *testing.T) {
	fastBackoff(t)
	binary, logPath := fakeTrivy(t, "", 1, 1, 1, 0)
	s := &TrivyScanner{Binary: binary}

	err := s.Prepare(context.Background())
	if !errors.Is(err, ErrDBUnavailable) {
		t.Fatalf("Prepare = %v, want ErrDBUnavailable", err)
	}
	if !strings.Contains(err.Error(), "404 Not Found") {
		t.Errorf("error lost the underlying reason: %v", err)
	}
	if n := len(dbCalls(t, logPath)); n != trivydb.Attempts {
		t.Fatalf("first Prepare made %d attempts, want %d", n, trivydb.Attempts)
	}

	if err := s.Prepare(context.Background()); err != nil {
		t.Fatalf("second Prepare did not recover: %v", err)
	}
	if err := s.Prepare(context.Background()); err != nil {
		t.Fatalf("a prepared scanner failed to stay prepared: %v", err)
	}
	if n := len(dbCalls(t, logPath)); n != trivydb.Attempts+1 {
		t.Errorf("made %d downloads, want %d: once prepared, it should not download again", n, trivydb.Attempts+1)
	}
}

func TestPrepareFallsBackOnlyWhenNoRepositoryIsConfigured(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured string
		want       []string // the repository each attempt names, "" for Trivy's default
	}{
		{"default mirror, then upstream", "", []string{"", trivydb.FallbackRepository}},
		{"configured repository is kept", "registry.internal/trivy-db:2",
			[]string{"registry.internal/trivy-db:2", "registry.internal/trivy-db:2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fastBackoff(t)
			binary, logPath := fakeTrivy(t, "", 1, 0)
			s := &TrivyScanner{Binary: binary, DBRepository: tc.configured}
			if err := s.Prepare(context.Background()); err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			got := dbCalls(t, logPath)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d attempts, want %d: %v", len(got), len(tc.want), got)
			}
			for i, repo := range tc.want {
				if repo == "" && strings.Contains(got[i], "--db-repository") {
					t.Errorf("attempt %d overrode the repository: %q", i+1, got[i])
				}
				if repo != "" && !strings.Contains(got[i], "--db-repository "+repo) {
					t.Errorf("attempt %d = %q, want --db-repository %s", i+1, got[i], repo)
				}
			}
		})
	}
}

func TestScanRefTellsADeletedReferenceFromOtherFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		stderr   string
		notFound bool
	}{
		{"deleted digest", "GET https://example.io/v2/base/manifests/sha256:aaa: MANIFEST_UNKNOWN: manifest unknown", true},
		{"deleted repository", "GET https://example.io/v2/gone/manifests/1: NAME_UNKNOWN: repository name not known", true},
		{"unauthorised", "GET https://example.io/v2/base/manifests/1: UNAUTHORIZED: authentication required", false},
		{"timeout", "context deadline exceeded", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binary, _ := fakeTrivy(t, tc.stderr, 0)
			s := &TrivyScanner{Binary: binary, Credentials: anonymous}
			_, err := s.ScanRef(context.Background(), "example.io/base:1")
			if err == nil {
				t.Fatal("scan succeeded despite the scanner failing")
			}
			if got := errors.Is(err, ErrNotFound); got != tc.notFound {
				t.Errorf("errors.Is(err, ErrNotFound) = %v, want %v: %v", got, tc.notFound, err)
			}
			if errors.Is(err, ErrDBUnavailable) {
				t.Errorf("a scan failure is not a database failure: %v", err)
			}
		})
	}
}

// failOnceScanner fails each reference's first scan with err, then succeeds.
type failOnceScanner struct {
	err   error
	calls map[string]int
}

func (f *failOnceScanner) Name() string { return "fail-once" }

func (f *failOnceScanner) ScanRef(_ context.Context, ref string) (*Result, error) {
	f.calls[ref]++
	if f.calls[ref] == 1 {
		return nil, f.err
	}
	return res(ref, "debian", [3]string{"debian", "openssl", "CVE-1"}), nil
}

// A scanner that could not run says nothing about the base, so it is not cached
// against it; a base that failed to scan is, as before.
func TestResolverCachesOnlyFailuresThatAreAboutTheBase(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		wantCalls   int
		wantScanned int
		wantFailed  int
	}{
		{"database unavailable", fmt.Errorf("%w: 404", ErrDBUnavailable), 2, 1, 0},
		{"base unreadable", errors.New("unauthorized"), 1, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &failOnceScanner{err: tc.err, calls: map[string]int{}}
			r := &Resolver{Scanner: f}
			for i := 0; i < 2; i++ {
				//nolint:errcheck // the assertions are on calls and counts
				_, _ = r.Scan(context.Background(), "base:1")
			}
			if got := f.calls["base:1"]; got != tc.wantCalls {
				t.Errorf("scanned %d times, want %d", got, tc.wantCalls)
			}
			if r.Scanned() != tc.wantScanned || r.Failed() != tc.wantFailed {
				t.Errorf("Scanned() = %d, Failed() = %d, want %d and %d",
					r.Scanned(), r.Failed(), tc.wantScanned, tc.wantFailed)
			}
		})
	}
}

// A run that gave up waiting for a scan slot says nothing about the base either,
// and must not leave an entry that reads as in flight for ever.
func TestResolverDoesNotKeepACancelledWait(t *testing.T) {
	f := newFake()
	f.gate = make(chan struct{})
	r := &Resolver{Scanner: f, Concurrency: 1}

	done := make(chan struct{})
	go func() {
		//nolint:errcheck // occupies the only slot
		_, _ = r.Scan(context.Background(), "busy:1")
		close(done)
	}()
	for f.live.Load() < 1 {
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Scan(ctx, "base:1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan = %v, want context.Canceled", err)
	}
	close(f.gate)
	<-done

	if _, err := r.Scan(context.Background(), "base:1"); err != nil {
		t.Fatalf("a later run inherited the cancelled wait: %v", err)
	}
	if got := f.count("base:1"); got != 1 {
		t.Errorf("scanned %d times, want 1", got)
	}
}
