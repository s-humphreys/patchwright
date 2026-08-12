package trivy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeTrivy writes a stub trivy on PATH that appends its arguments to a log and
// exits with the codes given, one per invocation (the last repeats). Returns the
// path of the log so a test can assert what was actually run.
func fakeTrivy(t *testing.T, exitCodes ...int) (binary, logPath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "trivy")
	logPath = filepath.Join(dir, "calls.log")
	counter := filepath.Join(dir, "count")

	script := `#!/bin/sh
echo "$@" >> ` + logPath + `
n=$(cat ` + counter + ` 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > ` + counter + `
codes="` + joinCodes(exitCodes) + `"
code=$(echo "$codes" | cut -d, -f"$n")
[ -n "$code" ] || code=$(echo "$codes" | rev | cut -d, -f1 | rev)
if [ "$code" != "0" ]; then
  echo "FATAL	Fatal error	run error: DB error: 404 Not Found" >&2
fi
exit "$code"
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return binary, logPath
}

func joinCodes(codes []int) string {
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = string(rune('0' + c))
	}
	return strings.Join(parts, ",")
}

func calls(t *testing.T, logPath string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// A flaky mirror must not cost the whole assessment: the DB download is retried,
// and the second attempt reaches past the mirror list to the upstream repository.
func TestPrepareRetriesAndFallsBackToUpstreamRepository(t *testing.T) {
	dbDownloadBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	binary, logPath := fakeTrivy(t, 1, 0)
	s := &source{binary: binary, timeout: "5m"}

	if err := s.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare failed despite the retry succeeding: %v", err)
	}
	if !s.prepared {
		t.Error("prepared is false, so scans will redundantly update the DB again")
	}
	got := calls(t, logPath)
	if len(got) != 2 {
		t.Fatalf("got %d invocations, want 2: %v", len(got), got)
	}
	if strings.Contains(got[0], "--db-repository") {
		t.Errorf("first attempt overrode the repository, want Trivy's default: %q", got[0])
	}
	if !strings.Contains(got[1], fallbackDBRepository) {
		t.Errorf("retry did not fall back to %s: %q", fallbackDBRepository, got[1])
	}
}

// A caller naming a repository usually means the default is unreachable, so the
// fallback must not quietly reach out to the internet instead.
func TestPrepareKeepsAConfiguredRepositoryOnRetry(t *testing.T) {
	dbDownloadBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	binary, logPath := fakeTrivy(t, 1, 0)
	s := &source{binary: binary, dbRepo: "registry.internal/trivy-db:2"}

	if err := s.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	for _, c := range calls(t, logPath) {
		if !strings.Contains(c, "registry.internal/trivy-db:2") {
			t.Errorf("attempt did not use the configured repository: %q", c)
		}
		if strings.Contains(c, fallbackDBRepository) {
			t.Errorf("attempt reached past the configured repository to the internet: %q", c)
		}
	}
}

// Persistent failure still fails, and says why: a retry that hides a real
// outage would leave the run reporting images as unscanned with no reason.
func TestPrepareGivesUpAndReportsTheReason(t *testing.T) {
	dbDownloadBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	binary, logPath := fakeTrivy(t, 1)
	s := &source{binary: binary}

	err := s.Prepare(context.Background())
	if err == nil {
		t.Fatal("Prepare succeeded despite every attempt failing")
	}
	if !strings.Contains(err.Error(), "404 Not Found") {
		t.Errorf("error lost the underlying reason: %v", err)
	}
	if strings.Contains(err.Error(), "FATAL") {
		t.Errorf("error kept Trivy's banner instead of the reason: %v", err)
	}
	if s.prepared {
		t.Error("prepared is true after a failed download")
	}
	if n := len(calls(t, logPath)); n != dbDownloadAttempts {
		t.Errorf("made %d attempts, want %d", n, dbDownloadAttempts)
	}
}

// A cancelled context will not heal, so the remaining attempts must not be
// burned on it (nor the backoff waited out).
func TestPrepareStopsOnACancelledContext(t *testing.T) {
	binary, logPath := fakeTrivy(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := (&source{binary: binary}).Prepare(ctx); err == nil {
		t.Fatal("Prepare succeeded with a cancelled context")
	}
	if n := len(calls(t, logPath)); n > 1 {
		t.Errorf("made %d attempts after cancellation, want at most 1", n)
	}
}
