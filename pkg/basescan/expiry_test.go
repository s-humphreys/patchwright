package basescan

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Expiry, which is a correctness property rather than a performance one.
//
// An image's own CVEs are re-read every assessment; its base's were not, and a CVE
// absent from the base scan is reported as coming from the APPLICATION. So a cache
// that never expired blamed the team for every CVE published against a base package
// after the process started - for as long as the process lived.

type countingScanner struct {
	scans atomic.Int64
	// cves is what each successive scan of a reference returns, so a re-scan can be
	// seen to pick up something the first one did not know about.
	mu   sync.Mutex
	cves map[string][]string
	fail error
}

func (c *countingScanner) Name() string { return "counting" }

func (c *countingScanner) ScanRef(_ context.Context, ref string) (*Result, error) {
	c.scans.Add(1)
	if c.fail != nil {
		return nil, c.fail
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := &Result{CVEs: map[string][]Package{}}
	for _, id := range c.cves[ref] {
		out.CVEs[id] = nil
	}
	return out, nil
}

// clock is a hand-wound clock, so ageing is exact rather than slept for.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)}
}

func TestAScanIsReusedWithinTheWindow(t *testing.T) {
	scanner := &countingScanner{cves: map[string][]string{"base:1": {"CVE-1"}}}
	clk := newClock()
	r := &Resolver{Scanner: scanner, MaxAge: time.Hour, Now: clk.now}

	for i := 0; i < 4; i++ {
		clk.advance(10 * time.Minute)
		if _, err := r.Scan(context.Background(), "base:1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := scanner.scans.Load(); got != 1 {
		t.Errorf("scanned %d times inside the window, want 1", got)
	}
	if got := r.Rescanned(); got != 0 {
		t.Errorf("Rescanned = %d, want 0", got)
	}
}

// The point of the change: a base is read again once its scan has aged out, and the
// second read is what notices a CVE the first could not have known about.
func TestAnAgedScanIsReadAgainAndPicksUpNewCVEs(t *testing.T) {
	scanner := &countingScanner{cves: map[string][]string{"base:1": {"CVE-1"}}}
	clk := newClock()
	r := &Resolver{Scanner: scanner, MaxAge: 12 * time.Hour, Now: clk.now}

	first, err := r.Scan(context.Background(), "base:1")
	if err != nil {
		t.Fatal(err)
	}
	if first.Has("CVE-2") {
		t.Fatal("the fixture should not carry CVE-2 yet")
	}

	// A CVE is published against a package in that base.
	scanner.mu.Lock()
	scanner.cves["base:1"] = []string{"CVE-1", "CVE-2"}
	scanner.mu.Unlock()

	// Still inside the window: the old answer stands, which is the trade being made.
	clk.advance(11 * time.Hour)
	stale, _ := r.Scan(context.Background(), "base:1")
	if stale.Has("CVE-2") {
		t.Error("nothing should have re-scanned inside the window")
	}

	clk.advance(2 * time.Hour)
	fresh, err := r.Scan(context.Background(), "base:1")
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.Has("CVE-2") {
		t.Error("past the window the base must be read again, or a new base CVE is " +
			"attributed to the application forever")
	}
	if got := scanner.scans.Load(); got != 2 {
		t.Errorf("scanned %d times, want 2", got)
	}
	if got := r.Rescanned(); got != 1 {
		t.Errorf("Rescanned = %d, want 1 so a run can report re-reading separately", got)
	}
}

// An unset bound must not mean "forever". The safe reading of a missing limit is the
// one that cannot quietly grow, because forever is the bug this fixes.
func TestAnUnsetWindowTakesTheDefaultRatherThanForever(t *testing.T) {
	scanner := &countingScanner{cves: map[string][]string{"base:1": {"CVE-1"}}}
	clk := newClock()
	r := &Resolver{Scanner: scanner, Now: clk.now} // no MaxAge

	if _, err := r.Scan(context.Background(), "base:1"); err != nil {
		t.Fatal(err)
	}
	clk.advance(DefaultMaxAge + time.Minute)
	if _, err := r.Scan(context.Background(), "base:1"); err != nil {
		t.Fatal(err)
	}
	if got := scanner.scans.Load(); got != 2 {
		t.Errorf("scanned %d times, want 2: an unset window must still expire", got)
	}
}

// Explicitly disabled, for a one-shot command whose process outlives nothing.
func TestANegativeWindowNeverExpires(t *testing.T) {
	scanner := &countingScanner{cves: map[string][]string{"base:1": {"CVE-1"}}}
	clk := newClock()
	r := &Resolver{Scanner: scanner, MaxAge: -1, Now: clk.now}

	for i := 0; i < 3; i++ {
		if _, err := r.Scan(context.Background(), "base:1"); err != nil {
			t.Fatal(err)
		}
		clk.advance(30 * 24 * time.Hour)
	}
	if got := scanner.scans.Load(); got != 1 {
		t.Errorf("scanned %d times with expiry off, want 1", got)
	}
}

// A failed scan is stamped too, so one unreachable base is not retried for every image
// built on it - the behaviour expiry must not undo.
func TestAFailedScanIsNotRetriedPerImageWithinTheWindow(t *testing.T) {
	scanner := &countingScanner{fail: errors.New("registry refused")}
	clk := newClock()
	r := &Resolver{Scanner: scanner, MaxAge: time.Hour, Now: clk.now}

	for i := 0; i < 50; i++ {
		if _, err := r.Scan(context.Background(), "base:1"); err == nil {
			t.Fatal("want the failure")
		}
	}
	if got := scanner.scans.Load(); got != 1 {
		t.Errorf("a broken base was scanned %d times, want 1 within the window", got)
	}
	// And it is retried once the window passes: a registry that was down may be up.
	clk.advance(2 * time.Hour)
	_, _ = r.Scan(context.Background(), "base:1")
	if got := scanner.scans.Load(); got != 2 {
		t.Errorf("scanned %d times, want a retry after the window", got)
	}
}

// Several images built on the same base are resolved concurrently. Expiry must not
// break the deduplication that is the whole economy of this type: an in-flight scan is
// not an expired one.
func TestConcurrentCallersStillShareOneScan(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var scans atomic.Int64
	blocking := &blockingScanner{scans: &scans, started: started, release: release}
	clk := newClock()
	r := &Resolver{Scanner: blocking, MaxAge: time.Nanosecond, Now: clk.now}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Scan(context.Background(), "base:1")
		}()
	}
	<-started
	// Time passes while the scan is in flight, which under a naive age check would
	// make every waiting caller start its own.
	clk.advance(time.Hour)
	close(release)
	wg.Wait()

	if got := scans.Load(); got != 1 {
		t.Errorf("%d concurrent callers started %d scans, want 1", 8, got)
	}
}

type blockingScanner struct {
	scans    *atomic.Int64
	started  chan struct{}
	release  chan struct{}
	onceOnly sync.Once
}

func (b *blockingScanner) Name() string { return "blocking" }

func (b *blockingScanner) ScanRef(_ context.Context, _ string) (*Result, error) {
	b.scans.Add(1)
	b.onceOnly.Do(func() { close(b.started) })
	<-b.release
	return &Result{CVEs: map[string][]Package{}}, nil
}
