package basescan

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

type fakeScanner struct {
	mu    sync.Mutex
	calls map[string]int
	fail  map[string]bool
	// gate blocks every scan until closed, so concurrent callers are genuinely
	// in flight together rather than serialised by luck.
	gate chan struct{}
	live atomic.Int32
	peak atomic.Int32
}

func newFake() *fakeScanner {
	return &fakeScanner{calls: map[string]int{}, fail: map[string]bool{}}
}

func (f *fakeScanner) Name() string { return "fake" }

func (f *fakeScanner) ScanRef(ctx context.Context, ref string) (*Result, error) {
	n := f.live.Add(1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	defer f.live.Add(-1)
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	f.calls[ref]++
	shouldFail := f.fail[ref]
	f.mu.Unlock()
	if shouldFail {
		return nil, errors.New("boom")
	}
	return res(ref, "debian", [3]string{"debian", "openssl", "CVE-1"}), nil
}

func (f *fakeScanner) count(ref string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[ref]
}

func TestResolverScansEachReferenceOnce(t *testing.T) {
	// The economy of the whole design. 684 images resolve to 30 base
	// repositories; scanning per image is the estate-wide scan this avoids.
	f := newFake()
	f.gate = make(chan struct{})
	r := &Resolver{Scanner: f, Concurrency: 8}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			//nolint:errcheck // the assertion is on the call count
			_, _ = r.Scan(context.Background(), "base:1")
		}()
	}
	close(f.gate)
	wg.Wait()

	if got := f.count("base:1"); got != 1 {
		t.Errorf("50 concurrent images on one base should cause 1 scan, got %d", got)
	}
	if r.Scanned() != 1 {
		t.Errorf("Scanned() = %d, want 1", r.Scanned())
	}
}

func TestResolverCachesFailures(t *testing.T) {
	// One unreachable base must not become one failed scan per image built on it.
	f := newFake()
	f.fail["broken:1"] = true
	r := &Resolver{Scanner: f}

	for i := 0; i < 5; i++ {
		if _, err := r.Scan(context.Background(), "broken:1"); err == nil {
			t.Fatal("expected the scan to fail")
		}
	}
	if got := f.count("broken:1"); got != 1 {
		t.Errorf("a failing base should be attempted once, got %d attempts", got)
	}
}

func TestResolverBoundsConcurrency(t *testing.T) {
	// Each scan pulls an image. Unbounded, a run pulls dozens at once and the
	// registry, not the tool, decides what happens next.
	f := newFake()
	f.gate = make(chan struct{})
	r := &Resolver{Scanner: f, Concurrency: 3}

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			//nolint:errcheck // the assertion is on peak concurrency
			_, _ = r.Scan(context.Background(), string(rune('a'+i)))
		}(i)
	}
	// Let the goroutines pile up against the gate before releasing them.
	for f.live.Load() < 3 {
	}
	close(f.gate)
	wg.Wait()

	if p := f.peak.Load(); p > 3 {
		t.Errorf("peak concurrent scans = %d, want at most 3", p)
	}
}

func TestResolverRejectsEmptyReference(t *testing.T) {
	r := &Resolver{Scanner: newFake()}
	if _, err := r.Scan(context.Background(), ""); err == nil {
		t.Error("an empty reference is a bug in the caller, not a scan to attempt")
	}
}
