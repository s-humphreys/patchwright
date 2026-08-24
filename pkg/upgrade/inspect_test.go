package upgrade

import (
	"context"
	"errors"
	"testing"
	"time"
)

type countingInspector struct {
	calls  map[string]int
	labels map[string]string
	err    error
}

func (c *countingInspector) Labels(_ context.Context, ref string) (map[string]string, error) {
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[ref]++
	return c.labels, c.err
}
func (c *countingInspector) Digest(context.Context, string) (string, error) { return "", nil }

func TestCachingInspectorReadsEachReferenceOnce(t *testing.T) {
	inner := &countingInspector{labels: map[string]string{"a": "b"}}
	c := NewCachingInspector(inner)
	for i := 0; i < 5; i++ {
		if _, err := c.Labels(context.Background(), "reg/app:1"); err != nil {
			t.Fatal(err)
		}
	}
	if inner.calls["reg/app:1"] != 1 {
		t.Fatalf("read the registry %d times, want 1", inner.calls["reg/app:1"])
	}
}

func TestCachingInspectorCachesFailures(t *testing.T) {
	// An unreadable image is unreadable for both stages; retrying per stage doubles
	// the wait for an answer that cannot change within a run.
	inner := &countingInspector{err: errors.New("unauthorized")}
	c := NewCachingInspector(inner)
	for i := 0; i < 3; i++ {
		if _, err := c.Labels(context.Background(), "reg/app:1"); err == nil {
			t.Fatal("expected the error to be returned")
		}
	}
	if inner.calls["reg/app:1"] != 1 {
		t.Fatalf("read the registry %d times, want 1", inner.calls["reg/app:1"])
	}
}

func TestCachingInspectorExpires(t *testing.T) {
	// A tag can be republished, so an entry must not outlive the run that made it.
	inner := &countingInspector{labels: map[string]string{"a": "b"}}
	c := NewCachingInspector(inner)
	c.TTL = time.Nanosecond
	if _, err := c.Labels(context.Background(), "reg/app:1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if _, err := c.Labels(context.Background(), "reg/app:1"); err != nil {
		t.Fatal(err)
	}
	if inner.calls["reg/app:1"] != 2 {
		t.Fatalf("expired entry was reused: %d reads", inner.calls["reg/app:1"])
	}
}
