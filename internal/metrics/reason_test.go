package metrics

import "testing"

func TestNormalizeReasonKeepsTheFirstClauseWhole(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			// A dotted label key is not a sentence boundary. This produced
			// "image records no base image; add one of org" as a metric label.
			in:   "image records no base image; add one of org.opencontainers.image.base.name or image.base.ref.name at build time",
			want: "image records no base image",
		},
		{
			in:   "read image config for x: reading image x: POST https://y UNAUTHORIZED: authentication required",
			want: "read image config for x",
		},
		{in: "", want: "unknown"},
		{in: "no comparable version", want: "no comparable version"},
	}
	for _, c := range cases {
		if got := normalizeReason(c.in); got != c.want {
			t.Errorf("normalizeReason(%.40q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeReasonTrimsLongReasonsAtAWordBoundary(t *testing.T) {
	long := "cannot reach the registry because the network path to the mirror is blocked by a policy somewhere upstream and nobody knows where"
	got := normalizeReason(long)
	if len(got) > 80 {
		t.Fatalf("label too long (%d): %q", len(got), got)
	}
	if got[len(got)-1] == ' ' || !isWordEnd(long, got) {
		t.Fatalf("truncated mid-word: %q", got)
	}
}

// isWordEnd reports whether got ends where a word ends in the original.
func isWordEnd(original, got string) bool {
	if len(got) >= len(original) {
		return true
	}
	return original[len(got)] == ' '
}
