package basescan

import (
	"testing"
)

// res builds a scan result from a list of "ecosystem:package:CVE" triples.
func res(ref, osFamily string, triples ...[3]string) *Result {
	r := &Result{Ref: ref, OSFamily: osFamily, Ecosystems: map[string]bool{}, CVEs: map[string][]Package{}}
	for _, t := range triples {
		r.Ecosystems[t[0]] = true
		r.CVEs[t[2]] = append(r.CVEs[t[2]], Package{Ecosystem: t[0], Name: t[1]})
	}
	return r
}

func TestDiffSeparatesBaseFromApplication(t *testing.T) {
	// The question the whole design exists to answer: of an image's CVEs, which
	// arrived with the base and which did the Dockerfile install.
	built := res("base:1", "debian",
		[3]string{"debian", "openssl", "CVE-1"},
		[3]string{"debian", "zlib", "CVE-2"})
	cand := res("base:2", "debian",
		[3]string{"debian", "zlib", "CVE-2"})

	v, s := Diff([]string{"CVE-1", "CVE-2", "CVE-3"}, built, cand)

	if v["CVE-1"].Origin != OriginBase {
		t.Errorf("CVE-1 came from the base image, got %q", v["CVE-1"].Origin)
	}
	if v["CVE-3"].Origin != OriginApp {
		t.Errorf("CVE-3 is not in the base, so the app introduced it, got %q", v["CVE-3"].Origin)
	}
	// CVE-1 is gone in the candidate; CVE-2 survives it.
	if !v["CVE-1"].FixedByUpgrade {
		t.Error("CVE-1 is absent from the candidate base, so the upgrade fixes it")
	}
	if v["CVE-2"].FixedByUpgrade {
		t.Error("CVE-2 is still in the candidate base, so the upgrade does NOT fix it")
	}
	if s.Clears != 1 || s.Leaves != 1 || s.FromApp != 1 || s.FromBase != 2 {
		t.Errorf("summary wrong: %+v", s)
	}
}

func TestDiffCountsWhatTheUpgradeIntroduces(t *testing.T) {
	// Reporting only what an upgrade fixes is one-sided arithmetic, and the first
	// person to check it stops trusting the recommendation.
	built := res("base:1", "debian", [3]string{"debian", "openssl", "CVE-1"})
	cand := res("base:2", "debian", [3]string{"debian", "curl", "CVE-9"})

	_, s := Diff([]string{"CVE-1"}, built, cand)
	if s.Introduces != 1 {
		t.Errorf("the candidate base carries CVE-9, which the current one does not: got %d", s.Introduces)
	}
	if s.Clears != 1 {
		t.Errorf("clears = %d, want 1", s.Clears)
	}
}

func TestUnscannedBaseIsUnknownNotApplication(t *testing.T) {
	// The failure this design is a correction of: presenting "we did not look" as
	// "this is yours". A team sent work by that mistake has no way to tell.
	v, s := Diff([]string{"CVE-1"}, nil, nil)
	if v["CVE-1"].Origin != OriginUnknown {
		t.Errorf("with no base scan the origin is unknown, got %q", v["CVE-1"].Origin)
	}
	if s.Unknown != 1 || s.FromApp != 0 {
		t.Errorf("an unscanned base must not be attributed to the app: %+v", s)
	}
}

func TestNoCandidateLeavesTheUpgradeQuestionUndetermined(t *testing.T) {
	// Ownership is answerable from the base alone. "What would the upgrade fix"
	// is not, and must not read as "nothing".
	built := res("base:1", "debian", [3]string{"debian", "openssl", "CVE-1"})
	v, s := Diff([]string{"CVE-1"}, built, nil)
	if v["CVE-1"].Origin != OriginBase {
		t.Errorf("origin should still be decided, got %q", v["CVE-1"].Origin)
	}
	if v["CVE-1"].Determined {
		t.Error("no candidate was scanned, so the upgrade question is undetermined")
	}
	if s.Clears != 0 || s.Leaves != 0 {
		t.Errorf("no candidate means no clears/leaves claim: %+v", s)
	}
}

func TestDiffDeduplicatesAndIgnoresEmpty(t *testing.T) {
	built := res("base:1", "debian", [3]string{"debian", "openssl", "CVE-1"})
	_, s := Diff([]string{"CVE-1", "CVE-1", ""}, built, built)
	if s.Total != 1 {
		t.Errorf("the same CVE listed twice is one finding, got Total=%d", s.Total)
	}
}
