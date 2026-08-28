package basescan

import "sort"

// Origin is where a vulnerability came from, established by scanning rather than
// inferred from a package name.
type Origin string

const (
	// OriginBase means the base image as built already contained this CVE. The
	// team that owns the application did not introduce it and mostly cannot fix
	// it in their own repository.
	OriginBase Origin = "base"
	// OriginApp means the CVE is in the image but not in the base it was built
	// from, so something the Dockerfile did put it there. This is the team's.
	OriginApp Origin = "app"
	// OriginUnknown means no base scan was available, so the question was not
	// answered. Deliberately distinct from OriginApp: "we did not look" and "we
	// looked and it is yours" are different statements, and collapsing them is
	// how the previous attempt at this shipped a guess dressed as an answer.
	OriginUnknown Origin = "unknown"
)

// Verdict is what the differential concluded about one CVE.
type Verdict struct {
	Origin Origin
	// FixedByUpgrade is true only when the CVE is in the base as built AND absent
	// from the candidate base. False when the candidate was not scanned, which is
	// why Determined exists.
	FixedByUpgrade bool
	// Determined reports whether a candidate base was actually scanned. Without
	// it, "not fixed by the upgrade" is indistinguishable from "we never checked",
	// and the page must not render those the same way.
	Determined bool
}

// Summary counts a differential across one image, which is what a queue row needs
// in order to say what an upgrade buys.
type Summary struct {
	Total      int // CVEs considered
	FromBase   int // present in the base as built
	FromApp    int // in the image, not in its base
	Unknown    int // no base scan, so unattributed
	Clears     int // fixed by moving to the candidate base
	Leaves     int // from the base, still present in the candidate
	Introduces int // in the candidate base but not the current one
}

// Diff classifies an image's CVEs against the base it was built from and the base
// it is being asked to move to.
//
// built may be nil (no base known, or its scan failed), in which case nothing is
// attributed and every CVE is Unknown. candidate may be nil independently: the
// base is known but there is no upgrade to evaluate, so ownership is answerable
// and "what would the upgrade fix" is not.
func Diff(cves []string, built, candidate *Result) (map[string]Verdict, Summary) {
	out := make(map[string]Verdict, len(cves))
	var s Summary

	seen := make(map[string]bool, len(cves))
	for _, cve := range cves {
		if cve == "" || seen[cve] {
			continue
		}
		seen[cve] = true
		s.Total++

		if built == nil {
			out[cve] = Verdict{Origin: OriginUnknown}
			s.Unknown++
			continue
		}
		if !built.Has(cve) {
			// Absent from the base is a real answer only because the base was
			// actually scanned; that is what `built != nil` establishes.
			out[cve] = Verdict{Origin: OriginApp, Determined: candidate != nil}
			s.FromApp++
			continue
		}

		v := Verdict{Origin: OriginBase, Determined: candidate != nil}
		s.FromBase++
		if candidate != nil && !candidate.Has(cve) {
			v.FixedByUpgrade = true
			s.Clears++
		} else if candidate != nil {
			s.Leaves++
		}
		out[cve] = v
	}

	// What the upgrade would bring with it. A base that fixes 3,664 and adds 40 is
	// still worth taking, but reporting only the first half is the kind of
	// one-sided arithmetic that gets a recommendation distrusted the first time
	// somebody checks it.
	if built != nil && candidate != nil {
		for cve := range candidate.CVEs {
			if !built.Has(cve) {
				s.Introduces++
			}
		}
	}
	return out, s
}

// FilterPackages narrows a set of provider-supplied package names to the
// ecosystems the image actually contains.
//
// The provider names a package per CVE drawn from a generic remediation record,
// so it frequently names one from an ecosystem the image does not have - a Debian
// package for a Red Hat image. Where the named ecosystem IS present, the name
// agreed with a scanner 94% of the time, so this filter is the difference between
// unusable and usable, not a cosmetic tidy-up.
//
// Returns only packages whose ecosystem the base scan confirms.
func FilterPackages(pkgs []Package, in *Result) []Package {
	if in == nil || len(in.Ecosystems) == 0 {
		return nil
	}
	var out []Package
	for _, p := range pkgs {
		if in.Ecosystems[p.Ecosystem] {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
