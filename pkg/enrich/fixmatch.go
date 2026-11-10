package enrich

import (
	"regexp"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// matchFixToPackages makes a CVE's fix agree with the packages a scanner found it
// in, once there are any.
//
// The provider's fixed version is per CVE, not per package: it is whichever
// distribution's advisory the platform happened to record, and on the live estate
// that put `1.1.0-2ubuntu0.1` beside Azure Linux's brotli and `3.11.2-6+deb12u9`
// beside its python3. Taken at face value, an Ubuntu revision made an Azure Linux
// image "fixable", and a known-exploited critical that is fixable is urgent - so a
// version that cannot be installed on the image was raising its priority.
//
// The scanner's per-package version wins wherever it has one, because it came from
// the same pass as the package name and so belongs to the package's own ecosystem.
// Without one, the provider's version stands unless it demonstrably belongs to a
// distribution none of the packages are from. "Demonstrably" is deliberate: only a
// distribution's own revision marker counts as proof, so an unmarked version is
// given the benefit of the doubt it had before, and a CVE with no packages named is
// left exactly as the provider reported it.
func matchFixToPackages(v *model.Vulnerability) {
	if len(v.Packages) == 0 {
		return
	}
	var scanned string
	for _, p := range v.Packages {
		if p.FixedIn == "" {
			continue
		}
		if p.FixedIn == v.FixedVersion {
			// Already one the scanner agrees with; keep it rather than swap it for
			// another package's, so the version shown stays stable between runs.
			v.FixAvailable = true
			return
		}
		if scanned == "" {
			scanned = p.FixedIn
		}
	}
	if scanned != "" {
		v.FixAvailable, v.FixedVersion = true, scanned
		return
	}
	if v.FixedVersion == "" {
		return
	}
	for _, p := range v.Packages {
		if !foreignTo(v.FixedVersion, p.Ecosystem) {
			return
		}
	}
	// Cleared as well as disowned: a version left beside fix_available=false would
	// still read as something to upgrade to.
	v.FixAvailable, v.FixedVersion = false, ""
}

// distroMarkers are the revision markers that tie a package version to one
// distribution, mapped to the scanner ecosystems that distribution is reported as.
//
// Not a version parser, and not every distribution: only markers that cannot
// appear in another ecosystem's versions, for the distributions this estate runs.
// A version matching none of them proves nothing and is never rejected.
var distroMarkers = []struct {
	marker     *regexp.Regexp
	ecosystems []string
}{
	// First match wins, and Ubuntu goes first: its revisions are built on Debian's,
	// so its marker is the more specific of the two.
	{regexp.MustCompile(`ubuntu`), []string{"ubuntu"}},
	{regexp.MustCompile(`[+~]deb\d+u\d+`), []string{"debian"}},
	{regexp.MustCompile(`\.azl\d+`), []string{"azurelinux"}},
	{regexp.MustCompile(`\.cm\d+`), []string{"cbl-mariner", "mariner"}},
	{regexp.MustCompile(`\.el\d+`), []string{"redhat", "rhel", "centos", "rocky", "alma", "oracle"}},
}

// foreignTo reports whether version is demonstrably another distribution's than
// ecosystem's. A language ecosystem (npm, nuget, gobinary, ...) is in none of the
// lists, so any distribution's revision is foreign to it.
func foreignTo(version, ecosystem string) bool {
	for _, d := range distroMarkers {
		if !d.marker.MatchString(version) {
			continue
		}
		for _, eco := range d.ecosystems {
			if eco == ecosystem {
				return false
			}
		}
		return true
	}
	return false
}
