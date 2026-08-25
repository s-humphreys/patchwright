package upgrade

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/s-humphreys/patchwright/pkg/config"
)

// The Python tags this estate actually has, which is where the whole feature comes
// from: a service on 3.12.3 was being told to move to 3.14.7, a runtime migration its
// dependency tree could not take, when 3.12.14 was sitting there.
var pythonTags = []string{
	"3.12.3", "3.12.9", "3.12.10", "3.12.11", "3.12.14",
	"3.13.0", "3.13.7", "3.14.0", "3.14.7",
}

func pick(t *testing.T, current, strategy, ceiling string, tags []string) string {
	t.Helper()
	v, err := semver.StrictNewVersion(current)
	if err != nil {
		t.Fatal(err)
	}
	got := newestWithin(v, tags, strategy, ceiling)
	if got == nil {
		return ""
	}
	return got.Original()
}

func TestStrategyDecidesHowFarToMove(t *testing.T) {
	cases := []struct{ strategy, want string }{
		{"patch", "3.12.14"},
		{"minor", "3.14.7"},
		{"latest", "3.14.7"},
	}
	for _, c := range cases {
		if got := pick(t, "3.12.3", c.strategy, "", pythonTags); got != c.want {
			t.Errorf("strategy %q picked %q, want %q", c.strategy, got, c.want)
		}
	}
}

func TestCeilingKeepsPatchingWhileAMigrationWaits(t *testing.T) {
	// The point of a ceiling rather than a suppression: the CVEs stay fixable.
	if got := pick(t, "3.12.3", "latest", "3.12", pythonTags); got != "3.12.14" {
		t.Errorf("ceiling 3.12 picked %q, want 3.12.14", got)
	}
	if got := pick(t, "3.12.3", "latest", "3.13", pythonTags); got != "3.13.7" {
		t.Errorf("ceiling 3.13 picked %q, want 3.13.7", got)
	}
	// A ceiling at the current version leaves nothing to recommend, which the caller
	// reports as held back rather than as up to date.
	if got := pick(t, "3.12.14", "latest", "3.12", pythonTags); got != "" {
		t.Errorf("ceiling at the current minor picked %q, want nothing", got)
	}
}

func TestAnUnparseableCeilingConstrainsNothing(t *testing.T) {
	// A typo must not silently stop an estate being told about upgrades.
	if got := pick(t, "3.12.3", "latest", "three-twelve", pythonTags); got != "3.14.7" {
		t.Errorf("a nonsense ceiling picked %q, want the unconstrained answer", got)
	}
}

func TestVariantSuffixesStayOnTheirTrack(t *testing.T) {
	// The distro lives in the prerelease slot, and swapping it is an operating system
	// change presented as a patch.
	tags := []string{"10.0.3-azurelinux3.0", "10.0.11-azurelinux3.0", "10.0.11", "10.1.0"}
	if got := pick(t, "10.0.3-azurelinux3.0", "patch", "", tags); got != "10.0.11-azurelinux3.0" {
		t.Errorf("picked %q, want to stay on azurelinux", got)
	}
}

func TestConfigResolvesStrategyAndCeilingPerImage(t *testing.T) {
	cfg := config.UpgradeConfig{
		Strategy: "latest",
		Rules: []config.UpgradeRule{
			{Name: "docker.io/python", Strategy: "patch", Ceiling: "3.12",
				Until: "2099-01-01", Reason: "cdt dependencies are not 3.14 ready"},
			{Name: "acr.io/dotnet/*", Strategy: "minor"},
		},
	}
	strategy, ceiling, reason, expired := cfg.For("docker.io/python")
	if strategy != "patch" || ceiling != "3.12" || expired {
		t.Errorf("python rule = %q/%q expired=%v", strategy, ceiling, expired)
	}
	if reason == "" {
		t.Error("the reason for a ceiling must travel with it")
	}
	if s, _, _, _ := cfg.For("acr.io/dotnet/aspnet"); s != "minor" {
		t.Errorf("prefix rule gave %q, want minor", s)
	}
	if s, c, _, _ := cfg.For("docker.io/redis"); s != "latest" || c != "" {
		t.Errorf("unmatched image gave %q/%q, want the default and no ceiling", s, c)
	}
}

func TestAnExpiredCeilingIsNotAppliedButIsReported(t *testing.T) {
	// A constraint with a passed end date must not hold an estate back silently. It
	// lapses, and says it lapsed, so somebody revisits the decision.
	cfg := config.UpgradeConfig{Rules: []config.UpgradeRule{
		{Name: "docker.io/python", Ceiling: "3.12", Until: "2020-01-01",
			Reason: "was blocked on dependencies"},
	}}
	strategy, ceiling, reason, expired := cfg.For("docker.io/python")
	if !expired {
		t.Fatal("a ceiling dated 2020 has expired")
	}
	if ceiling != "" {
		t.Errorf("an expired ceiling must not be applied, got %q", ceiling)
	}
	if reason == "" || strategy == "" {
		t.Errorf("the reason and strategy still travel: %q / %q", reason, strategy)
	}
}

func TestDotnetPatchesStayOnTheirServicingBand(t *testing.T) {
	// .NET is not the Python case: its minor is always 0 within a major, so
	// "same major" already means "patch", and 10.0.3 -> 10.0.11 was never wrong.
	tags := []string{"10.0.1-azurelinux3.0", "10.0.3-azurelinux3.0", "10.0.11-azurelinux3.0",
		"11.0.0-azurelinux3.0"}
	if got := pick(t, "10.0.3-azurelinux3.0", "latest", "", tags); got != "10.0.11-azurelinux3.0" {
		t.Errorf("picked %q, want 10.0.11 on the same variant", got)
	}
}

func TestSDKFeatureBandsCanBeHeldWithACeiling(t *testing.T) {
	// The one .NET shape where the default surprises: an SDK feature band lives in
	// the PATCH field, so 10.0.100 -> 10.0.400 is a tooling jump that looks like a
	// patch. A ceiling expresses "stay in this band" because it is an upper bound
	// rather than a prefix match.
	tags := []string{"10.0.100-noble", "10.0.108-noble", "10.0.200-noble", "10.0.400-noble"}
	if got := pick(t, "10.0.100-noble", "patch", "", tags); got != "10.0.400-noble" {
		t.Errorf("unconstrained picked %q; feature bands are invisible to semver", got)
	}
	if got := pick(t, "10.0.100-noble", "patch", "10.0.199", tags); got != "10.0.108-noble" {
		t.Errorf("ceiling 10.0.199 picked %q, want to stay in the 1xx band", got)
	}
}

func TestInternalMirrorTagsAreTheMirrorsOwnVersioning(t *testing.T) {
	// The internal base carries the .NET major in the PATH (dotnet/aspnet/10) and
	// versions itself 1.x.y. A strategy applies to the mirror's numbering, not to
	// .NET's, so "minor" here allows 1.0 -> 1.1 of our own base image.
	tags := []string{"1.0.2", "1.0.5", "1.1.0", "1.1.1"}
	if got := pick(t, "1.0.2", "minor", "", tags); got != "1.1.1" {
		t.Errorf("picked %q, want the newest of our own base", got)
	}
	if got := pick(t, "1.0.2", "patch", "", tags); got != "1.0.5" {
		t.Errorf("patch-only picked %q; on this mirror that pins an older base", got)
	}
}
