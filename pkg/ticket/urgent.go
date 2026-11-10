package ticket

import (
	"fmt"
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// DefaultUrgentEPSS is the exploitation probability at or above which a CVE is
// listed on a ticket as one the ticket must clear, when nothing configures it.
// It matches the shipped policy rules, so the list a ticket prints is the list
// that made the finding urgent.
const DefaultUrgentEPSS = 0.5

// UrgentVuln is one CVE a ticket exists to clear, with what closes it.
//
// A ticket's remaining thousand CVEs are context. These are the acceptance
// criteria: exploited in the wild, or likely to be, with a fix published. Each
// carries a plain-English Where and Action, because the people who pick these
// tickets up build .NET and Python services and should not need to know what
// linux-libc-dev is to act on a row that names it.
type UrgentVuln struct {
	Vuln
	// Why is what made it urgent, in the words a ticket prints: "exploited in
	// the wild", "EPSS 0.87", or both.
	Why string
	// Cleared reports that the ticket's upgrade removes it. Measured reports that
	// this was actually checked, by a base differential or by the upgrade provably
	// leaving the image where it is; when false, Cleared is false through
	// ignorance, and the two must not render the same way.
	Cleared  bool
	Measured bool
	// Origin is "base", "app", or "" when no base scan attributed it.
	Origin string
	// Package, Ecosystem and Path are what carries it, when a scan named one.
	// Empty means nothing scanned the layer it lives in, not that nothing does.
	Package   string
	Ecosystem string
	Path      string
	// Where and Action are the rendering of the above for somebody who does not
	// know package ecosystems: what the thing is, and what to do about it.
	Where  string
	Action string
	// Reference is the CVE record.
	Reference string
}

// urgent picks the CVEs that made this group urgent and says what closes each.
//
// Deduplicated across the group's images, since a shared base puts the same CVE
// on every one. Cleared is conservative: when several deployments were measured,
// the upgrade clears the CVE only if it clears it on all of them, because a
// ticket that says "clears" and leaves one environment carrying it gets bounced.
func urgent(group []sink.FindingView, epss float64) []UrgentVuln {
	if epss <= 0 {
		epss = DefaultUrgentEPSS
	}
	byID := map[string]*UrgentVuln{}
	var order []string
	for _, f := range group {
		for _, v := range f.Vulns {
			if !isUrgent(v, epss) {
				continue
			}
			u := byID[v.ID]
			if u == nil {
				u = &UrgentVuln{
					Vuln: Vuln{ID: v.ID, Severity: v.Severity, CVSS: v.CVSS,
						FixedVersion: v.FixedVersion, EPSS: v.EPSS, KEV: v.KEV},
					Why:       why(v, epss),
					Origin:    v.Origin,
					Cleared:   true,
					Reference: "https://www.cve.org/CVERecord?id=" + v.ID,
				}
				byID[v.ID] = u
				order = append(order, v.ID)
			}
			if measured, fixed := verdict(f, v); measured {
				u.Measured = true
				u.Cleared = u.Cleared && fixed
			}
			if u.Origin == "" {
				u.Origin = v.Origin
			}
			if u.Package == "" && len(v.Packages) > 0 {
				p := v.Packages[0]
				u.Package, u.Ecosystem, u.Path = p.Name, p.Ecosystem, p.Path
				// A row that tells somebody to move this package has to name a version
				// of it, and only FixedIn is sure to be one: see FixableInBuild.
				if u.FixedVersion == "" || v.FixableInBuild() {
					u.FixedVersion = p.FixedIn
				}
			}
		}
	}
	out := make([]UrgentVuln, 0, len(order))
	for _, id := range order {
		u := byID[id]
		// Never measured means never cleared, whatever the default above said.
		u.Cleared = u.Cleared && u.Measured
		u.Where, u.Action = describe(*u)
		out = append(out, *u)
	}
	// Exploited in the wild first, then most likely to be. A ticket should lead
	// with the one that is actually being used against somebody.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].KEV != out[j].KEV {
			return out[i].KEV
		}
		if out[i].EPSS != out[j].EPSS {
			return out[i].EPSS > out[j].EPSS
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func isUrgent(v sink.VulnView, epss float64) bool {
	return v.FixAvailable && (v.KEV || v.EPSS >= epss)
}

func isFixableCritical(v sink.VulnView) bool {
	return v.Severity == "critical" && v.FixAvailable
}

// verdict says whether the proposed change was measured against one CVE on one
// image, and if so whether it removes it. Two things measure it: a base
// differential, which scanned the base being moved onto, and an upgrade that
// provably leaves the image exactly as it is, which removes nothing from it.
//
// A CVE the image's own build adds, with a fix for every package carrying it, is
// cleared by the ticket whatever its upgrade is: the ticket names the package and
// the version to move it to, so that move is part of the change it asks for.
func verdict(f sink.FindingView, v sink.VulnView) (measured, fixed bool) {
	if unmoved(f) {
		return true, false
	}
	if v.FixableInBuild() {
		return true, true
	}
	return v.OriginDetermined, v.FixedByUpgrade
}

// actionable picks the CVEs that make a group actionable: its urgent ones when it
// carries any, since those are what the shipped rules raise a ticket for, and its
// fixable criticals otherwise, for a group a coarser rule made actionable.
func actionable(group []sink.FindingView, epss float64) func(sink.VulnView) bool {
	if epss <= 0 {
		epss = DefaultUrgentEPSS
	}
	pick := func(v sink.VulnView) bool { return isUrgent(v, epss) }
	if !carries(group, pick) {
		return isFixableCritical
	}
	return pick
}

// packageOnly reports a finding whose whole ticket is moving packages in its own
// build: at least one of the CVEs that make it actionable is FixableInBuild, and
// its base offers nothing for the rest. Either there is no newer base, or the one
// on offer was measured to keep every other actionable CVE.
//
// Without this such a finding is skipped for good, as "already on the latest" or
// as an upgrade that clears nothing, and an exploited CVE in a package somebody's
// Dockerfile installs sits in the queue with no ticket and no owner. A rebuild
// ticket is the wrong one for it: the rebuild is work that changes nothing.
//
// Unresolved and operator-chosen versions are left to the skips they have: what
// moving them would do is not known, so neither is whether this is all the work.
func packageOnly(f sink.FindingView, epss float64) bool {
	u := f.Upgrade
	if u == nil || u.Kind != "base" || !u.Resolved || u.OperatorChosen {
		return false
	}
	pick := actionable([]sink.FindingView{f}, epss)
	fixable := false
	for _, v := range f.Vulns {
		if !pick(v) {
			continue
		}
		if v.FixableInBuild() {
			fixable = true
			continue
		}
		// One the move might clear makes this a rebuild ticket, which lists the
		// package moves beside the rebuild instead.
		if u.Available && (!v.OriginDetermined || v.FixedByUpgrade) {
			return false
		}
	}
	return fixable
}

// asPackageChange gives a package-only finding the package change as its upgrade,
// so grouping, the priority threshold, rendering and reconciliation take it through
// the same path as any other change. The base move it replaces fixes none of what
// made it actionable, so it has nothing to say on this ticket.
func asPackageChange(f sink.FindingView, epss float64) sink.FindingView {
	up := &sink.UpgradeView{Kind: "package", Available: true, Resolved: true, Actionable: true}
	if fixes := buildFixes([]sink.FindingView{f}, epss); len(fixes) == 1 {
		up.Name, up.Current, up.Latest = fixes[0].Name, fixes[0].Current, fixes[0].Fixed
	}
	f.Upgrade = up
	return f
}

// PackageFix is one package an image's own build has to move, and what that clears.
type PackageFix struct {
	Name      string
	Ecosystem string
	// Path is the file declaring a language package; empty for an OS package.
	Path string
	// Current is the version the scan found installed, empty when it reported none.
	// Fixed is the version that clears CVEs, from the same scan as the name.
	Current string
	Fixed   string
	// CVEs are the actionable CVEs this move clears, exploited first.
	CVEs []string
}

// CVEList is CVEs as one string, for a template.
func (p PackageFix) CVEList() string { return strings.Join(p.CVEs, ", ") }

// buildFixes lists the package moves that clear the group's actionable CVEs which
// its images' own builds add. One row per package and fixed version: two CVEs
// fixed in different versions of one package are two versions to know about, and
// which is later is not something every ecosystem's version strings say.
func buildFixes(group []sink.FindingView, epss float64) []PackageFix {
	pick := actionable(group, epss)
	type rank struct {
		kev  bool
		epss float64
	}
	ranks := map[string]rank{}
	byKey := map[string]*PackageFix{}
	seen := map[string]bool{}
	var keys []string
	for _, f := range group {
		for _, v := range f.Vulns {
			if !pick(v) || !v.FixableInBuild() {
				continue
			}
			ranks[v.ID] = rank{v.KEV, v.EPSS}
			for _, p := range v.Packages {
				key := p.Ecosystem + "\x00" + p.Name + "\x00" + p.Path + "\x00" + p.FixedIn
				pf := byKey[key]
				if pf == nil {
					pf = &PackageFix{Name: p.Name, Ecosystem: p.Ecosystem, Path: p.Path, Fixed: p.FixedIn}
					byKey[key] = pf
					keys = append(keys, key)
				}
				if pf.Current == "" {
					pf.Current = p.Installed
				}
				if !seen[key+"\x00"+v.ID] {
					seen[key+"\x00"+v.ID] = true
					pf.CVEs = append(pf.CVEs, v.ID)
				}
			}
		}
	}
	sort.Strings(keys)
	out := make([]PackageFix, 0, len(keys))
	for _, k := range keys {
		pf := *byKey[k]
		sort.Slice(pf.CVEs, func(i, j int) bool {
			a, b := ranks[pf.CVEs[i]], ranks[pf.CVEs[j]]
			if a.kev != b.kev {
				return a.kev
			}
			if a.epss != b.epss {
				return a.epss > b.epss
			}
			return pf.CVEs[i] < pf.CVEs[j]
		})
		out = append(out, pf)
	}
	return out
}

// unmoved reports that the finding's upgrade was measured to leave its image on
// the tag it already runs: a chart bump whose target chart deploys the same tag
// from the same repository, or whose tag our own release values pin.
//
// A tag taken from the chart's appVersion is how its templates usually behave
// rather than something read off the image entry, and a moved repository is a
// different image whatever its tag, so neither is ever proof of staying put.
func unmoved(f sink.FindingView) bool {
	u := f.Upgrade
	return u != nil && u.Kind == "chart" && u.ImageCurrent != "" && u.ImageLatest == u.ImageCurrent &&
		u.ImageLatestFrom != model.ImageTagFromAppVersion && u.ImageLatestRepo == ""
}

// clearsNone reports that the proposed change was measured to clear none of the
// CVEs that make this group actionable, so a ticket for it would ask for work
// that fixes nothing.
//
// The actionable CVEs are the urgent ones when there are any, since those are
// what the shipped rules raise a ticket for and what "Done means" lists, and the
// fixable criticals otherwise, for a group a coarser rule made actionable. A
// change that moves no image at all clears nothing whatever the CVEs are.
//
// Judged per image: every image carrying one of those CVEs has to have been
// measured and found to keep it. An image nothing measured might lose it, and an
// image that cannot be measured - no differential configured, no base resolved, a
// base gone from its registry - is never a reason to withhold a ticket: that gap
// is permanent, and holding on it would mean never raising one.
//
// An image whose measurement failed in THIS run is a different gap, and is
// unmeasured's to judge, not this function's: it is temporary, and the run that
// cannot see is not the one to act on what it cannot see.
func clearsNone(group []sink.FindingView, epss float64) bool {
	if len(group) == 0 {
		return false
	}
	moved := false
	for _, f := range group {
		if !unmoved(f) {
			moved = true
		}
	}
	if !moved {
		return true
	}
	pick := actionable(group, epss)
	picked := false
	for _, f := range group {
		for _, v := range f.Vulns {
			if !pick(v) {
				continue
			}
			picked = true
			if measured, fixed := verdict(f, v); !measured || fixed {
				return false
			}
		}
	}
	return picked
}

// unmeasured returns why the proposed change could not be judged in this run, or
// "" when it could. That is when a measurement that would have decided it failed:
// an image carrying one of the actionable CVEs went unmeasured because its base
// differential failed this run, and nothing else in the group was measured to
// clear one.
//
// Raising a ticket on that unknown is how one unavailable vulnerability database
// raised tickets for upgrades already measured, the run before, to fix nothing.
// Acting on it the other way, closing or commenting, is no better. So the change
// is held: nothing raised, nothing open touched, until a run can see it.
//
// A change some image was measured to clear stands on that measurement and is not
// held: whatever the unmeasured images would have said, the ticket is justified.
func unmeasured(group []sink.FindingView, epss float64) string {
	pick := actionable(group, epss)
	reason := ""
	for _, f := range group {
		for _, v := range f.Vulns {
			if !pick(v) {
				continue
			}
			measured, fixed := verdict(f, v)
			if measured && fixed {
				return ""
			}
			if !measured && f.BaseDiffError != "" && reason == "" {
				reason = f.BaseDiffError
			}
		}
	}
	return reason
}

func carries(group []sink.FindingView, pick func(sink.VulnView) bool) bool {
	for _, f := range group {
		for _, v := range f.Vulns {
			if pick(v) {
				return true
			}
		}
	}
	return false
}

func why(v sink.VulnView, epss float64) string {
	var parts []string
	if v.KEV {
		parts = append(parts, "exploited in the wild")
	}
	if v.EPSS >= epss {
		parts = append(parts, fmt.Sprintf("EPSS %.2f", v.EPSS))
	}
	return strings.Join(parts, ", ")
}

// ecosystem is what a ticket says about a package manager's packages: the noun
// for one of them, and how to move it.
type ecosystem struct {
	// noun names the kind of package ("Python package", "Linux package").
	noun string
	// os is true for a distribution's packages, installed rather than declared.
	os bool
	// upgrade is the command that takes an OS package to its fixed version.
	upgrade string
	// where is the file a language package is normally declared in, used when the
	// scan did not record a path.
	where string
}

// ecosystems maps the scanner's ecosystem names to how a ticket talks about them.
// A name not listed here gets the generic wording, never nothing.
var ecosystems = map[string]ecosystem{
	"debian": {noun: "Linux package", os: true, upgrade: "apt-get update && apt-get upgrade -y"},
	"ubuntu": {noun: "Linux package", os: true, upgrade: "apt-get update && apt-get upgrade -y"},

	"alpine":     {noun: "Linux package", os: true, upgrade: "apk upgrade --no-cache"},
	"wolfi":      {noun: "Linux package", os: true, upgrade: "apk upgrade --no-cache"},
	"chainguard": {noun: "Linux package", os: true, upgrade: "apk upgrade --no-cache"},

	"azurelinux":  {noun: "Linux package", os: true, upgrade: "tdnf update -y"},
	"mariner":     {noun: "Linux package", os: true, upgrade: "tdnf update -y"},
	"cbl-mariner": {noun: "Linux package", os: true, upgrade: "tdnf update -y"},
	"photon":      {noun: "Linux package", os: true, upgrade: "tdnf update -y"},

	"redhat": {noun: "Linux package", os: true, upgrade: "dnf update -y"},
	"rhel":   {noun: "Linux package", os: true, upgrade: "dnf update -y"},
	"centos": {noun: "Linux package", os: true, upgrade: "dnf update -y"},
	"rocky":  {noun: "Linux package", os: true, upgrade: "dnf update -y"},
	"alma":   {noun: "Linux package", os: true, upgrade: "dnf update -y"},
	"fedora": {noun: "Linux package", os: true, upgrade: "dnf update -y"},
	"amazon": {noun: "Linux package", os: true, upgrade: "dnf update -y"},
	"oracle": {noun: "Linux package", os: true, upgrade: "dnf update -y"},

	"suse":     {noun: "Linux package", os: true, upgrade: "zypper update -y"},
	"opensuse": {noun: "Linux package", os: true, upgrade: "zypper update -y"},
	"sles":     {noun: "Linux package", os: true, upgrade: "zypper update -y"},

	"pip":        {noun: "Python package", where: "requirements.txt or pyproject.toml"},
	"python-pkg": {noun: "Python package", where: "requirements.txt or pyproject.toml"},
	"poetry":     {noun: "Python package", where: "pyproject.toml"},
	"pipenv":     {noun: "Python package", where: "Pipfile"},
	"uv":         {noun: "Python package", where: "pyproject.toml"},
	"conda-pkg":  {noun: "Python package", where: "environment.yml"},

	"npm":      {noun: "npm package", where: "package.json"},
	"node-pkg": {noun: "npm package", where: "package.json"},
	"yarn":     {noun: "npm package", where: "package.json"},
	"pnpm":     {noun: "npm package", where: "package.json"},
	"bun":      {noun: "npm package", where: "package.json"},

	"nuget":           {noun: "NuGet package", where: "the .csproj"},
	"dotnet-core":     {noun: "NuGet package", where: "the .csproj"},
	"packages-props":  {noun: "NuGet package", where: "Directory.Packages.props"},
	"gomod":           {noun: "Go module", where: "go.mod"},
	"gobinary":        {noun: "Go module compiled into a binary", where: "the binary's go.mod"},
	"jar":             {noun: "Java library", where: "the build file"},
	"pom":             {noun: "Java library", where: "pom.xml"},
	"gradle":          {noun: "Java library", where: "build.gradle"},
	"sbt":             {noun: "Java library", where: "build.sbt"},
	"gem":             {noun: "Ruby gem", where: "Gemfile"},
	"gemspec":         {noun: "Ruby gem", where: "Gemfile"},
	"bundler":         {noun: "Ruby gem", where: "Gemfile"},
	"cargo":           {noun: "Rust crate", where: "Cargo.toml"},
	"rust-binary":     {noun: "Rust crate compiled into a binary", where: "Cargo.toml"},
	"composer":        {noun: "PHP package", where: "composer.json"},
	"composer-vendor": {noun: "PHP package", where: "composer.json"},
	"pub":             {noun: "Dart package", where: "pubspec.yaml"},
	"hex":             {noun: "Elixir package", where: "mix.exs"},
	"cocoapods":       {noun: "CocoaPods dependency", where: "the Podfile"},
	"swift":           {noun: "Swift package", where: "Package.swift"},
	"conan":           {noun: "C/C++ package", where: "conanfile"},
}

// buildOnly names OS packages that have no business in a runtime image: they exist
// to compile things. The right fix is not to upgrade them but to stop shipping
// them, which no package manager command says.
var buildOnly = map[string]string{
	"linux-libc-dev":  "kernel headers",
	"linux-headers":   "kernel headers",
	"binutils":        "compiler tooling",
	"gcc":             "compiler tooling",
	"g++":             "compiler tooling",
	"cpp":             "compiler tooling",
	"make":            "compiler tooling",
	"build-essential": "compiler tooling",
}

// describe renders one urgent CVE's Where and Action for a reader who does not
// know what an ecosystem is. Every branch returns something; a blank cell in a
// ticket reads as "we do not know either".
func describe(u UrgentVuln) (where, action string) {
	fixed := u.FixedVersion
	if fixed == "" {
		fixed = "the fixed version"
	}
	name := u.Package

	switch {
	case u.Cleared && u.Origin == "app":
		// Cleared by moving the package rather than by the upgrade: where it lives is
		// worded as for any package the build adds, and what to do is the move.
		plain := u
		plain.Cleared = false
		where, _ = describe(plain)
		return where, buildFixAction(u)

	case u.Cleared:
		if name != "" {
			return fmt.Sprintf("The base image (%s)", name), "Nothing extra. The rebuild above removes it."
		}
		return "The base image", "Nothing extra. The rebuild above removes it."

	case u.Origin == "base" && u.Measured:
		where = "The base image"
		if name != "" {
			where = fmt.Sprintf("The base image (%s)", name)
		}
		return where, fmt.Sprintf("The newer base still carries it. Take %s on top of the base in your Dockerfile, or wait for the base to update.", fixed)
	}

	if name == "" {
		if !u.Measured {
			return "Not determined: the base could not be scanned",
				fmt.Sprintf("Make the change above, then check the dashboard link. If this remains, find what ships a version below %s and move it to %s.", fixed, fixed)
		}
		return "A dependency your build adds (no scan named it)",
			fmt.Sprintf("Find what ships a version below %s in your lockfiles and move it to %s.", fixed, fixed)
	}

	eco, known := ecosystems[strings.ToLower(u.Ecosystem)]
	if !known {
		return fmt.Sprintf("The %s package %s", u.Ecosystem, name),
			fmt.Sprintf("Move %s to %s where your build declares it.", name, fixed)
	}
	if eco.os {
		if kind, ok := buildOnlyKind(name); ok {
			return fmt.Sprintf("%s your Dockerfile installs (%s)", capitalise(kind), name),
				fmt.Sprintf("Only needed to compile. Install %s in a build stage so it is not in the runtime image, or run `%s` after your install step to take %s.", name, eco.upgrade, fixed)
		}
		return fmt.Sprintf("A %s your Dockerfile installs (%s)", eco.noun, name),
			fmt.Sprintf("Run `%s` after your install step to take %s, or remove %s if only the build needs it.", eco.upgrade, fixed, name)
	}
	declared := eco.where
	if u.Path != "" {
		declared = u.Path
	}
	return fmt.Sprintf("The %s %s, declared in %s", eco.noun, name, declared),
		fmt.Sprintf("Move %s to %s in %s and refresh the lockfile.", name, fixed, declared)
}

// buildFixAction says how to move a package the build adds to the version that
// clears a CVE, and that a rebuild on a newer base will not: the ticket exists
// because the base move on offer was the instruction, and it fixes nothing here.
func buildFixAction(u UrgentVuln) string {
	const notBase = " A base image rebuild will not remove it: it is not in the base."
	eco, known := ecosystems[strings.ToLower(u.Ecosystem)]
	switch {
	case known && eco.os:
		return fmt.Sprintf("Upgrade %s to %s in your Dockerfile: run `%s` after your install step, or remove %s if only the build needs it.",
			u.Package, u.FixedVersion, eco.upgrade, u.Package) + notBase
	case known:
		declared := eco.where
		if u.Path != "" {
			declared = u.Path
		}
		return fmt.Sprintf("Move %s to %s in %s and refresh the lockfile.", u.Package, u.FixedVersion, declared) + notBase
	}
	return fmt.Sprintf("Move %s to %s where your build declares it.", u.Package, u.FixedVersion) + notBase
}

// buildOnlyKind matches a package to the build-only table, including versioned
// names like linux-headers-6.1.0-amd64.
func buildOnlyKind(name string) (string, bool) {
	n := strings.ToLower(name)
	if k, ok := buildOnly[n]; ok {
		return k, true
	}
	for prefix, k := range buildOnly {
		if strings.HasPrefix(n, prefix+"-") {
			return k, true
		}
	}
	return "", false
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
