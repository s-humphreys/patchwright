package ticket

import (
	"fmt"
	"sort"
	"strings"

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
	// this was actually checked by a base differential; when false, Cleared is
	// false through ignorance, and the two must not render the same way.
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
			if !v.FixAvailable || !(v.KEV || v.EPSS >= epss) {
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
			if v.OriginDetermined {
				u.Measured = true
				u.Cleared = u.Cleared && v.FixedByUpgrade
			}
			if u.Origin == "" {
				u.Origin = v.Origin
			}
			if u.Package == "" && len(v.Packages) > 0 {
				p := v.Packages[0]
				u.Package, u.Ecosystem, u.Path = p.Name, p.Ecosystem, p.Path
				if u.FixedVersion == "" {
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
