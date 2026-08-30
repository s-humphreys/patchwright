package support

import "strings"

// Product identification: which piece of software is a base image, so its support
// window can be looked up.
//
// This is a table rather than an inference because the mapping is not derivable. A
// repository path is a vendor's filing decision: mcr.microsoft.com/dotnet/aspnet and
// mcr.microsoft.com/dotnet/runtime are the same support cycle, eclipse-temurin and
// openjdk are the same language with different packaging, and "node" tells you nothing
// about the fact that endoflife.date files it as "nodejs".
//
// The table is deliberately conservative. An unrecognised base image reports NO support
// data rather than a guess, and the queue then says the support status was not checked.
// Guessing wrong in the confident direction would be worse than not looking: it would
// mark a live runtime end-of-life, or worse, an end-of-life runtime supported.

// products maps a repository suffix to an endoflife.date product name. Matching is on
// path segments from the right, so "docker.io/library/node" and "node" both resolve, and
// a private mirror at "example.azurecr.io/dockerhub/node" resolves too.
var products = map[string]string{
	// Language runtimes, where an end-of-life major is the case this exists for.
	"node":            "nodejs",
	"python":          "python",
	"golang":          "go",
	"go":              "go",
	"ruby":            "ruby",
	"php":             "php",
	"rust":            "rust",
	"openjdk":         "java",
	"eclipse-temurin": "eclipse-temurin",
	"amazoncorretto":  "amazon-corretto",

	// .NET files several images against one support cycle.
	"dotnet/sdk":             "dotnet",
	"dotnet/runtime":         "dotnet",
	"dotnet/aspnet":          "dotnet",
	"dotnet/runtime-deps":    "dotnet",
	"dotnet/monitor":         "dotnet",
	"dotnet/samples":         "dotnet",
	"dotnet/nightly/sdk":     "dotnet",
	"dotnet/nightly/aspnet":  "dotnet",
	"dotnet/nightly/runtime": "dotnet",

	// Operating system bases. Worth having: an image on an unmaintained distro has
	// the same permanent-no-fix property as a dead runtime, and the same empty Fix
	// column.
	"alpine":        "alpine",
	"debian":        "debian",
	"ubuntu":        "ubuntu",
	"rockylinux":    "rocky-linux",
	"almalinux":     "almalinux",
	"amazonlinux":   "amazon-linux",
	"oraclelinux":   "oracle-linux",
	"opensuse/leap": "opensuse-leap",

	// Services commonly run from an official image, where the major line matters.
	"postgres":                     "postgresql",
	"mysql":                        "mysql",
	"mariadb":                      "mariadb",
	"redis":                        "redis",
	"valkey":                       "valkey",
	"mongo":                        "mongodb",
	"nginx":                        "nginx",
	"haproxy":                      "haproxy",
	"rabbitmq":                     "rabbitmq",
	"elasticsearch":                "elasticsearch",
	"opensearchproject/opensearch": "opensearch",
	"grafana/grafana":              "grafana",
	"kong":                         "kong-gateway",
	"traefik":                      "traefik",
	"consul":                       "consul",
	"vault":                        "vault",
}

// ProductFor identifies the endoflife.date product for a repository, or reports that
// this base image is not one it knows.
//
// Overrides come from configuration and win, so an internal base image can be declared
// as the thing it is built from ("example.azurecr.io/dotnet/aspnet/10" is a .NET support
// cycle even though the path is the organisation's own).
func ProductFor(repository string, overrides map[string]string) (string, bool) {
	product, _, ok := ProductAndCycleFor(repository, overrides)
	return product, ok
}

// ProductAndCycleFor resolves a repository to a product and, optionally, the
// support cycle it is pinned to.
//
// The cycle normally comes from the image's TAG, which is right for an upstream
// image: docker.io/node:20 is nodejs 20. It is wrong for a mirror that carries
// its own versioning. An internal "dotnet/aspnet/10" tagged 1.0.2 is .NET 10 - the
// major is in the PATH, and reading the tag makes it .NET 1.0, which reached end
// of life in 2019. That misfired on 382 images before anyone noticed, every one of
// them reported as running a dead runtime.
//
// So a mapping may pin the cycle explicitly:
//
//	example.azurecr.io/dotnet/aspnet/10: dotnet@10
//
// An empty product still suppresses the check for that repository.
func ProductAndCycleFor(repository string, overrides map[string]string) (product, cycle string, ok bool) {
	repo := strings.ToLower(strings.Trim(repository, "/"))
	if repo == "" {
		return "", "", false
	}
	// Longest override match first: an override is somebody's explicit statement
	// about this repository and outranks the built-in table entirely.
	if p, found := matchLongest(repo, overrides); found {
		name, pinned := splitCycle(p)
		return name, pinned, name != ""
	}
	if p, found := matchLongest(repo, products); found {
		name, pinned := splitCycle(p)
		return name, pinned, name != ""
	}
	return "", "", false
}

// splitCycle separates "dotnet@10" into its product and the cycle it pins.
func splitCycle(v string) (product, cycle string) {
	if i := strings.Index(v, "@"); i >= 0 {
		return strings.TrimSpace(v[:i]), strings.TrimSpace(v[i+1:])
	}
	return strings.TrimSpace(v), ""
}

// matchLongest finds the entry matching the most trailing path segments, so a specific
// "dotnet/aspnet" beats a bare "dotnet" and a mirror prefix never defeats a match.
func matchLongest(repo string, table map[string]string) (string, bool) {
	if len(table) == 0 {
		return "", false
	}
	segments := strings.Split(repo, "/")
	best, bestLen := "", 0
	for key, product := range table {
		k := strings.ToLower(strings.Trim(key, "/"))
		kseg := strings.Split(k, "/")
		if len(kseg) > len(segments) || len(kseg) <= bestLen {
			continue
		}
		// Compare the key's segments against the repository's trailing segments, so
		// the registry and any mirror path in front of them are ignored.
		tail := segments[len(segments)-len(kseg):]
		match := true
		for i := range kseg {
			if tail[i] != kseg[i] {
				match = false
				break
			}
		}
		if match {
			best, bestLen = product, len(kseg)
		}
	}
	return best, bestLen > 0
}
