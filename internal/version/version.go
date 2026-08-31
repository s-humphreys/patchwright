// Package version reports which build this is.
package version

import "runtime/debug"

// Version is the release this binary was built from, set at link time:
//
//	-ldflags "-X github.com/s-humphreys/patchwright/internal/version.Version=v1.29.0"
//
// Unset it falls back to the module version the toolchain recorded, and then to
// "dev". A build that cannot say what it is says so, rather than claiming a version
// it might not be - the point of showing this at all is telling two deployments
// apart, and a confident wrong answer defeats that.
var Version string

// String returns the version, resolved once at first use.
func String() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
