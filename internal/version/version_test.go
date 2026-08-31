package version

import "testing"

func TestAnUnstampedBuildSaysSoRatherThanGuessing(t *testing.T) {
	// The point of showing a version is telling two deployments apart. A build that
	// cannot say what it is has to say that, because a confident wrong answer is
	// worse than an obviously absent one.
	Version = ""
	if got := String(); got == "" {
		t.Error("String() must always return something to render")
	}
}

func TestAStampedBuildReportsWhatItWasGiven(t *testing.T) {
	Version = "v1.29.0"
	defer func() { Version = "" }()
	if got := String(); got != "v1.29.0" {
		t.Errorf("String() = %q, want the linker-supplied value", got)
	}
}
