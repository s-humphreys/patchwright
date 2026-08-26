package cli

import (
	"slices"
	"testing"
)

func TestSourcesInheritTheProvidersOptions(t *testing.T) {
	// The Rapid7 vuln, exploit and age sources are the same platform reached the same
	// way, and the provider was already told where it is. Making somebody repeat the
	// base URL four times is not configuration, it is four chances to typo one — and a
	// base URL wrong by a character fails in a way that reads like a permissions
	// problem.
	pf := &providerFlags{name: "rapid7", options: []string{"base-url=https://example.divvycloud.com"}}

	for _, source := range []string{"rapid7", "public,rapid7", "RAPID7"} {
		got := pf.inherited(source, nil)
		if !slices.Equal(got, pf.options) {
			t.Errorf("source %q inherited %v, want the provider's options", source, got)
		}
	}
}

func TestAForeignSourceInheritsNothing(t *testing.T) {
	// Trivy is not the provider and does not take its options; handing them over would
	// pass a base URL to something that has no use for one.
	pf := &providerFlags{name: "rapid7", options: []string{"base-url=https://example.divvycloud.com"}}
	if got := pf.inherited("trivy", nil); len(got) != 0 {
		t.Errorf("trivy inherited %v, want nothing", got)
	}
	if got := pf.inherited("public", nil); len(got) != 0 {
		t.Errorf("public inherited %v, want nothing", got)
	}
}

func TestExplicitOptionsWin(t *testing.T) {
	// A source can still be pointed somewhere else: inheritance is a default, not a
	// rule.
	pf := &providerFlags{name: "rapid7", options: []string{"base-url=https://one.example"}}
	own := []string{"base-url=https://two.example"}
	if got := pf.inherited("rapid7", own); !slices.Equal(got, own) {
		t.Errorf("inherited %v, want the explicit options %v", got, own)
	}
}

func TestNoSourceMeansNothingToInherit(t *testing.T) {
	pf := &providerFlags{name: "rapid7", options: []string{"base-url=https://one.example"}}
	if got := pf.inherited("", nil); len(got) != 0 {
		t.Errorf("empty source inherited %v", got)
	}
}
