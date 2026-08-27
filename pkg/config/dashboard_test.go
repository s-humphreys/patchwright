package config

import "testing"

func TestDashboardLinkOmittedWhenUnconfigured(t *testing.T) {
	// A ticket pointing at a hostname nobody can reach is worse than a ticket with no
	// link, and the server cannot know its own external URL: it binds a port and has
	// no idea what ingress or port-forward somebody reaches it through.
	var d DashboardConfig
	if got := d.Link([2]string{"team", "platform"}); got != "" {
		t.Fatalf("Link() = %q, want empty when no dashboard URL is set", got)
	}
}

func TestDashboardLinkBuildsADeepLink(t *testing.T) {
	d := DashboardConfig{URL: "https://patchwright.example.internal/"}
	got := d.Link([2]string{"team", "data platform"}, [2]string{"service", "top/notch"})
	want := "https://patchwright.example.internal/?service=top%2Fnotch&team=data+platform"
	if got != want {
		t.Fatalf("Link() = %q, want %q", got, want)
	}
}

func TestDashboardLinkDropsEmptyParameters(t *testing.T) {
	// A link carrying "?team=" would filter the queue to nothing, which looks exactly
	// like the work having been done.
	d := DashboardConfig{URL: "https://patchwright.example.internal"}
	got := d.Link([2]string{"team", ""}, [2]string{"service", "app"})
	if want := "https://patchwright.example.internal/?service=app"; got != want {
		t.Fatalf("Link() = %q, want %q", got, want)
	}
	if got := d.Link([2]string{"team", ""}); got != "https://patchwright.example.internal/" {
		t.Fatalf("Link() with nothing to filter on = %q, want the bare page", got)
	}
}
