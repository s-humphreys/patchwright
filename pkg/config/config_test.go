package config

import "testing"

// A rule that silently does not fire is worse than no rule: nobody is looking for it,
// and the report presents the unconstrained answer with the same confidence as a
// considered one.
//
// This is the case that shipped: a ceiling holding Python at 3.12 applied to an image
// whose base label read "docker.io/python" and was skipped for one reading
// "docker.io/library/python". Same image, same team's intent, opposite advice - the
// queue told one service to patch to 3.12.14 and another to migrate to 3.14.7, which
// the ceiling's own stated reason says is not ready.
func TestUpgradeRulesMatchEverySpellingOfOneImage(t *testing.T) {
	cfg := UpgradeConfig{
		Strategy: "latest",
		Rules: []UpgradeRule{{
			Name: "docker.io/python", Strategy: "patch", Ceiling: "3.12",
			Until: "2099-12-31", Reason: "dependencies are not ready",
		}},
	}

	// Every one of these is Docker Hub's python image.
	for _, name := range []string{
		"docker.io/python",
		"docker.io/library/python",
		"index.docker.io/library/python",
		"library/python",
		"python",
		"DOCKER.IO/Library/Python",
	} {
		strategy, ceiling, _, expired := cfg.For(name)
		if strategy != "patch" || ceiling != "3.12" || expired {
			t.Errorf("%s: strategy=%q ceiling=%q expired=%v, want patch/3.12: the ceiling must not depend on the spelling",
				name, strategy, ceiling, expired)
		}
	}

	// And it must not overreach. These are different images that merely look similar.
	for _, name := range []string{
		"ghcr.io/acme/python",
		"example.azurecr.io/python",
		"docker.io/bitnami/python",
		"docker.io/pythonic",
	} {
		if strategy, ceiling, _, _ := cfg.For(name); ceiling != "" || strategy != "latest" {
			t.Errorf("%s: strategy=%q ceiling=%q, want the default: a rule for Docker Hub's python must not capture it",
				name, strategy, ceiling)
		}
	}
}

func TestCanonicalisationKeepsWildcardRulesWorking(t *testing.T) {
	cfg := UpgradeConfig{
		Strategy: "latest",
		Rules:    []UpgradeRule{{Name: "mcr.microsoft.com/dotnet/*", Strategy: "minor"}},
	}
	if s, _, _, _ := cfg.For("mcr.microsoft.com/dotnet/aspnet"); s != "minor" {
		t.Errorf("wildcard rule stopped matching: got %q", s)
	}
	// A Docker Hub wildcard has to survive the implicit namespace too.
	hub := UpgradeConfig{Strategy: "latest", Rules: []UpgradeRule{{Name: "bitnami/*", Strategy: "patch"}}}
	for _, name := range []string{"docker.io/bitnami/redis", "bitnami/redis"} {
		if s, _, _, _ := hub.For(name); s != "patch" {
			t.Errorf("%s: got %q, want patch", name, s)
		}
	}
}
