package upgrade

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/support"
)

// The case this exists for. A ceiling holding Python at 3.12 was written because ONE
// team's dependency tree is not ready. Keyed only on the base image, it held back every
// other service on that base and reported them with somebody else's stated reason.
func pythonCeiling(when string) config.RemediationConfig {
	return config.RemediationConfig{
		FirstPartyRegistries: []string{"example.azurecr.io"},
		Upgrade: config.UpgradeConfig{
			Strategy: "latest",
			Rules: []config.UpgradeRule{{
				Name: "docker.io/python", When: when, Strategy: "patch",
				Ceiling: "3.12", Until: "2099-12-31",
				Reason: "this team's packages are not 3.14 ready",
			}},
		},
	}
}

// service builds a first-party image on python 3.12.3, owned by a team and running in a
// namespace, which is what a scope has to be able to name.
func service(repo, team, namespace string) model.AssessedImage {
	return model.AssessedImage{
		Image: model.Image{
			Registry: "example.azurecr.io", Repository: repo, Tag: "1.0.0",
			Ref: "example.azurecr.io/" + repo + ":1.0.0",
		},
		Occurrences: []model.Occurrence{{
			Owner: model.Owner{Class: "engineering", Team: team},
			Resource: model.Resource{
				Dimensions: map[string]string{"namespace": namespace, "account": "Production EU"},
				Labels:     map[string]string{"team": team},
			},
		}},
	}
}

func pythonResolver(t *testing.T, cfg config.RemediationConfig) *BaseResolver {
	t.Helper()
	return &BaseResolver{
		Cfg: cfg,
		Inspector: eolInspector{labels: map[string]string{
			"org.opencontainers.image.base.name": "docker.io/python:3.12.3",
		}},
		Lister: eolLister{tags: []string{"3.12.3", "3.12.14", "3.13.2", "3.14.7"}},
	}
}

func upgradeFor(t *testing.T, r *BaseResolver, imgs ...model.AssessedImage) map[string]model.Upgrade {
	t.Helper()
	got, err := r.Upgrades(context.Background(), imgs)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestAScopedCeilingHoldsOnlyTheServiceItIsAbout(t *testing.T) {
	r := pythonResolver(t, pythonCeiling("owner['team'] == 'research'"))
	got := upgradeFor(t, r,
		service("task-daemon", "research", "analytics"),
		service("storefront", "insights", "shop"),
	)

	held := got["example.azurecr.io/task-daemon:1.0.0"]
	if held.Latest != "3.12.14" {
		t.Errorf("scoped team: Latest = %q, want 3.12.14 (the ceiling applies)", held.Latest)
	}
	if held.Ceiling != "3.12" || held.Rule != "docker.io/python" {
		t.Errorf("scoped team: ceiling=%q rule=%q, want the rule named", held.Ceiling, held.Rule)
	}

	free := got["example.azurecr.io/storefront:1.0.0"]
	if free.Latest != "3.14.7" {
		t.Errorf("other team: Latest = %q, want 3.14.7: another team's constraint must not hold it", free.Latest)
	}
	if free.Ceiling != "" || free.Rule != "" || free.CeilingReason != "" {
		t.Errorf("other team: got ceiling=%q rule=%q reason=%q, want none of it",
			free.Ceiling, free.Rule, free.CeilingReason)
	}
}

func TestAScopeCanNameANamespaceOrLabelRatherThanATeam(t *testing.T) {
	// Ownership is not always the right axis: the constraint may belong to one
	// deployment of a service, and the namespace is what somebody can point at.
	for _, when := range []string{
		"'analytics' in dimensions['namespace']",
		"'research' in labels['team']",
		"image['repository'] == 'task-daemon'",
	} {
		r := pythonResolver(t, pythonCeiling(when))
		got := upgradeFor(t, r,
			service("task-daemon", "research", "analytics"),
			service("storefront", "insights", "shop"),
		)
		if v := got["example.azurecr.io/task-daemon:1.0.0"].Latest; v != "3.12.14" {
			t.Errorf("when=%q: scoped image got %q, want 3.12.14", when, v)
		}
		if v := got["example.azurecr.io/storefront:1.0.0"].Latest; v != "3.14.7" {
			t.Errorf("when=%q: unscoped image got %q, want 3.14.7", when, v)
		}
	}
}

func TestAnUnscopedRuleStillAppliesEverywhere(t *testing.T) {
	// The existing behaviour has to survive: a rule with no `when` is estate-wide,
	// which is what every rule written before this feature meant.
	r := pythonResolver(t, pythonCeiling(""))
	got := upgradeFor(t, r,
		service("task-daemon", "research", "analytics"),
		service("storefront", "insights", "shop"),
	)
	for ref, up := range got {
		if up.Latest != "3.12.14" {
			t.Errorf("%s: Latest = %q, want 3.12.14", ref, up.Latest)
		}
	}
}

func TestAScopeThatDoesNotCompileFailsTheRun(t *testing.T) {
	// Not a rule that never matches. An inert rule reports the unconstrained answer
	// with the same confidence as a considered one, and nobody goes looking for it.
	r := pythonResolver(t, pythonCeiling("owner['team' == 'oops'"))
	_, err := r.Upgrades(context.Background(), []model.AssessedImage{service("a", "t", "n")})
	if err == nil {
		t.Fatal("want an error for a scope that does not compile")
	}
	if !strings.Contains(err.Error(), "docker.io/python") {
		t.Errorf("error should name the rule, got: %v", err)
	}
}

func TestAScopeThatCannotBeDecidedDoesNotApplyTheCeiling(t *testing.T) {
	// An expression that evaluates to an error has not said this image is covered.
	// Applying somebody else's ceiling on a maybe is worse than applying none: the
	// report would show a restraint with a reason belonging to another service.
	r := pythonResolver(t, pythonCeiling("dimensions['nosuchkey'][0] == 'x'"))
	got := upgradeFor(t, r, service("storefront", "insights", "shop"))
	up := got["example.azurecr.io/storefront:1.0.0"]
	if up.Ceiling != "" {
		t.Errorf("ceiling = %q, want none when the scope could not be decided", up.Ceiling)
	}
	if up.Latest != "3.14.7" {
		t.Errorf("Latest = %q, want the unconstrained answer", up.Latest)
	}
}

func TestTheFirstMatchingScopedRuleWins(t *testing.T) {
	// Ordering is the file's, as before, so a specific rule sits above a general one.
	cfg := config.RemediationConfig{
		FirstPartyRegistries: []string{"example.azurecr.io"},
		Upgrade: config.UpgradeConfig{
			Strategy: "latest",
			Rules: []config.UpgradeRule{
				{Name: "docker.io/python", When: "owner['team'] == 'research'",
					Strategy: "patch", Ceiling: "3.12", Until: "2099-12-31", Reason: "not ready"},
				{Name: "docker.io/python", Strategy: "minor", Ceiling: "3.13", Until: "2099-12-31",
					Reason: "estate default"},
			},
		},
	}
	r := pythonResolver(t, cfg)
	got := upgradeFor(t, r,
		service("task-daemon", "research", "analytics"),
		service("storefront", "insights", "shop"),
	)
	if v := got["example.azurecr.io/task-daemon:1.0.0"].Latest; v != "3.12.14" {
		t.Errorf("specific rule: got %q, want 3.12.14", v)
	}
	if v := got["example.azurecr.io/storefront:1.0.0"].Latest; v != "3.13.2" {
		t.Errorf("fallthrough rule: got %q, want 3.13.2", v)
	}
}

func TestAScopeSeesEveryDeploymentOfTheImage(t *testing.T) {
	// One image typically runs in several namespaces. A rule naming one of them must
	// match regardless of which deployment the resolver started from, or the decision
	// would depend on provider ordering.
	img := service("task-daemon", "research", "analytics")
	img.Occurrences = append(img.Occurrences, model.Occurrence{
		Owner:    model.Owner{Class: "engineering", Team: "research"},
		Resource: model.Resource{Dimensions: map[string]string{"namespace": "analytics-jobs"}},
	})
	r := pythonResolver(t, pythonCeiling("'analytics-jobs' in dimensions['namespace']"))
	got := upgradeFor(t, r, img)
	if v := got["example.azurecr.io/task-daemon:1.0.0"].Latest; v != "3.12.14" {
		t.Errorf("got %q, want 3.12.14: the second deployment's namespace must be visible", v)
	}
}

func TestACeilingIsNotSteppedPastEvenWhenTheLineIsDead(t *testing.T) {
	// The two features meet here. A ceiling holds this image inside Python 3.12; the
	// support feed says 3.12 is finished. Recommending the migration would walk past an
	// explicit constraint, which is the same failure as a rule that silently does not
	// fire, pointing the other way.
	//
	// The honest output is both facts: the line is dead, and policy holds you on it.
	// That is a conflict for a person to resolve by lifting the ceiling.
	cfg := config.RemediationConfig{
		FirstPartyRegistries: []string{"example.azurecr.io"},
		Upgrade: config.UpgradeConfig{
			Strategy: "latest",
			Rules: []config.UpgradeRule{{
				Name: "docker.io/python", Strategy: "patch", Ceiling: "3.12",
				Until: "2099-12-31", Reason: "dependencies are not ready",
			}},
		},
	}
	r := &BaseResolver{
		Cfg: cfg,
		Inspector: eolInspector{labels: map[string]string{
			"org.opencontainers.image.base.name": "docker.io/python:3.12.14",
		}},
		// Nothing newer in 3.12, and the off-track target EXISTS as a tag, so the
		// only thing stopping the migration being recommended is the ceiling. Without
		// "3.14" here the test would pass because no candidate could be constructed,
		// which proves nothing about the behaviour under test.
		Lister:  eolLister{tags: []string{"3.12.14", "3.13", "3.13.2", "3.14", "3.14.7"}},
		Support: eolSupport{product: pythonDead()},
		Now:     func() time.Time { return day("2026-08-27") },
	}
	got := upgradeFor(t, r, service("legacy-etl", "insights", "etl"))
	up := got["example.azurecr.io/legacy-etl:1.0.0"]

	if up.OutOfTrack {
		t.Error("recommended a move off the line, stepping past an explicit ceiling")
	}
	if up.Latest != "" || up.Available {
		t.Errorf("Latest = %q available=%v, want no recommendation while the ceiling stands", up.Latest, up.Available)
	}
	if !up.HeldBack {
		t.Error("HeldBack is false: newer versions exist and policy allows none of them")
	}
	// And the reader must still be told the line is finished, or the ceiling looks
	// merely conservative rather than actively harmful.
	if up.Support == nil || up.Support.Supported || !up.Support.Known {
		t.Errorf("support = %+v, want a known end-of-life verdict alongside the ceiling", up.Support)
	}
	if up.Ceiling != "3.12" || up.Rule == "" {
		t.Errorf("ceiling=%q rule=%q, want the constraint named", up.Ceiling, up.Rule)
	}
}

// pythonDead is the support feed with 3.12 finished and newer lines maintained.
func pythonDead() support.Product {
	return support.Product{Name: "python", Cycles: []support.Cycle{
		{Name: "3.12", EOL: day("2026-01-01"), EOLKnown: true},
		{Name: "3.13", EOL: day("2029-10-31"), EOLKnown: true},
		{Name: "3.14", EOL: day("2030-10-31"), EOLKnown: true},
	}}
}
