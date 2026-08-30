package upgrade

import (
	"fmt"
	"sort"

	"cel.dev/cel-go/cel"

	"github.com/s-humphreys/patchwright/internal/celx"
	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// Scoping upgrade rules to the workloads they are actually about.
//
// A rule keyed only on a base image name says "nobody may move past Python 3.12". That
// is almost never what anybody means. The constraint behind it belongs to a service: one
// team's dependency tree is not ready, and every other service on that base is held at a
// version it could have left months ago — reported, worse, as a considered recommendation
// with a stated reason belonging to somebody else's code.
//
// So a rule can carry a `when` expression over the first-party image and where it runs,
// and the report names which rule applied. Both halves matter: without the scope the
// constraint is too broad, and without naming the rule a reader cannot tell a deliberate
// restraint from a resolver that found nothing.

// upgradeEnv is the CEL environment a rule's `when` is compiled against.
//
// Deliberately narrower than the policy environment. This decides how far to move a
// version, so it gets the identity of the thing being moved and where it runs, and none
// of the severity or exploit signals: a ceiling that lifted itself because a CVE turned
// up would be a constraint that evaporates exactly when somebody leans on it.
func upgradeEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("image", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("base", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("owner", cel.MapType(cel.StringType, cel.StringType)),
		// Lists rather than single values: one image is typically deployed several
		// times, so "which namespace" has more than one answer and a rule should be
		// able to name any of them without knowing which deployment it came from.
		cel.Variable("dimensions", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("labels", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
	)
}

// ruleSet is the upgrade rules with their scopes compiled.
type ruleSet struct {
	cfg      config.UpgradeConfig
	programs []cel.Program // nil entry means an unscoped rule, which always applies
}

// newRuleSet compiles every rule's scope up front.
//
// A rule that does not compile is an error rather than a rule that never matches. The
// difference is the whole point of this file: a silently inert rule reports the
// unconstrained answer as though somebody had chosen it.
func newRuleSet(cfg config.UpgradeConfig) (*ruleSet, error) {
	rs := &ruleSet{cfg: cfg, programs: make([]cel.Program, len(cfg.Rules))}
	if !cfg.HasScopes() {
		return rs, nil
	}
	env, err := upgradeEnv()
	if err != nil {
		return nil, err
	}
	for i, r := range cfg.Rules {
		if r.When == "" {
			continue
		}
		prg, err := celx.CompileBool(env, r.When)
		if err != nil {
			name := r.Name
			if name == "" {
				name = fmt.Sprintf("rule %d", i+1)
			}
			return nil, fmt.Errorf("upgrade rule %q: when: %w", name, err)
		}
		rs.programs[i] = prg
	}
	return rs, nil
}

// decision is what the rules say about one image, and which rule said it.
type decision struct {
	Strategy string
	Ceiling  string
	Reason   string
	Expired  bool
	Rule     string
}

// forImage picks the first rule whose name matches the base AND whose scope includes
// this image, falling back to the default strategy.
//
// First match wins, as before, so the file reads top to bottom and a specific rule goes
// above a general one. An expression that fails to evaluate does NOT match: a rule whose
// scope cannot be decided has not said this image is covered, and quietly applying
// somebody else's ceiling is worse than applying none.
func (rs *ruleSet) forImage(base string, act map[string]any) decision {
	for i, r := range rs.cfg.Rules {
		if !config.MatchesImageName(r.Name, base) {
			continue
		}
		if prg := rs.programs[i]; prg != nil {
			ok, err := celx.EvalBool(prg, act)
			if err != nil || !ok {
				continue
			}
		}
		strategy := r.Strategy
		if !config.ValidStrategy(strategy) {
			strategy = rs.cfg.EffectiveStrategy()
		}
		d := decision{Strategy: strategy, Reason: r.Reason, Rule: ruleLabel(r, i)}
		if r.Ceiling != "" && r.Expired() {
			d.Expired = true
			return d
		}
		d.Ceiling = r.Ceiling
		return d
	}
	return decision{Strategy: rs.cfg.EffectiveStrategy()}
}

func ruleLabel(r config.UpgradeRule, i int) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("rule %d", i+1)
}

// activation describes one first-party image to a rule's scope.
//
// Values are collected across every deployment of the image, de-duplicated and sorted:
// an image running in three namespaces gets all three, so a rule naming one of them
// matches regardless of which deployment the resolver happened to start from. Sorted so
// the same estate produces the same decision on every run.
func imageActivation(img model.AssessedImage) map[string]any {
	dims := map[string]map[string]bool{}
	labels := map[string]map[string]bool{}
	owner := map[string]string{}
	for _, o := range img.Occurrences {
		for k, v := range o.Resource.Dimensions {
			if v == "" {
				continue
			}
			if dims[k] == nil {
				dims[k] = map[string]bool{}
			}
			dims[k][v] = true
		}
		for k, v := range o.Resource.Labels {
			if v == "" {
				continue
			}
			if labels[k] == nil {
				labels[k] = map[string]bool{}
			}
			labels[k][v] = true
		}
		// First non-empty owner wins. Occurrences of one image nearly always agree,
		// and where they do not, the image is one thing being rebuilt once.
		if owner["team"] == "" && o.Owner.Team != "" {
			owner["team"] = o.Owner.Team
			owner["class"] = o.Owner.Class
			owner["rule"] = o.Owner.Rule
		}
	}
	return map[string]any{
		"image": map[string]string{
			"registry":   img.Image.Registry,
			"repository": img.Image.Repository,
			"tag":        img.Image.Tag,
			"ref":        img.Image.Ref,
			"name":       img.Image.Registry + "/" + img.Image.Repository,
		},
		"owner":      owner,
		"dimensions": flatten(dims),
		"labels":     flatten(labels),
	}
}

// withBase returns the activation for one base-image decision.
//
// Copied rather than mutated: the same image activation is reused for every link in a
// base chain, and writing the base into it would leave the previous link's values behind
// for the next rule to match on.
func withBase(act map[string]any, base model.Image) map[string]any {
	out := make(map[string]any, len(act)+1)
	for k, v := range act {
		out[k] = v
	}
	out["base"] = map[string]string{
		"name":    base.Registry + "/" + base.Repository,
		"current": base.Tag,
	}
	return out
}

// emptyActivation describes an image the estate knows nothing about, for a base image
// resolved as a link in somebody else's chain rather than as a finding of its own.
//
// A scoped rule will not match it, which is the safe direction: it means a constraint
// somebody wrote about their service does not silently attach to an image they were not
// talking about. That base image's own finding, if it is in the estate, gets its own
// decision with its own context.
func emptyActivation(base model.Image) map[string]any {
	return map[string]any{
		"image":      map[string]string{},
		"owner":      map[string]string{},
		"dimensions": map[string][]string{},
		"labels":     map[string][]string{},
		"base": map[string]string{
			"name":    base.Registry + "/" + base.Repository,
			"current": base.Tag,
		},
	}
}

func flatten(in map[string]map[string]bool) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, set := range in {
		vals := make([]string, 0, len(set))
		for v := range set {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		out[k] = vals
	}
	return out
}
