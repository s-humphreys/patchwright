// Package attribute assigns an Owner to each occurrence by evaluating
// user-defined CEL ownership rules. Rules reason over the generic occurrence
// context — image, dimensions, labels, counts, resource — so ownership logic
// is entirely configuration, never hard-coded.
package attribute

import (
	"fmt"
	"log/slog"

	"cel.dev/cel-go/cel"

	"github.com/s-humphreys/patchwright/internal/celx"
	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// UnknownOwner is assigned when no ownership rule matches.
var UnknownOwner = model.Owner{Class: "unknown", Team: "unknown"}

// Attributor evaluates compiled ownership rules against occurrences.
type Attributor struct {
	rules []compiledRule
}

type compiledRule struct {
	rule     config.OwnerRule
	match    cel.Program
	teamFrom cel.Program // nil unless the rule sets teamFrom
}

// occurrenceEnv builds the CEL environment for occurrence-level rules.
func occurrenceEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("image", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("dimensions", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("labels", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("counts", cel.MapType(cel.StringType, cel.IntType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.StringType)),
	)
}

// New compiles ownership rules into an Attributor.
func New(rules []config.OwnerRule) (*Attributor, error) {
	env, err := occurrenceEnv()
	if err != nil {
		return nil, fmt.Errorf("build cel env: %w", err)
	}
	a := &Attributor{}
	for _, r := range rules {
		match, err := celx.CompileBool(env, r.Match)
		if err != nil {
			return nil, fmt.Errorf("owner rule %q: match: %w", r.Name, err)
		}
		cr := compiledRule{rule: r, match: match}
		if r.TeamFrom != "" {
			teamFrom, err := celx.CompileString(env, r.TeamFrom)
			if err != nil {
				return nil, fmt.Errorf("owner rule %q: teamFrom: %w", r.Name, err)
			}
			cr.teamFrom = teamFrom
		}
		a.rules = append(a.rules, cr)
	}
	return a, nil
}

// Attribute returns the Owner for a single occurrence. The first rule whose
// match expression is true wins; if none match, UnknownOwner is returned.
func (a *Attributor) Attribute(o model.Occurrence) (model.Owner, error) {
	act := occurrenceActivation(o)
	for _, cr := range a.rules {
		matched, err := celx.EvalBool(cr.match, act)
		if err != nil {
			return model.Owner{}, fmt.Errorf("owner rule %q: evaluating match for image %q: %w", cr.rule.Name, o.Image.Ref, err)
		}
		if !matched {
			continue
		}
		owner := model.Owner{Class: cr.rule.Class, Team: cr.rule.Team, Rule: cr.rule.Name}
		if cr.teamFrom != nil {
			team, err := celx.EvalString(cr.teamFrom, act)
			if err != nil {
				return model.Owner{}, fmt.Errorf("owner rule %q: evaluating teamFrom for image %q: %w", cr.rule.Name, o.Image.Ref, err)
			}
			owner.Team = team
		}
		return owner, nil
	}
	return UnknownOwner, nil
}

// AttributeAll assigns owners to every occurrence in place, returning the same
// slice for convenience.
func (a *Attributor) AttributeAll(occ []model.Occurrence) ([]model.Occurrence, error) {
	unknown := 0
	for i := range occ {
		owner, err := a.Attribute(occ[i])
		if err != nil {
			return nil, err
		}
		occ[i].Owner = owner
		if owner.Rule == "" {
			unknown++
		}
	}
	if unknown > 0 {
		slog.Warn("some occurrences matched no ownership rule", "unattributed", unknown, "total", len(occ))
	}
	return occ, nil
}

// occurrenceActivation builds the CEL variable bindings for one occurrence.
func occurrenceActivation(o model.Occurrence) map[string]any {
	return map[string]any{
		"image": map[string]string{
			"registry":   o.Image.Registry,
			"repository": o.Image.Repository,
			"tag":        o.Image.Tag,
			"digest":     o.Image.Digest,
			"ref":        o.Image.Ref,
		},
		"dimensions": nonNil(o.Resource.Dimensions),
		"labels":     nonNil(o.Resource.Labels),
		"counts":     map[string]int(o.Counts.Normalized()),
		"resource": map[string]string{
			"id":   o.Resource.ID,
			"type": o.Resource.Type,
			"name": o.Resource.Name,
		},
	}
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
