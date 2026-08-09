// Package policy decides which findings are actionable. It evaluates
// user-defined CEL rules over the finding context — image, rolled-up counts,
// risk, owner, aggregated dimensions/labels, and per-CVE vulnerabilities.
// Suppression takes precedence over actionability; among actionable rules, the
// first match wins and sets the priority.
package policy

import (
	"fmt"

	"github.com/google/cel-go/cel"

	"github.com/s-humphreys/patchwright/internal/celx"
	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// Evaluator applies compiled policy rules to findings.
type Evaluator struct {
	actionable []compiledRule
	suppress   []compiledRule
}

type compiledRule struct {
	rule config.PolicyRule
	prg  cel.Program
}

// findingEnv builds the CEL environment for finding-level rules.
func findingEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("image", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("counts", cel.MapType(cel.StringType, cel.IntType)),
		cel.Variable("risk", cel.DoubleType),
		cel.Variable("owner", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("dimensions", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("labels", cel.MapType(cel.StringType, cel.ListType(cel.StringType))),
		cel.Variable("vulns", cel.ListType(cel.MapType(cel.StringType, cel.DynType))),
		// Liveness from reconciliation. When reconciliation has not run,
		// reconciled is false and live defaults to true so rules that ignore
		// liveness behave unchanged.
		cel.Variable("reconciled", cel.BoolType),
		cel.Variable("live", cel.BoolType),
		// upgrade_available is true when remediation detected a newer version
		// that can be applied directly (e.g. a newer Helm chart, or a newer
		// image tag for a directly-deployed workload). It is false for images
		// whose version is controlled by a chart/operator, since bumping them
		// directly isn't the remediation.
		cel.Variable("upgrade_available", cel.BoolType),
	)
}

// New compiles actionable and suppress rules into an Evaluator.
func New(actionable, suppress []config.PolicyRule) (*Evaluator, error) {
	env, err := findingEnv()
	if err != nil {
		return nil, fmt.Errorf("build cel env: %w", err)
	}
	e := &Evaluator{}
	var compileErr error
	e.actionable, compileErr = compileRules(env, actionable, "actionable")
	if compileErr != nil {
		return nil, compileErr
	}
	e.suppress, compileErr = compileRules(env, suppress, "suppress")
	if compileErr != nil {
		return nil, compileErr
	}
	return e, nil
}

func compileRules(env *cel.Env, rules []config.PolicyRule, kind string) ([]compiledRule, error) {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		prg, err := celx.CompileBool(env, r.When)
		if err != nil {
			return nil, fmt.Errorf("%s rule %q: when: %w", kind, r.Name, err)
		}
		out = append(out, compiledRule{rule: r, prg: prg})
	}
	return out, nil
}

// Evaluate sets Actionable/Suppressed/Priority/Reasons on a finding in place.
// A finding matched by a suppress rule is marked suppressed and never
// actionable. Otherwise the first matching actionable rule marks it actionable
// and assigns its priority. Findings matching no rule are left non-actionable
// with an explanatory reason.
func (e *Evaluator) Evaluate(f *model.Finding) error {
	act := findingActivation(*f)

	for _, cr := range e.suppress {
		matched, err := celx.EvalBool(cr.prg, act)
		if err != nil {
			return fmt.Errorf("suppress rule %q: evaluating for image %q: %w", cr.rule.Name, f.Image.Ref, err)
		}
		if matched {
			f.Suppressed = true
			f.Actionable = false
			f.Reasons = append(f.Reasons, fmt.Sprintf("suppressed by rule %q", cr.rule.Name))
			return nil
		}
	}

	for _, cr := range e.actionable {
		matched, err := celx.EvalBool(cr.prg, act)
		if err != nil {
			return fmt.Errorf("actionable rule %q: evaluating for image %q: %w", cr.rule.Name, f.Image.Ref, err)
		}
		if matched {
			f.Actionable = true
			f.Priority = cr.rule.Priority
			f.Reasons = append(f.Reasons, fmt.Sprintf("matched actionable rule %q", cr.rule.Name))
			return nil
		}
	}

	f.Reasons = append(f.Reasons, "no actionable rule matched")
	return nil
}

// EvaluateAll evaluates every finding in place.
func (e *Evaluator) EvaluateAll(findings []model.Finding) error {
	for i := range findings {
		if err := e.Evaluate(&findings[i]); err != nil {
			return err
		}
	}
	return nil
}

// findingActivation builds the CEL variable bindings for one finding.
func findingActivation(f model.Finding) map[string]any {
	vulns := make([]any, 0, len(f.Vulns))
	for _, v := range f.Vulns {
		vulns = append(vulns, map[string]any{
			"id":            v.ID,
			"severity":      v.Severity,
			"cvss":          v.CVSS,
			"fix_available": v.FixAvailable,
			"fixed_version": v.FixedVersion,
			"epss":          v.EPSS,
			"kev":           v.KEV,
		})
	}
	// When reconciliation has not run, liveness is unknown; default live to
	// true so liveness-unaware rules are unaffected.
	live := f.Live
	if !f.Reconciled {
		live = true
	}
	return map[string]any{
		"image": map[string]string{
			"registry":   f.Image.Registry,
			"repository": f.Image.Repository,
			"tag":        f.Image.Tag,
			"digest":     f.Image.Digest,
			"ref":        f.Image.Ref,
		},
		"counts":            map[string]int(f.Counts.Normalized()),
		"risk":              f.RiskScore,
		"owner":             map[string]string{"class": f.Owner.Class, "team": f.Owner.Team},
		"dimensions":        f.Dimensions,
		"labels":            f.Labels,
		"vulns":             vulns,
		"reconciled":        f.Reconciled,
		"live":              live,
		"upgrade_available": f.Upgrade != nil && f.Upgrade.Available && f.Upgrade.Actionable,
	}
}
