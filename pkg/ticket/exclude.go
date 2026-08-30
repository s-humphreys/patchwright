package ticket

import (
	"fmt"

	"cel.dev/cel-go/cel"

	"github.com/s-humphreys/patchwright/internal/celx"
	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/policy"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// exclusions decide which actionable findings should not become tickets.
//
// This is separate from policy suppression on purpose. A suppressed finding is
// one nobody should act on, and disappears from the assessment. An excluded
// finding is real work that is simply tracked somewhere else — a team with its
// own upgrade cadence, a component under a different process. It stays in the
// report and the queue; it just does not get a ticket raised here.
type exclusions struct {
	rules []compiledExclusion
}

type compiledExclusion struct {
	rule config.ExcludeRule
	prg  cel.Program
}

func newExclusions(rules []config.ExcludeRule) (*exclusions, error) {
	if len(rules) == 0 {
		return &exclusions{}, nil
	}
	// The same CEL environment as policy rules, so `dimensions['namespace']` and
	// `image.registry` mean here exactly what they mean there.
	env, err := policy.FindingEnv()
	if err != nil {
		return nil, err
	}
	out := &exclusions{}
	for _, r := range rules {
		if r.Name == "" {
			return nil, fmt.Errorf("jira exclude rule missing name")
		}
		if r.When == "" {
			return nil, fmt.Errorf("jira exclude rule %q missing when expression", r.Name)
		}
		prg, err := celx.CompileBool(env, r.When)
		if err != nil {
			return nil, fmt.Errorf("jira exclude rule %q: %w", r.Name, err)
		}
		out.rules = append(out.rules, compiledExclusion{rule: r, prg: prg})
	}
	return out, nil
}

// match returns the first matching rule's name and reason, if any.
func (e *exclusions) match(f sink.FindingView) (name, reason string, matched bool, err error) {
	if e == nil || len(e.rules) == 0 {
		return "", "", false, nil
	}
	act := viewActivation(f)
	for _, cr := range e.rules {
		ok, err := celx.EvalBool(cr.prg, act)
		if err != nil {
			return "", "", false, fmt.Errorf("jira exclude rule %q: %w", cr.rule.Name, err)
		}
		if ok {
			return cr.rule.Name, cr.rule.Reason, true, nil
		}
	}
	return "", "", false, nil
}

// viewActivation binds a finding view to the same CEL variable names the policy
// engine uses over model.Finding, so one expression reads the same in both
// places. The two inputs genuinely differ (this side reads the saved JSON), but
// the vocabulary must not.
func viewActivation(f sink.FindingView) map[string]any {
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

	// Match the policy engine: when reconciliation did not run, liveness is
	// unknown and defaults to true so liveness-unaware rules are unaffected.
	reconciled, live := false, true
	if f.Liveness != nil {
		reconciled, live = true, f.Liveness.Live
	}

	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for k, v := range f.Counts {
		counts[k] = v
	}

	upgradeAvailable := f.Upgrade != nil && f.Upgrade.Available && f.Upgrade.Actionable

	return map[string]any{
		"image": map[string]string{
			"registry":   f.Registry,
			"repository": f.Repository,
			"tag":        f.Tag,
			"digest":     f.Digest,
			"ref":        f.Image,
		},
		"counts":            counts,
		"risk":              f.Risk,
		"owner":             map[string]string{"class": f.Owner.Class, "team": f.Owner.Team},
		"dimensions":        f.Dimensions,
		"labels":            f.Labels,
		"vulns":             vulns,
		"reconciled":        reconciled,
		"live":              live,
		"upgrade_available": upgradeAvailable,
	}
}
