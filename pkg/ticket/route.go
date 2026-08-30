package ticket

import (
	"fmt"

	"cel.dev/cel-go/cel"

	"github.com/s-humphreys/patchwright/internal/celx"
	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/policy"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Routing sends a finding's ticket to the tracker its owner actually uses.
//
// One deployment covers teams that do not share a board: platform work belongs
// on one project, an SRE team may have its own with a different issue type and
// priority scheme. Without routing the only options are a single shared project
// or one deployment per team, and both are worse than they sound — the first
// buries a team's work in someone else's backlog, the second duplicates the
// config that decides what "actionable" means.
//
// Routes match on the same CEL variables as policy and exclusion rules, so
// owner['team'] means here exactly what it means there. First match wins, and a
// finding matching nothing uses the top-level settings.

// routeName is the reserved name for the top-level settings, so every draft has
// a route and there is no "no route" branch to forget.
const routeName = "(default)"

type routes struct {
	compiled []compiledRoute
}

type compiledRoute struct {
	route config.TicketRoute
	prg   cel.Program
}

func newRoutes(rules []config.TicketRoute) (*routes, error) {
	if len(rules) == 0 {
		return &routes{}, nil
	}
	env, err := policy.FindingEnv()
	if err != nil {
		return nil, err
	}
	out := &routes{}
	for _, r := range rules {
		if r.Name == "" {
			return nil, fmt.Errorf("jira route missing name")
		}
		if r.Name == routeName {
			// Otherwise a route could shadow the default in logs and dry runs,
			// and two different configurations would report the same name.
			return nil, fmt.Errorf("jira route may not be named %q; that name is reserved for the top-level settings", routeName)
		}
		if r.When == "" {
			return nil, fmt.Errorf("jira route %q missing when", r.Name)
		}
		prg, err := celx.CompileBool(env, r.When)
		if err != nil {
			return nil, fmt.Errorf("jira route %q: %w", r.Name, err)
		}
		out.compiled = append(out.compiled, compiledRoute{route: r, prg: prg})
	}
	return out, nil
}

// match returns the name of the first route matching the finding, or routeName.
//
// An expression that errors at evaluation is treated as not matching, and the
// finding falls through to the next route. The alternative — failing the run —
// would mean one malformed expression stops every team's tickets, and the
// alternative to that — treating an error as a match — would send work to a
// board on the strength of a broken rule.
func (r *routes) match(f sink.FindingView) string {
	for _, c := range r.compiled {
		if ok, err := celx.EvalBool(c.prg, viewActivation(f)); err == nil && ok {
			return c.route.Name
		}
	}
	return routeName
}
