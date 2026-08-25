// Package ticket turns assessed findings into ticket drafts. It is deliberately
// free of any Jira client: planning what to raise is pure, deterministic, and
// testable, and only the separate transport applies it. That split is what makes
// a trustworthy dry run possible.
package ticket

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Draft is one ticket to raise: what it says, and which images it covers.
type Draft struct {
	Summary     string
	Description string
	// Images are bare repositories (no registry, no tag), the form the image
	// field/label carries and the key an existing ticket is found by.
	Images []string
	// Findings are the assessed findings this draft covers, for reporting.
	Findings []sink.FindingView
	// Key is the grouping key that produced this draft (a deployment source
	// where known, else the repository), surfaced for explainability.
	Key string
	// Priority is the highest assessment priority across the findings covered, so
	// the ticket can be raised at a matching Jira priority rather than a fixed one.
	Priority string
	// Upgrades are the version moves this draft asks for, carried so reconciliation
	// can tell whether an existing ticket's target has moved on.
	Upgrades []ImageUpgrade
	// Route names the routing rule that chose this draft's tracker, or
	// "(default)" for the top-level settings. Carried so a dry run says where a
	// ticket would land, which is the question routing creates.
	Route string
}

// Skip records a finding that will not be ticketed, and why. Skips are reported
// rather than silently dropped: "criticals with nowhere to go" is exactly what
// someone should look at by hand.
type Skip struct {
	Image  string
	Reason string
	// Policy is true when configuration chose not to ticket this — an exclusion, a
	// priority threshold, no matching route. The work still exists.
	//
	// The distinction is load-bearing for reconciliation. A finding that leaves the
	// queue because it was fixed and one that leaves because we decided not to track
	// it look identical from the drafts, and an existing ticket for the second must
	// not be told the work appears done. Changing a threshold would otherwise mark
	// every ticket it newly excludes as finished.
	Policy bool
}

// Plan is the outcome of planning: what to raise, and what was left out.
type Plan struct {
	Drafts []Draft
	Skips  []Skip
}

// Planner renders drafts from findings according to the Jira config.
type Planner struct {
	cfg config.JiraConfig
	// tmpls holds one parsed template per route name, so a team can word its own
	// tickets. Every route has an entry, falling back to the base template.
	tmpls    map[string]*template.Template
	routes   *routes
	tmpl     *template.Template
	excluded *exclusions
}

// NewPlanner loads and parses the configured ticket template.
func NewPlanner(cfg config.JiraConfig) (*Planner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(cfg.Template)
	if err != nil {
		return nil, fmt.Errorf("read ticket template %s: %w", cfg.Template, err)
	}
	tmpl, err := template.New("ticket").Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse ticket template %s: %w", cfg.Template, err)
	}
	routed, err := newRoutes(cfg.Routes)
	if err != nil {
		return nil, err
	}
	// Parse every route's template up front. A template that does not parse is a
	// configuration error, and finding that out on the first ticket of the month
	// for one team is far worse than finding out at startup.
	tmpls := map[string]*template.Template{routeName: tmpl}
	for _, r := range cfg.Routes {
		if r.Template == "" || r.Template == cfg.Template {
			tmpls[r.Name] = tmpl
			continue
		}
		raw, err := os.ReadFile(r.Template)
		if err != nil {
			return nil, fmt.Errorf("read ticket template %s for route %q: %w", r.Template, r.Name, err)
		}
		t, err := template.New("ticket").Parse(string(raw))
		if err != nil {
			return nil, fmt.Errorf("parse ticket template %s for route %q: %w", r.Template, r.Name, err)
		}
		tmpls[r.Name] = t
	}

	excluded, err := newExclusions(cfg.Exclude)
	if err != nil {
		return nil, err
	}
	return &Planner{cfg: cfg, tmpl: tmpl, tmpls: tmpls, routes: routed, excluded: excluded}, nil
}

// Plan decides which findings become tickets, groups them, and renders each.
//
// Only actionable, unsuppressed findings are considered: a suppressed finding is
// one policy has already decided not to act on, and ticketing it would undo that
// decision.
func (p *Planner) Plan(findings []sink.FindingView) (*Plan, error) {
	out := &Plan{}

	var eligible []sink.FindingView
	for _, f := range findings {
		if !f.Actionable || f.Suppressed {
			continue
		}
		// Exclusions first: an excluded finding is out of scope here regardless of
		// whether it has an upgrade, and reporting it as "nothing to upgrade to"
		// would be the wrong explanation.
		name, why, excluded, err := p.excluded.match(f)
		if err != nil {
			return nil, err
		}
		if excluded {
			reason := fmt.Sprintf("excluded by rule %q", name)
			if why != "" {
				reason += ": " + why
			}
			out.Skips = append(out.Skips, Skip{Image: f.Image, Reason: reason, Policy: true})
			continue
		}
		if reason, ok := p.skipReason(f); ok {
			out.Skips = append(out.Skips, Skip{Image: f.Image, Reason: reason})
			continue
		}
		// With requireRoute, an unrouted finding is reported rather than sent to
		// the default tracker. Reported, not dropped: the work still exists and
		// still needs a home, and silence here would read as "nothing to do".
		if p.cfg.RequireRoute && p.routes.match(f) == routeName {
			owner := "unattributed"
			if f.Owner.Class != "" || f.Owner.Team != "" {
				owner = strings.TrimSpace(f.Owner.Class + "/" + f.Owner.Team)
			}
			out.Skips = append(out.Skips, Skip{
				Image: f.Image, Policy: true,
				Reason: fmt.Sprintf("no ticket route matches its owner (%s) and requireRoute is set, "+
					"so no tracker is configured for this work", owner),
			})
			continue
		}
		eligible = append(eligible, f)
	}

	// Group within a route, never across one. Two findings that share an upgrade
	// still need two tickets when they belong to different teams' trackers: one
	// issue cannot exist in two projects, and merging them would silently move
	// one team's work onto another team's board.
	for _, name := range p.routeOrder(eligible) {
		for _, g := range mergeChains(group(byRoute(eligible, p.routes, name))) {
			d, err := p.render(g, name)
			if err != nil {
				return nil, err
			}
			// Judged on the draft rather than on each finding, so a low-priority image
			// that shares an upgrade with an urgent one still rides along: one change,
			// one ticket. Filtering findings before grouping would split that change
			// in two and send half of it nowhere.
			if cfg := p.routeConfig(name); !cfg.TicketsPriority(d.Priority) {
				for _, img := range d.Images {
					out.Skips = append(out.Skips, Skip{
						Image: img, Policy: true,
						Reason: fmt.Sprintf("highest priority in this change is %q, below the "+
							"minimum ticket priority %q; it stays in the queue",
							dashIfEmpty(d.Priority), cfg.MinPriority),
					})
				}
				continue
			}
			out.Drafts = append(out.Drafts, d)
		}
	}
	return out, nil
}

// routeConfig resolves the settings for a route name, so a per-team threshold is
// honoured rather than only the top-level one.
func (p *Planner) routeConfig(name string) config.JiraConfig {
	for _, r := range p.cfg.Routes {
		if r.Name == name {
			return p.cfg.Resolve(r)
		}
	}
	return p.cfg
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// routeOrder returns the route names present in these findings, in configuration
// order with the default last, so output is deterministic rather than following
// map iteration.
func (p *Planner) routeOrder(findings []sink.FindingView) []string {
	present := map[string]bool{}
	for _, f := range findings {
		present[p.routes.match(f)] = true
	}
	var out []string
	for _, r := range p.cfg.Routes {
		if present[r.Name] {
			out = append(out, r.Name)
		}
	}
	if present[routeName] {
		out = append(out, routeName)
	}
	return out
}

// byRoute returns the findings routed to name.
func byRoute(findings []sink.FindingView, r *routes, name string) []sink.FindingView {
	out := make([]sink.FindingView, 0, len(findings))
	for _, f := range findings {
		if r.match(f) == name {
			out = append(out, f)
		}
	}
	return out
}

// Config exposes the ticket configuration, including its routes, so callers can
// resolve per-project decisions without keeping a second copy of it.
func (p *Planner) Config() config.JiraConfig { return p.cfg }

// skipReason reports why a finding should not be ticketed, if it should not.
//
// The distinction between "on the latest version" and "we could not resolve the
// versions" matters here more than anywhere else: skipping the first is correct,
// while silently skipping the second would mean never raising a ticket for an
// image whose registry we simply cannot read, and never learning that.
func (p *Planner) skipReason(f sink.FindingView) (string, bool) {
	if !p.cfg.EffectiveRequireUpgrade() {
		return "", false
	}
	switch {
	case f.Upgrade == nil && !f.RemediationChecked:
		return "upgrade detection did not run (no --remediation), so it is unknown whether a fix exists", true
	case f.Upgrade == nil:
		return "upgrade detection ran but could not resolve any version for this image (needs investigation, not a ticket)", true
	case !f.Upgrade.Resolved:
		return "available versions could not be resolved (e.g. private registry tags unreadable), so 'no upgrade' is unproven", true
	case !f.Upgrade.Available:
		return "already on the latest available version; nothing to upgrade to", true
	}
	return "", false
}

// ticketGroup is one ticket's worth of findings: the upgrade(s) someone applies,
// and the images that bump updates as a consequence.
type ticketGroup struct {
	// primary are the findings whose versions are actually changed.
	primary []sink.FindingView
	// dependents are findings fixed by changing primary, listed for context but
	// not as work. Empty for an ordinary ticket.
	dependents []sink.FindingView
}

// all returns every finding on the ticket, primary first.
func (g ticketGroup) all() []sink.FindingView {
	return append(append([]sink.FindingView{}, g.primary...), g.dependents...)
}

// mergeChains folds a group of managed images into the ticket for the component
// that manages them, when that component is itself in the finding set.
//
// Six Flux controllers are owned by flux-operator, whose own tag is owned by its
// Helm chart. Left alone that is two tickets, neither actionable: one asking for
// six bumps nobody applies directly, and one for the operator image. The only
// change a human can make is to the operator's chart, so that is what the ticket
// should ask for, with the six controllers listed as what it fixes.
//
// Matching is by name: a managed group whose source is a bare component name
// ("flux-operator") folds into the group holding an image whose repository ends
// in that name. Deliberately narrow — sources that are object references or URLs
// are left alone, because inferring a manager from them would mean guessing (a
// "Kiali" custom resource does not tell us its operator is called
// kiali-operator), and a wrong merge writes a ticket that asks for the wrong
// change.
func mergeChains(groups []ticketGroup) []ticketGroup {
	// Where each component name lives, by group index.
	owner := map[string]int{}
	for i, g := range groups {
		for _, f := range g.primary {
			owner[lastSegment(f.Repository)] = i
		}
	}

	merged := make([]bool, len(groups))
	for i, g := range groups {
		name := managedBy(g.primary)
		if name == "" {
			continue
		}
		target, ok := owner[name]
		if !ok || target == i || merged[target] {
			continue
		}
		groups[target].dependents = append(groups[target].dependents, g.primary...)
		merged[i] = true
	}

	out := make([]ticketGroup, 0, len(groups))
	for i, g := range groups {
		if !merged[i] {
			out = append(out, g)
		}
	}
	return out
}

// managedBy returns the component that owns every finding's version in the
// group, or "" when there is not exactly one. It reads the Manager the live
// source resolved rather than inferring anything from a source string.
func managedBy(findings []sink.FindingView) string {
	name := ""
	for _, f := range findings {
		u := f.Upgrade
		if u == nil || u.Manager == "" {
			return ""
		}
		if name != "" && u.Manager != name {
			return ""
		}
		name = u.Manager
	}
	return name
}

// group collects findings that a single change would fix. Findings sharing a
// deployment source (a chart, a GitOps path) are fixed by one edit, so they
// belong on one ticket; anything else stands alone. Keys are sorted so output is
// stable across runs.
func group(findings []sink.FindingView) []ticketGroup {
	byKey := map[string][]sink.FindingView{}
	for _, f := range findings {
		byKey[groupKey(f)] = append(byKey[groupKey(f)], f)
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]ticketGroup, 0, len(keys))
	for _, k := range keys {
		g := byKey[k]
		sort.Slice(g, func(i, j int) bool { return g[i].Image < g[j].Image })
		out = append(out, ticketGroup{primary: g})
	}
	return out
}

func groupKey(f sink.FindingView) string {
	if f.Upgrade == nil {
		return f.Repository
	}
	// A managed workload's version lives with its manager, so everything under one
	// manager is one change. This also keeps controller sets together now that the
	// manager name is no longer stuffed into Source.
	if f.Upgrade.Manager != "" {
		return f.Upgrade.Manager
	}
	// A base-image upgrade is one repository rebuilt onto a newer base. Grouping by
	// the base alone put every application sharing that base on one ticket — two
	// teams, one ticket, and no single person able to finish it. Grouping by
	// repository puts every tag of one application together instead, which is the
	// promotion path through environments: one change, released forward.
	if f.Upgrade.Kind == "base" {
		return f.Repository + " on " + f.Upgrade.Name
	}
	if f.Upgrade.Source == "" {
		return f.Repository
	}
	key := collapseObjectRef(f.Upgrade.Source)
	// The path is part of the identity: two Kustomizations in one repo are two
	// separate changes, so they must not collapse into one ticket.
	if f.Upgrade.SourcePath != "" {
		key += " " + f.Upgrade.SourcePath
	}
	return key
}

// collapseObjectRef reduces a Kubernetes object reference ("Kind/namespace/name")
// to "Kind/namespace".
//
// Some controllers give each managed package its own object, so the source is
// unique per package: every Crossplane provider has its own ProviderRevision.
// Grouping on the raw source would then produce one ticket per package, which is
// literally correct and practically useless, since they live in one place and get
// bumped in one sitting. Anything that is not an object reference (a chart repo
// URL, a GitOps path, a bare name) is returned unchanged.
func collapseObjectRef(source string) string {
	if strings.Contains(source, "://") {
		return source
	}
	parts := strings.Split(source, "/")
	if len(parts) != 3 {
		return source
	}
	// A Kubernetes Kind is UpperCamelCase, which is what separates
	// "ProviderRevision/ns/name" from a registry path like "ghcr.io/org/image".
	if kind := parts[0]; kind == "" || kind[0] < 'A' || kind[0] > 'Z' {
		return source
	}
	return parts[0] + "/" + parts[1]
}

// render executes the template for one ticket group.
func (p *Planner) render(group ticketGroup, route string) (Draft, error) {
	data := newTemplateData(group)
	tmpl := p.tmpls[route]
	if tmpl == nil {
		tmpl = p.tmpl
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return Draft{}, fmt.Errorf("render ticket template for %s: %w", data.ServiceName, err)
	}
	summary, description, err := splitSummary(buf.String())
	if err != nil {
		return Draft{}, fmt.Errorf("ticket template for %s: %w", data.ServiceName, err)
	}
	return Draft{
		Summary:     summary,
		Description: description,
		Priority:    data.Priority,
		Upgrades:    data.Upgrades,
		Images:      data.Images,
		Findings:    group.all(),
		Key:         groupKey(group.primary[0]),
		Route:       route,
	}, nil
}

// splitSummary separates the rendered "Summary: ..." first line from the
// description body. Keeping both in one file means the wording of a ticket lives
// in one place rather than split across a template and a config string.
func splitSummary(rendered string) (summary, description string, err error) {
	trimmed := strings.TrimLeft(rendered, "\r\n \t")
	line, rest, found := strings.Cut(trimmed, "\n")
	if !found {
		return "", "", fmt.Errorf("template produced no description: expected %q on the first line, then a blank line, then the body", "Summary: ...")
	}
	const prefix = "Summary:"
	if !strings.HasPrefix(line, prefix) {
		return "", "", fmt.Errorf("template must start with %q, got %q", prefix+" ...", strings.TrimSpace(line))
	}
	summary = strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if summary == "" {
		return "", "", fmt.Errorf("template produced an empty summary")
	}
	return summary, strings.TrimSpace(rest), nil
}
