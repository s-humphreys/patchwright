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
}

// Skip records a finding that will not be ticketed, and why. Skips are reported
// rather than silently dropped: "criticals with nowhere to go" is exactly what
// someone should look at by hand.
type Skip struct {
	Image  string
	Reason string
}

// Plan is the outcome of planning: what to raise, and what was left out.
type Plan struct {
	Drafts []Draft
	Skips  []Skip
}

// Planner renders drafts from findings according to the Jira config.
type Planner struct {
	cfg      config.JiraConfig
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
	excluded, err := newExclusions(cfg.Exclude)
	if err != nil {
		return nil, err
	}
	return &Planner{cfg: cfg, tmpl: tmpl, excluded: excluded}, nil
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
			out.Skips = append(out.Skips, Skip{Image: f.Image, Reason: reason})
			continue
		}
		if reason, ok := p.skipReason(f); ok {
			out.Skips = append(out.Skips, Skip{Image: f.Image, Reason: reason})
			continue
		}
		eligible = append(eligible, f)
	}

	for _, g := range mergeChains(group(eligible)) {
		d, err := p.render(g)
		if err != nil {
			return nil, err
		}
		out.Drafts = append(out.Drafts, d)
	}
	return out, nil
}

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
func (p *Planner) render(group ticketGroup) (Draft, error) {
	data := newTemplateData(group)
	var buf bytes.Buffer
	if err := p.tmpl.Execute(&buf, data); err != nil {
		return Draft{}, fmt.Errorf("render ticket template for %s: %w", data.ServiceName, err)
	}
	summary, description, err := splitSummary(buf.String())
	if err != nil {
		return Draft{}, fmt.Errorf("ticket template for %s: %w", data.ServiceName, err)
	}
	return Draft{
		Summary:     summary,
		Description: description,
		Images:      data.Images,
		Findings:    group.all(),
		Key:         groupKey(group.primary[0]),
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
