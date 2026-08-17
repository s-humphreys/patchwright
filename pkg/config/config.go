// Package config defines patchwright's declarative rule configuration and
// loads it from YAML. Rules are written by users — security and platform
// engineers alike — and interpreted as CEL expressions over the generic model,
// so no organization-specific taxonomy is baked into the tool.
package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// Config is the complete rule set. Ownership rules attribute each occurrence to
// an owner; policy rules (actionable/suppress) decide what to act on.
type Config struct {
	// Owners are evaluated in order against each occurrence; the first whose
	// Match expression is true wins.
	Owners []OwnerRule `yaml:"owners"`
	// Actionable rules mark a finding for action and assign a priority; the
	// first matching rule wins.
	Actionable []PolicyRule `yaml:"actionable"`
	// Suppress rules drop a finding from the actionable set (e.g. accepted
	// risk, known false positive). Suppression takes precedence over
	// actionability.
	Suppress []PolicyRule `yaml:"suppress"`
	// Scan tunes image vulnerability scanning.
	Scan ScanConfig `yaml:"scan"`
	// Remediation tunes how upgrades are detected.
	Remediation RemediationConfig `yaml:"remediation"`
	// Jira configures ticket creation (the `ticket` command). Optional; only
	// validated when that command runs.
	Jira JiraConfig `yaml:"jira"`

	// Sources is the raw text of each file this config was loaded from, in order.
	// Not settable from YAML: it describes the load, not the configuration.
	Sources []Source `yaml:"-"`
}

// RemediationConfig tunes upgrade detection.
type RemediationConfig struct {
	// FirstPartyRegistries name the registries whose images you build yourself.
	//
	// For those, a newer image tag is a release number rather than a fix: the tags
	// are your versioning scheme, and the vulnerabilities are almost always in the
	// base image. Naming them here stops a tag bump being reported as remediation
	// and turns on base-image detection instead.
	//
	// Empty means every image is treated as third-party, which is the right default
	// for a deployment that only runs other people's images.
	FirstPartyRegistries []string `yaml:"firstPartyRegistries"`

	// Base tunes how a first-party image's base is found.
	Base BaseImageConfig `yaml:"base"`
}

// BaseImageConfig describes where an image records its base, and how far to follow
// the chain.
//
// Configuration rather than constants because the conventions differ: the OCI
// standard keys are what a spec-compliant builder writes, BuildKit and various CI
// systems write their own, and some organisations set a label by hand. Naming them
// is a two-line config change; guessing wrongly is a silent wrong answer.
type BaseImageConfig struct {
	// RefLabels are the image config labels that may hold the base reference, in
	// preference order. Defaults to the OCI standard key followed by BuildKit's.
	RefLabels []string `yaml:"refLabels"`
	// DigestLabels hold the digest of the base that was actually built against.
	// Used where the base reference is a floating tag, so "is it current" is a
	// digest comparison rather than a version comparison.
	DigestLabels []string `yaml:"digestLabels"`
	// MaxDepth bounds how far a chain of first-party bases is followed — an image
	// on a language base which is itself built on a runtime base. Defaults to 4.
	// The walk always stops at the first base that is not first-party.
	MaxDepth int `yaml:"maxDepth"`
}

// Default label keys. The OCI standard first, then BuildKit's, which is what
// buildx writes today and is far more common in the wild than the standard one.
var (
	defaultBaseRefLabels    = []string{"org.opencontainers.image.base.name", "image.base.ref.name"}
	defaultBaseDigestLabels = []string{"org.opencontainers.image.base.digest", "image.base.digest"}
)

// EffectiveRefLabels returns the configured keys, or the defaults.
func (b BaseImageConfig) EffectiveRefLabels() []string {
	if len(b.RefLabels) > 0 {
		return b.RefLabels
	}
	return defaultBaseRefLabels
}

// EffectiveDigestLabels returns the configured keys, or the defaults.
func (b BaseImageConfig) EffectiveDigestLabels() []string {
	if len(b.DigestLabels) > 0 {
		return b.DigestLabels
	}
	return defaultBaseDigestLabels
}

// EffectiveMaxDepth returns the configured chain depth, or 4.
func (b BaseImageConfig) EffectiveMaxDepth() int {
	if b.MaxDepth > 0 {
		return b.MaxDepth
	}
	return 4
}

// IsFirstParty reports whether an image registry is one you build into.
func (r RemediationConfig) IsFirstParty(registry string) bool {
	for _, reg := range r.FirstPartyRegistries {
		if strings.EqualFold(strings.TrimSpace(reg), registry) {
			return true
		}
	}
	return false
}

// JiraConfig describes where tickets go and what they look like. Everything
// organization-specific (project, issue type, the custom field holding the
// image) is configuration, so no Jira schema is baked into the tool.
type JiraConfig struct {
	// Board is the board id tickets are raised against. Required.
	Board int `yaml:"board"`
	// Project key, e.g. "PROJ". Required.
	Project string `yaml:"project"`
	// Template is a path to the ticket template (Go text/template). Its first
	// line must be "Summary: ...", then a blank line, then the description.
	// Required.
	Template string `yaml:"template"`

	// ImageField is a custom field id (e.g. "customfield_12345") holding the
	// image repositories a ticket covers. It doubles as the idempotency key: it
	// is how an existing ticket for an image is found without local state.
	// Exactly one of ImageField or ImageLabel is required.
	ImageField string `yaml:"imageField"`
	// ImageLabel puts the images in labels instead, for projects with no such
	// custom field. Labels are always JQL-queryable, so this is the fallback
	// when a team-managed project will not filter on cf[NNNNN].
	ImageLabel bool `yaml:"imageLabel"`

	// Epic, when set, becomes each ticket's parent.
	Epic string `yaml:"epic"`
	// IssueType defaults to "Task".
	IssueType string `yaml:"issueType"`
	// Priority is the Jira priority name used when PriorityMap has nothing for a
	// finding, e.g. "Highest". Left to Jira's default when empty.
	Priority string `yaml:"priority"`
	// PriorityMap translates a finding's priority into a Jira priority name, so
	// the assessment's ordering survives into the tracker. Without it every ticket
	// gets the same Priority, which flattens the queue: an urgent, exploited,
	// fixable finding and a low one become indistinguishable the moment they
	// become tickets.
	//
	// Deliberately not defaulted. Priority schemes are per-instance, and guessing
	// names that do not exist would fail ticket creation with a Jira field error;
	// see config/policy.yaml for a worked example.
	PriorityMap map[string]string `yaml:"priorityMap"`
	// Labels are added to every ticket, alongside any image labels.
	Labels []string `yaml:"labels"`

	// Exclude lists CEL rules for findings that should not be ticketed here.
	//
	// Distinct from policy suppression: a suppressed finding is one nobody should
	// act on and it leaves the assessment entirely, whereas an excluded one is
	// real work simply tracked elsewhere (a team with its own upgrade cadence, a
	// component under a different process). It stays in the report and the queue
	// and is listed as skipped, so excluding something never hides it.
	Exclude []ExcludeRule `yaml:"exclude"`

	// Routes send findings to different projects, boards or issue types based on
	// who owns them, so one deployment can serve teams that do not share a
	// tracker. The first matching route wins; findings matching none use the
	// settings above.
	//
	// A route sets only what differs. Everything it leaves empty falls through to
	// the top-level configuration, so adding a team's board does not mean
	// restating the template, the image field and the priority map.
	Routes []TicketRoute `yaml:"routes"`

	// AutoClose, when true, lets reconciliation close a ticket whose work is
	// provably finished: every image it covers is present in the assessment, was
	// checked for remediation, and is already on the latest available version,
	// with live reconciliation having run so "everywhere" is a checked claim.
	//
	// Off by default, and deliberately narrow. Closing on the *absence* of a
	// finding would retire real work whenever a provider stopped assessing an
	// image, which is why that path only ever comments. This closes on positive
	// evidence instead. Without the evidence, or without this flag, the ticket is
	// commented on and left for a human.
	AutoClose bool `yaml:"autoClose"`
	// CloseTransition names the workflow transition to use, e.g. "Done" or
	// "Won't Do". Empty means the first available transition into a done status
	// category, which is right for simple workflows and wrong for boards with
	// several ways to finish — name it explicitly there.
	CloseTransition string `yaml:"closeTransition"`
	// CloseTransitionUnworked is used when the work landed without anyone picking
	// the ticket up, and CloseTransition is not available from where the ticket
	// sits, e.g. "Won't Do" on a board whose Done transition is only reachable
	// once a ticket has been refined and started.
	//
	// Restricted to unworked tickets on purpose. Nobody actioned this one — the
	// upgrade arrived by another route — so recording it as not-done is accurate.
	// Applying the same status to a ticket someone worked would misrepresent their
	// work, so that case still fails loudly rather than settling for the nearest
	// available transition.
	CloseTransitionUnworked string `yaml:"closeTransitionUnworked"`
	// ClosePriorityUnworked is the priority to set when closing via the unworked
	// transition, e.g. "Unprioritised" or "Lowest". Empty leaves priority alone.
	//
	// A ticket closed as not-worked that keeps its original priority still shows up
	// in every "highest priority open work" filter and report until someone notices
	// it is closed. Clearing the priority is part of the same statement: nobody
	// actioned this, and nobody needs to.
	//
	// Applied only on the unworked path. Work somebody completed keeps the priority
	// it was triaged at, since that is a record of how urgent it was.
	ClosePriorityUnworked string `yaml:"closePriorityUnworked"`

	// MinPriority is the lowest assessment priority worth a ticket: "high" raises
	// urgent and high findings and leaves the rest in the queue. Empty means every
	// actionable finding is ticketed.
	//
	// The queue and the tracker answer different questions. A queue can hold a
	// hundred low-priority findings usefully; a tracker holding a hundred tickets
	// nobody will action this quarter is a tracker people stop reading, and it takes
	// the urgent ones down with it.
	//
	// Findings below the threshold are reported as skipped with the reason, so this
	// decides what gets a ticket, never what is visible.
	MinPriority string `yaml:"minPriority"`

	// RequireRoute, when true, means a finding that matches no route gets no
	// ticket rather than falling through to the settings above.
	//
	// Worth being explicit about, because the two behaviours are both defensible
	// and the wrong one is silent. Fall-through suits a single shared board.
	// RequireRoute suits a deployment where every tracker is named on purpose:
	// coverage arriving for a team nobody has routed yet then produces reported
	// skips rather than tickets on whichever board happens to be the default.
	//
	// Skipped findings are still reported with the reason, and still appear in the
	// assessment and the queue. This decides where work is tracked, never whether
	// it is visible.
	RequireRoute bool `yaml:"requireRoute"`

	// RequireUpgrade, when unset, defaults to true: no ticket is raised for a
	// finding with nothing to upgrade to. A ticket saying "upgrade to the latest
	// version" for an image already on the latest wastes the assignee's time,
	// which is how a vulnerability queue loses credibility.
	RequireUpgrade *bool `yaml:"requireUpgrade"`
}

// isSet reports whether a config file actually defined a jira section, so an
// empty one does not clobber a section defined in an earlier file.
func (j JiraConfig) isSet() bool {
	return j.Board != 0 || j.Project != "" || j.Template != "" ||
		j.ImageField != "" || j.ImageLabel || j.Epic != "" || j.IssueType != "" ||
		j.Priority != "" || len(j.Labels) > 0 || j.RequireUpgrade != nil ||
		len(j.Exclude) > 0 || len(j.PriorityMap) > 0
}

// EffectiveRequireUpgrade reports whether findings with no available upgrade
// should be skipped. Defaults to true when unset.
func (j JiraConfig) EffectiveRequireUpgrade() bool {
	return j.RequireUpgrade == nil || *j.RequireUpgrade
}

// EffectiveIssueType returns the configured issue type, or "Task".
func (j JiraConfig) EffectiveIssueType() string {
	if j.IssueType == "" {
		return "Task"
	}
	return j.IssueType
}

// JiraPriority maps a finding's priority to a Jira priority name, falling back to
// the configured default. Returns "" to leave Jira's own default in place.
func (j JiraConfig) JiraPriority(findingPriority string) string {
	if v, ok := j.PriorityMap[findingPriority]; ok && v != "" {
		return v
	}
	return j.Priority
}

// Validate checks the Jira config is usable. Called by the ticket command
// rather than at load time, so an assess-only config need not define it.
func (j JiraConfig) Validate() error {
	var missing []string
	if j.Board == 0 {
		missing = append(missing, "board")
	}
	if j.Project == "" {
		missing = append(missing, "project")
	}
	if j.Template == "" {
		missing = append(missing, "template")
	}
	if len(missing) > 0 {
		return fmt.Errorf("jira config missing required field(s): %s", strings.Join(missing, ", "))
	}
	if j.ImageField == "" && !j.ImageLabel {
		return fmt.Errorf("jira config needs imageField or imageLabel: without one there is no way to find an existing ticket for an image, so every run would raise duplicates")
	}
	if j.ImageField != "" && j.ImageLabel {
		return fmt.Errorf("jira config sets both imageField and imageLabel; pick one so the idempotency key is unambiguous")
	}
	// Every route is validated as the configuration it actually becomes. A route
	// is a merge, so it can only break the result by overriding something into an
	// invalid combination, and that has to fail at load rather than at the first
	// ticket it tries to raise.
	if err := validateMinPriority(j.MinPriority); err != nil {
		return err
	}
	names := map[string]bool{}
	for i, r := range j.Routes {
		switch {
		case r.Name == "":
			return fmt.Errorf("jira route %d: missing name", i)
		case r.When == "":
			return fmt.Errorf("jira route %q: missing when", r.Name)
		case names[r.Name]:
			return fmt.Errorf("jira route %q: duplicate name", r.Name)
		}
		names[r.Name] = true
		resolved := j.Resolve(r)
		if err := resolved.Validate(); err != nil {
			return fmt.Errorf("jira route %q: %w", r.Name, err)
		}
	}
	return nil
}

// validateMinPriority rejects a threshold that is not on the ranked ladder.
//
// An unranked label ranks below everything, so a typo would quietly raise tickets for
// every finding — the opposite of what the setting is for, with nothing to notice.
func validateMinPriority(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil
	}
	if model.PriorityRank(p) == 0 {
		return fmt.Errorf("jira minPriority %q is not a ranked priority (want one of urgent, high, medium, low)", p)
	}
	return nil
}

// TicketsPriority reports whether a finding at this priority clears the threshold.
func (j JiraConfig) TicketsPriority(priority string) bool {
	min := strings.TrimSpace(j.MinPriority)
	if min == "" {
		return true
	}
	return model.PriorityRank(priority) >= model.PriorityRank(min)
}

// TicketRoute overrides ticket settings for the findings it matches.
//
// Only routing-relevant settings are overridable. Notably absent is Exclude:
// exclusions decide whether work is tracked at all, which is a policy question
// for the whole deployment rather than something a route should quietly change.
type TicketRoute struct {
	// Name identifies the route in logs and dry runs. Required.
	Name string `yaml:"name"`
	// When is a CEL expression over the same variables as policy rules, e.g.
	// "owner['team'] == 'sre'" or "owner['class'] == 'platform'". Required.
	When string `yaml:"when"`

	// Everything below overrides the top-level setting of the same name when
	// non-empty. Pointer and slice types distinguish "not set" from "set empty".
	Board int `yaml:"board"`
	// AutoClose and CloseTransition are per-route because both are properties of
	// the tracker, not of the deployment: one team may want closing automated and
	// another may not, and a transition named "Done" in one project says nothing
	// about another project's workflow.
	AutoClose               *bool  `yaml:"autoClose"`
	CloseTransition         string `yaml:"closeTransition"`
	CloseTransitionUnworked string `yaml:"closeTransitionUnworked"`
	ClosePriorityUnworked   string `yaml:"closePriorityUnworked"`
	MinPriority             string `yaml:"minPriority"`

	Project     string            `yaml:"project"`
	Template    string            `yaml:"template"`
	ImageField  string            `yaml:"imageField"`
	ImageLabel  *bool             `yaml:"imageLabel"`
	Epic        string            `yaml:"epic"`
	IssueType   string            `yaml:"issueType"`
	Priority    string            `yaml:"priority"`
	PriorityMap map[string]string `yaml:"priorityMap"`
	Labels      []string          `yaml:"labels"`
}

// Resolve returns the configuration for a route: the base with this route's
// overrides applied. The zero route returns the base unchanged, so the
// unrouted path and the routed path run through identical code.
func (c JiraConfig) Resolve(r TicketRoute) JiraConfig {
	out := c
	// Routes are a routing concern, not a policy one: the resolved config must
	// never carry a route's own nested routes.
	out.Routes = nil
	if r.Board != 0 {
		out.Board = r.Board
	}
	if r.AutoClose != nil {
		out.AutoClose = *r.AutoClose
	}
	if r.CloseTransition != "" {
		out.CloseTransition = r.CloseTransition
	}
	if r.CloseTransitionUnworked != "" {
		out.CloseTransitionUnworked = r.CloseTransitionUnworked
	}
	if r.ClosePriorityUnworked != "" {
		out.ClosePriorityUnworked = r.ClosePriorityUnworked
	}
	if r.MinPriority != "" {
		out.MinPriority = r.MinPriority
	}
	if r.Project != "" {
		out.Project = r.Project
	}
	if r.Template != "" {
		out.Template = r.Template
	}
	if r.ImageField != "" {
		out.ImageField = r.ImageField
		// A route naming a custom field means that field, not labels, even when
		// the base uses labels; otherwise the field would be written and the
		// lookup would still search labels, and no ticket would ever be found.
		out.ImageLabel = false
	}
	if r.ImageLabel != nil {
		out.ImageLabel = *r.ImageLabel
		if *r.ImageLabel {
			out.ImageField = ""
		}
	}
	if r.Epic != "" {
		out.Epic = r.Epic
	}
	if r.IssueType != "" {
		out.IssueType = r.IssueType
	}
	if r.Priority != "" {
		out.Priority = r.Priority
	}
	if len(r.PriorityMap) > 0 {
		out.PriorityMap = r.PriorityMap
	}
	if len(r.Labels) > 0 {
		out.Labels = r.Labels
	}
	return out
}

// ForProject returns the configuration governing a project: the route that writes
// there, or the base settings.
//
// Used for decisions about tickets that already exist, where the project is known
// from the issue key but the route that created it may since have been renamed or
// removed. Resolving by project rather than by route name means those tickets are
// still governed by the settings of the board they are actually on.
func (c JiraConfig) ForProject(project string) JiraConfig {
	if project == "" {
		return c
	}
	for _, r := range c.Routes {
		if resolved := c.Resolve(r); resolved.Project == project {
			return resolved
		}
	}
	return c
}

// Projects returns every distinct project this configuration can write to, base
// first. Reconciliation has to search all of them: a ticket that moved to
// another team's project is still an open ticket, and missing it would raise a
// duplicate.
func (c JiraConfig) Projects() []string {
	seen := map[string]bool{c.Project: true}
	out := []string{c.Project}
	for _, r := range c.Routes {
		if r.Project != "" && !seen[r.Project] {
			seen[r.Project] = true
			out = append(out, r.Project)
		}
	}
	return out
}

// ExcludeRule keeps matching findings out of ticket creation. When is a CEL
// boolean over the same variables as policy rules (image, counts, owner,
// dimensions, labels, vulns, ...), so one expression language covers both.
// Reason is shown in the skip report, because "why is this not ticketed?" should
// be answerable from the output rather than by reading config.
type ExcludeRule struct {
	Name   string `yaml:"name"`
	When   string `yaml:"when"`
	Reason string `yaml:"reason"`
}

// ScanConfig tunes which images are worth scanning for vulnerabilities.
type ScanConfig struct {
	// SkipOwnerClasses lists owner classes whose images are not scanned —
	// typically ones you can't remediate and already suppress (e.g.
	// cloud-provider-managed images). An image is skipped only if every one of
	// its workloads is owned by a skipped class.
	//
	// Unset defaults to ["cloud-provider"]; set to [] to scan everything.
	SkipOwnerClasses []string `yaml:"skipOwnerClasses"`

	// SkipRegistries lists image registry hosts whose images are not scanned,
	// regardless of owner — typically private registries you have no pull
	// credentials for locally, where every scan would fail anyway. Matched
	// exactly against the image registry host (e.g. "acme.azurecr.io").
	//
	// Unset means scan every registry.
	SkipRegistries []string `yaml:"skipRegistries"`
}

// EffectiveSkipOwnerClasses returns the configured skip list, or the default
// (["cloud-provider"]) when the field is unset. An explicit empty list scans
// everything.
func (s ScanConfig) EffectiveSkipOwnerClasses() []string {
	if s.SkipOwnerClasses == nil {
		return []string{"cloud-provider"}
	}
	return s.SkipOwnerClasses
}

// OwnerRule attributes a resource to an owner. Match is a CEL boolean over the
// occurrence context (image, dimensions, labels, counts, resource). Team is a
// literal owner; TeamFrom, when set, is a CEL string expression evaluated
// against the same context (e.g. "labels['team']" or "dimensions['namespace']")
// and takes precedence over Team.
type OwnerRule struct {
	Name     string `yaml:"name"`
	Match    string `yaml:"match"`
	Class    string `yaml:"class"`
	Team     string `yaml:"team"`
	TeamFrom string `yaml:"teamFrom"`
}

// PolicyRule is a named CEL boolean over the finding context. Priority is a
// free-form label applied when an actionable rule matches (ignored for
// suppress rules).
type PolicyRule struct {
	Name     string `yaml:"name"`
	When     string `yaml:"when"`
	Priority string `yaml:"priority"`

	// Until is the last date a suppress rule applies, as YYYY-MM-DD. After it, the
	// rule stops matching and the findings it was hiding return to the queue.
	//
	// Accepted risk with no expiry is accepted risk forever: nobody re-reads a
	// config file, so a decision taken for one quarter silently outlives the reason
	// for it. An expiry turns that into a review.
	//
	// Optional, and meaningless on an actionable rule — a priority does not expire —
	// so it is rejected there rather than ignored.
	Until string `yaml:"until"`
}

// untilLayout is the date format for PolicyRule.Until. Date only: an expiry with a
// time of day invites arguments about zones for no benefit.
const untilLayout = "2006-01-02"

// Expiry parses Until, returning the instant the rule stops applying: the end of
// that day in UTC, so a rule expiring today still applies today everywhere.
func (r PolicyRule) Expiry() (time.Time, bool, error) {
	if strings.TrimSpace(r.Until) == "" {
		return time.Time{}, false, nil
	}
	d, err := time.Parse(untilLayout, strings.TrimSpace(r.Until))
	if err != nil {
		return time.Time{}, false, fmt.Errorf("until %q is not a date in YYYY-MM-DD form", r.Until)
	}
	return d.AddDate(0, 0, 1), true, nil
}

// Expired reports whether the rule has lapsed as of now.
func (r PolicyRule) Expired(now time.Time) bool {
	end, ok, err := r.Expiry()
	if err != nil || !ok {
		// An unparseable date is rejected at load, so it cannot reach here; treating
		// it as unexpired is the safe reading either way, since the alternative
		// silently un-suppresses findings because of a typo.
		return false
	}
	return now.After(end)
}

// Source is one config file as loaded: its path and the text that was parsed.
type Source struct {
	Path    string
	Content string
}

// Load reads and merges one or more YAML config files. Later files append to
// earlier ones, so configuration can be split across files (e.g. ownership.yaml
// and policy.yaml).
func Load(paths ...string) (*Config, error) {
	cfg := &Config{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", p, err)
		}
		// Kept so a server can show the rules actually in effect. Re-reading the
		// file later would show whatever is on disk now, which is not the same
		// thing once someone has edited it mid-run.
		cfg.Sources = append(cfg.Sources, Source{Path: p, Content: string(data)})
		var part Config
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&part); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", p, err)
		}
		cfg.Owners = append(cfg.Owners, part.Owners...)
		cfg.Actionable = append(cfg.Actionable, part.Actionable...)
		cfg.Suppress = append(cfg.Suppress, part.Suppress...)
		// scan is a singleton section; for each field, the last file that sets
		// it wins (so the two knobs can live in different files).
		if part.Scan.SkipOwnerClasses != nil {
			cfg.Scan.SkipOwnerClasses = part.Scan.SkipOwnerClasses
		}
		if part.Scan.SkipRegistries != nil {
			cfg.Scan.SkipRegistries = part.Scan.SkipRegistries
		}
		// remediation is a singleton section, merged per field so the knobs can live
		// in different files.
		if part.Remediation.FirstPartyRegistries != nil {
			cfg.Remediation.FirstPartyRegistries = part.Remediation.FirstPartyRegistries
		}
		if part.Remediation.Base.RefLabels != nil {
			cfg.Remediation.Base.RefLabels = part.Remediation.Base.RefLabels
		}
		if part.Remediation.Base.DigestLabels != nil {
			cfg.Remediation.Base.DigestLabels = part.Remediation.Base.DigestLabels
		}
		if part.Remediation.Base.MaxDepth != 0 {
			cfg.Remediation.Base.MaxDepth = part.Remediation.Base.MaxDepth
		}
		// jira is a singleton section; the last file that sets it wins.
		if part.Jira.isSet() {
			cfg.Jira = part.Jira
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	slog.Debug("loaded config", "files", len(paths),
		"owner_rules", len(cfg.Owners), "actionable_rules", len(cfg.Actionable), "suppress_rules", len(cfg.Suppress))
	return cfg, nil
}

// validate checks structural invariants that are independent of CEL
// compilation (which the attribution and policy engines perform).
func (c *Config) validate() error {
	seen := map[string]bool{}
	for _, r := range c.Owners {
		if r.Name == "" {
			return fmt.Errorf("owner rule missing name")
		}
		if r.Match == "" {
			return fmt.Errorf("owner rule %q missing match expression", r.Name)
		}
		if seen["owner/"+r.Name] {
			return fmt.Errorf("duplicate owner rule name %q", r.Name)
		}
		seen["owner/"+r.Name] = true
	}
	for _, r := range c.Actionable {
		if err := validatePolicyRule("actionable", r, seen); err != nil {
			return err
		}
	}
	for _, r := range c.Suppress {
		if err := validatePolicyRule("suppress", r, seen); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyRule(kind string, r PolicyRule, seen map[string]bool) error {
	if r.Name == "" {
		return fmt.Errorf("%s rule missing name", kind)
	}
	if r.When == "" {
		return fmt.Errorf("%s rule %q missing when expression", kind, r.Name)
	}
	key := kind + "/" + r.Name
	if seen[key] {
		return fmt.Errorf("duplicate %s rule name %q", kind, r.Name)
	}
	seen[key] = true
	return nil
}
