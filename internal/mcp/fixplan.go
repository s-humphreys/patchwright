package mcp

import (
	"fmt"
	"sort"
	"strings"
)

// The answer to the only question most people ask: I have a ticket for this service,
// what do I do?
//
// The same data as service_report, shaped as a decision rather than a dataset. That
// difference is the point. A report hands over clears, leaves, introduces, a remainder
// split and a policy rule, and leaves an engineer to work out which of it is an
// instruction; roughly none of it is, until you know the vocabulary. So this says what to
// change, what not to do and why, what it achieves, and - the part that stops a ticket
// being reopened - which of the remainder was never theirs.
//
// It also says what it cannot answer. Patchwright knows the base image needs changing and
// does not know where the Dockerfile lives: `source_path` is populated on eight findings
// out of six hundred. Naming that gap is more useful than implying the plan is complete.

// FixPlan is one service's work, in the order somebody would do it.
type FixPlan struct {
	Freshness Freshness `json:"freshness"`

	Service string `json:"service"`
	Team    string `json:"team,omitempty"`
	// Why is the verdict and what earned it, in a sentence.
	Why string `json:"why"`

	// Do is the change to make. Absent when there is nothing to move to, in which case
	// Decide says what the situation needs instead.
	Do *FixAction `json:"do,omitempty"`
	// DoNot are the constraints that make the obvious move wrong: a policy ceiling, a
	// dead line, a tag somebody else owns.
	DoNot []string `json:"do_not,omitempty"`
	// Decide is what remains after the change, or instead of it when no change exists.
	// Reported separately from Do because it is somebody's judgement, not their keyboard.
	Decide []string `json:"decide,omitempty"`
	// Result is what the change achieves, for the ticket.
	Result *FixResult `json:"result,omitempty"`
	// AlsoTakes are other services on the same move: doing them together tests the base
	// once rather than once each.
	AlsoTakes []string `json:"also_takes,omitempty"`
	// Exploited names the known-exploited CVEs the service carries when there is no
	// change to make, and so no Result to carry them.
	//
	// Mitigate, isolate or accept is decided one CVE at a time. A decide branch that
	// reports "2 known-exploited" and no identifiers hands somebody a number to worry
	// about rather than a decision they can take, and this is the branch where nothing
	// else names them - a service already on its newest base has no differential to
	// list what an upgrade would clear.
	Exploited []ExploitedCVE `json:"known_exploited,omitempty"`
	// Unknown is what this plan cannot tell you, named rather than left as a silence.
	Unknown []string `json:"unknown,omitempty"`
}

// FixAction is the change itself.
type FixAction struct {
	// Change is the thing to edit, in words: the base image, the chart version, the tag.
	Change string `json:"change"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	// Kind distinguishes a rebuild on the same tag from a version change, because
	// "rebuild" understates a runtime migration to whoever has to do it.
	Kind string `json:"kind,omitempty"`
	// Yours is true when the team that builds the image applies this. When false,
	// AppliedIn names what owns the tag and editing the build would do nothing.
	Yours     bool   `json:"yours"`
	AppliedIn string `json:"applied_in,omitempty"`
	// Repository is the source repository that built the image, from the labels named by
	// remediation.base.repoLabels. This is what turns a plan into something a coding
	// agent can act on: patchwright reads images, not the code that produced them, so
	// without the label there is nothing to point at.
	Repository string `json:"repository,omitempty"`
	// Deployments is how many running deployments the change has to reach.
	Deployments int      `json:"deployments"`
	Where       []string `json:"where,omitempty"`
	// InProgress is a pull request already open for this change.
	InProgress string `json:"in_progress,omitempty"`
}

// FixResult is what the change buys, in the numbers a ticket wants.
type FixResult struct {
	// Clears and Of are distinct CVEs: how many of the service's total this removes.
	Clears int `json:"clears"`
	Of     int `json:"of"`
	// ClearsKnownExploited is the number that justifies doing it now.
	ClearsKnownExploited int `json:"clears_known_exploited"`
	// Introduces is what the new base brings with it. Reported always: a change described
	// only by what it fixes stops being trusted the first time somebody checks.
	Introduces int `json:"introduces"`
	// NotYours is what remains that the team cannot fix, and Why explains it. This is the
	// line that stops the ticket being reopened over a remainder nobody here owns.
	NotYours    int      `json:"not_yours"`
	NotYoursWhy string   `json:"not_yours_why,omitempty"`
	Packages    []string `json:"remaining_packages,omitempty"`
	// StillYours is what the change does not cover and the team does own.
	StillYours int `json:"still_yours"`
	// StillYoursCVEs names them. A count alone tells an engineer there is more to do and
	// an agent nothing it can act on; these are the CVEs to chase in the build itself,
	// once the base change has taken the rest away.
	StillYoursCVEs []ApplicationCVE `json:"still_yours_cves,omitempty"`
	// Verify is what to expect afterwards, in one sentence. An agent that does not know
	// the remainder is expected reads it as the change having failed.
	Verify string `json:"verify,omitempty"`
	// KnownExploited names the exploited CVEs and whether this change deals with each.
	// The list a pull request description wants, and the one to re-check when it lands.
	KnownExploited []ExploitedCVE `json:"known_exploited,omitempty"`
}

// ExploitedCVE is one known-exploited vulnerability and this change's effect on it.
type ExploitedCVE struct {
	ID string `json:"id"`
	// ClearedByThis is true when the change removes it. False means it survives, and the
	// service still carries it afterwards - which is the half a ticket must not silently
	// drop.
	ClearedByThis bool   `json:"cleared_by_this"`
	Severity      string `json:"severity,omitempty"`
	FixedVersion  string `json:"fixed_version,omitempty"`
	Reference     string `json:"reference"`
}

// fixPlan builds the plan for one service, or false when nothing matches.
func fixPlan(a Assessment, name string) (FixPlan, bool) {
	r, ok := serviceReport(a, name)
	if !ok {
		return FixPlan{}, false
	}
	p := FixPlan{
		Freshness: r.Freshness, Service: r.Service, Team: r.Team,
		Why: why(r),
	}

	u := r.Upgrade
	if u == nil || !u.Yours && u.State != "upgrade" {
		// Nothing resolved at all: say so rather than producing an empty plan that reads
		// as "no work".
		if u == nil {
			p.Decide = append(p.Decide, "No upgrade was looked for, so what would fix this is unknown "+
				"rather than nothing. Remediation lookup has to run first.")
			p.Unknown = append(p.Unknown, "whether an upgrade exists")
			p.Exploited = r.knownExploited
			return p, true
		}
	}

	switch u.State {
	case "upgrade":
		p.Do = &FixAction{
			Change: changeWords(u.Kind), From: u.From, To: u.To, Kind: u.Move,
			Yours: u.Yours, AppliedIn: u.AppliedIn, Repository: r.BuildRepo,
			Deployments: len(r.Deployments), Where: places(r),
		}
		if r.InProgress != nil {
			p.Do.InProgress = inProgressWords(r)
		}
	case "held":
		p.Decide = append(p.Decide, fmt.Sprintf(
			"Policy holds this at %s and there is no in-track version to take. Either lift the "+
				"ceiling or accept the finding - it will not clear itself.", u.From))
	case "latest":
		p.Decide = append(p.Decide, fmt.Sprintf(
			"Already on the newest version available (%s), so this is not a bump. The remaining "+
				"CVEs need a decision: wait for upstream, rebuild to pick up a moved tag, or "+
				"accept and record why.", u.From))
	case "unresolved":
		p.Unknown = append(p.Unknown, "what to upgrade to: the lookup could not answer")
	}

	p.DoNot = doNots(u)
	if u.Measured {
		p.Result = fixResult(r, u)
	}
	if p.Result == nil {
		p.Exploited = r.knownExploited
	}
	p.AlsoTakes = alsoTakes(a, r, u)
	p.Unknown = append(p.Unknown, unknowns(r, u)...)
	return p, true
}

func why(r ServiceReport) string {
	parts := []string{}
	if r.Priority != "" {
		verdict := r.Priority
		if r.PriorityWhere != "" {
			verdict += " in " + r.PriorityWhere
		}
		parts = append(parts, verdict)
	}
	if r.Exposure == "public" {
		parts = append(parts, "internet-facing")
	}
	if k := r.Vulnerabilities.KnownExploited; k > 0 {
		parts = append(parts, fmt.Sprintf("%d known-exploited CVEs", k))
	}
	parts = append(parts, fmt.Sprintf("%d vulnerabilities across %d deployments",
		r.Vulnerabilities.Total, len(r.Deployments)))
	out := strings.Join(parts, ", ")
	if r.Rule != "" {
		out += " (rule: " + r.Rule + ")"
	}
	return out
}

// changeWords names the thing to edit rather than the mechanism that found it.
func changeWords(kind string) string {
	switch kind {
	case "base":
		return "the base image this is built on"
	case "chart":
		return "the chart version"
	case "image":
		return "the image tag deployed"
	default:
		return "the version deployed"
	}
}

func places(r ServiceReport) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range r.Deployments {
		for _, acct := range d.Accounts {
			if !seen[acct] {
				seen[acct] = true
				out = append(out, acct)
			}
		}
	}
	sort.Strings(out)
	return out
}

func inProgressWords(r ServiceReport) string {
	p := r.InProgress
	out := p.PullRequest
	switch {
	case p.Stale:
		out += fmt.Sprintf(" (open %d days and stale - work done, not landed)", p.OpenDays)
	case !p.Exact:
		out += " (moves the same dependency to a DIFFERENT version, so it does not close this)"
	default:
		out += fmt.Sprintf(" (open %d days)", p.OpenDays)
	}
	return out
}

// doNots are the constraints that make the obvious move the wrong one.
func doNots(u *UpgradeAdvice) []string {
	var out []string
	if u.Newest != "" && u.Newest != u.To {
		msg := fmt.Sprintf("Do not go to %s, the newest available.", u.Newest)
		switch {
		case u.CeilingReason != "":
			msg += fmt.Sprintf(" Policy holds this line at %s: %q", u.Ceiling, u.CeilingReason)
		case u.Ceiling != "":
			msg += fmt.Sprintf(" Policy holds this line at %s.", u.Ceiling)
		case u.Strategy != "":
			msg += fmt.Sprintf(" The upgrade strategy is %s.", u.Strategy)
		}
		out = append(out, msg)
	}
	if u.CeilingExpired {
		out = append(out, fmt.Sprintf(
			"The ceiling at %s has expired, so it no longer applies - the recommendation above "+
				"is not being held back by it.", u.Ceiling))
	}
	if !u.Yours && u.AppliedIn != "" {
		out = append(out, fmt.Sprintf(
			"Do not edit the build: %s owns this tag, so the change is applied there.", u.AppliedIn))
	}
	if u.OutOfTrack {
		out = append(out, "This leaves the current line because that line is no longer maintained. "+
			"It is a migration to plan, not a bump to take.")
	}
	if strings.Contains(u.Support, "END OF LIFE") {
		out = append(out, "Do not expect further patches on this line: "+u.Support)
	}
	return out
}

func fixResult(r ServiceReport, u *UpgradeAdvice) *FixResult {
	out := &FixResult{
		Clears: u.Clears, Of: r.Vulnerabilities.Total,
		ClearsKnownExploited: u.ClearsKnownExploited,
		Introduces:           u.Introduces,
	}
	if u.Remainder != nil {
		out.NotYours = u.Remainder.StillInBase
		out.StillYours = u.Remainder.FromApplication
		out.StillYoursCVEs = u.Remainder.Application
		if out.NotYours > 0 {
			out.NotYoursWhy = "still present in the new base image, so upstream's to fix rather " +
				"than this team's - an upstream wait, not neglect"
		}
		for _, p := range u.Remainder.Packages {
			out.Packages = append(out.Packages, fmt.Sprintf("%s (%d)", p.Name, p.CVEs))
		}
	}
	out.KnownExploited = u.Exploited
	// What to expect afterwards. Without it a remainder reads as the change not having
	// worked, and somebody either reopens the ticket or goes looking for a second fix
	// that does not exist.
	out.Verify = fmt.Sprintf(
		"After the change this service should report about %d vulnerabilities rather than %d, "+
			"with %d of the %d known-exploited gone. A remainder is expected: %d stay because "+
			"the new base still carries them.",
		out.Of-out.Clears+out.Introduces, out.Of,
		out.ClearsKnownExploited, out.ClearsKnownExploited+u.LeavesKnownExploited, out.NotYours)
	return out
}

// alsoTakes finds the other services this same move fixes. Doing them together tests one
// base once rather than the same base several times.
func alsoTakes(a Assessment, r ServiceReport, u *UpgradeAdvice) []string {
	if u.State != "upgrade" || u.To == "" {
		return nil
	}
	items := a.items()
	// The service's own item, for the upgrade identity the grouping keys on.
	var name, target string
	for _, it := range items {
		if strings.EqualFold(it.Repository, r.Service) && it.Upgrade != nil {
			name, target = it.Upgrade.Name, it.Upgrade.Latest
			break
		}
	}
	if name == "" {
		return nil
	}
	seen := map[string]bool{r.Service: true}
	var out []string
	for _, it := range items {
		if it.Upgrade == nil || seen[it.Repository] {
			continue
		}
		if it.Upgrade.Name == name && it.Upgrade.Latest == target {
			seen[it.Repository] = true
			out = append(out, it.Repository)
		}
	}
	sort.Strings(out)
	if len(out) > maxNamed {
		rest := len(out) - maxNamed
		out = out[:maxNamed]
		out = append(out, fmt.Sprintf("and %d more - see worst_first", rest))
	}
	return out
}

// unknowns names what the plan cannot answer. A silence here reads as completeness.
func unknowns(r ServiceReport, u *UpgradeAdvice) []string {
	var out []string
	// The one an engineer asks first and patchwright cannot answer: it knows the base
	// image to change and not where the build that sets it lives.
	if u.State == "upgrade" && u.Yours && r.BuildRepo == "" {
		out = append(out, "which repository holds the build that sets this: the image records no "+
			"repository label. Patchwright reads images, not the code that produced them, so the "+
			"build has to say - see remediation.base.repoLabels for the keys it looks at")
	}
	if r.InProgress == nil {
		out = append(out, "whether anybody has started: no open pull request was matched, and on "+
			"this estate pull-request matching finds very little, so this is not evidence that "+
			"nobody has")
	}
	if u.Measured && u.DeploymentsMeasured < len(r.Deployments) {
		out = append(out, fmt.Sprintf(
			"what the change clears on %d of %d deployments, whose base could not be scanned",
			len(r.Deployments)-u.DeploymentsMeasured, len(r.Deployments)))
	}
	return out
}
