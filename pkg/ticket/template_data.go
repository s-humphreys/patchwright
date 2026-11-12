package ticket

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/config"
	grouping "github.com/s-humphreys/patchwright/pkg/group"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// TemplateData is what a ticket template can say. It is a deliberately flat,
// documented view rather than the raw finding, so template authors are not
// exposed to internal shapes and the contract is reviewable.
type TemplateData struct {
	// ServiceName is the human name for the thing being upgraded: the chart name
	// for chart upgrades, otherwise the last path segment of the repository.
	ServiceName string
	// Images are the bare repositories covered (no registry, no tag).
	Images []string
	// ImageCount is len(Images), so a summary can be honest about covering more
	// than one image without the template counting.
	ImageCount int
	// GroupNoun names what the grouped items are ("providers", "functions", or
	// the generic "images"), so a summary reads as English rather than as a key.
	GroupNoun string
	// Refs are the full image references, tags included, for the body text.
	Refs []string

	// Upgrade is the single version move this ticket asks for. It is nil when the
	// grouped images do NOT share one target version: a ticket covering six Flux
	// controllers cannot honestly say "upgrade to 1.6.3" when that is one
	// controller's version. Use Upgrades in that case.
	//
	// Kind "package" is a package the images' own build installs or declares, moved
	// to the version that clears what made them actionable: see PackageOnly.
	Upgrade *UpgradeData
	// Upgrades is the version move(s) to APPLY. For a chain-merged ticket this is
	// the managing component only, since bumping it is the whole action. An image
	// the change was measured to leave on its current tag is not listed: a row
	// saying it moves would be the ticket's first false statement.
	Upgrades []ImageUpgrade
	// Fixes are images updated as a consequence of Upgrades, listed for context
	// rather than as work. Empty on an ordinary ticket. A template should not
	// present these as things to bump: nobody can, which is why they were merged
	// into this ticket in the first place.
	Fixes []ImageUpgrade

	// BuildRepos are the repositories that build these images, when the images
	// record one. For a base-image rebuild this is the only actionable location a
	// ticket has: Source names the base being moved onto, which is somebody
	// else's repository and not where the work happens.
	BuildRepos []string

	// Source and SourcePath are the change target shared by everything on this
	// ticket: the repository (or owning custom resource) and the directory within
	// it. They sit at the top level, not under Upgrade, because grouping is BY
	// source — so a grouped ticket has one even when its images move to different
	// versions, and that is precisely the ticket where "where do I make the
	// change?" matters most.
	Source     string
	SourcePath string

	// Deployments are the tags this repository has in flight, ordered by how far
	// through an environment sequence they look: development first, production last.
	//
	// A ticket for an application deployed to three environments on three different
	// tags is one piece of work released forward, not three. Without this the ticket
	// says "upgrade storefront" and leaves the reader to work out that there are three
	// tags and which one moves first.
	Deployments []Deployment

	// Disambiguator is set only when another ticket in the same run renders the
	// same summary: the environments this one covers, or failing that the base it
	// rebuilds onto. Empty otherwise, so a template that uses it stays short for
	// the tickets that have nothing to be confused with.
	//
	// It exists because a template cannot see the other tickets in a run. Two
	// deployments of one service on different bases - production still on 8, dev
	// and prelive already on 10 - are two real pieces of work whose summaries are
	// identical, and a board showing the same line twice reads as a duplicate.
	Disambiguator string

	// DashboardURL deep-links to this work item on the status page, or is empty when
	// no dashboard URL is configured. A template must guard on it: a link to a
	// hostname nobody can reach is worse than no link.
	DashboardURL string

	// Priority is the highest policy priority across the grouped findings.
	Priority string
	// Accounts and Namespaces are the sorted, de-duplicated places this runs.
	Accounts   []string
	Namespaces []string
	// Teams are the attributed owning teams; empty when none could be resolved.
	Teams []string
	// WorkloadCount is the total number of workloads affected.
	WorkloadCount int

	// CriticalCount and HighCount are the provider's counts for the worst single
	// running image on this ticket, by the rule in group.WorstCounts: each severity
	// is the worst any assessed image reports, never a sum across them.
	//
	// They were a sum, and a ticket covering three tags of one service reported
	// roughly three times what any of them carries, since the tags share most of
	// their CVEs. A template saying "the running image carries N critical" then
	// named a number no image had, and disagreed with the queue and the service
	// report, which both use the worst. On a single-image ticket worst and sum are
	// the same number.
	//
	// ProviderAssessed reports whether the provider assessed any of these images at
	// all. When false the counts are zero through ignorance, so a template should
	// not present them as evidence.
	CriticalCount    int
	HighCount        int
	ProviderAssessed bool

	// FixableCriticals are critical CVEs with a fix available, highest EPSS
	// first, so the most exploitable appears at the top of a ticket.
	FixableCriticals []Vuln
	// MaxEPSS is the highest exploitation probability across all CVEs (0..1),
	// and KnownExploited reports CISA KEV membership.
	MaxEPSS        float64
	KnownExploited bool

	// Urgent are the CVEs this ticket's change was measured to clear: exploited in
	// the wild, or with an EPSS at or above the configured threshold, with a fix
	// published. Exploited first, then most likely to be. Each says where it lives
	// and what closes it, in words for somebody who does not know package
	// ecosystems.
	//
	// This is the list a template should call "done means", and only what the
	// change clears is on it. A CVE the change leaves behind, or that nothing
	// measured, is left off entirely: a ticket must never wait on something its
	// own change cannot touch, and listing it would make the ticket's close
	// condition one its assignee cannot meet. Empty when nothing was measured,
	// which says nothing about what the change clears and must not be worded as
	// if it did.
	Urgent []UrgentVuln
	// UrgentCleared is how many of Urgent the ticket's upgrade clears, and
	// UrgentUnknown is zero, now that Urgent holds only what the change clears.
	// Kept so a template written against the earlier contract still renders, and
	// renders only true statements. A rebuild ticket that also lists package moves
	// counts only what the rebuild clears, since an older template words this as
	// what "the rebuild alone" does; on a package-only ticket it is len(Urgent).
	UrgentCleared int
	UrgentUnknown int

	// Packages are the package moves the images' own build has to make: one per
	// package and fixed version, with the actionable CVEs each clears. They sit
	// beside a rebuild that leaves them, or are the whole change on a ticket where
	// PackageOnly is true. Empty when nothing the build adds has a known fix.
	Packages []PackageFix

	// clearsNone is set when the change was measured to clear none of the CVEs
	// that make this group actionable, which means there is no ticket to raise.
	clearsNone bool
	// unmeasured is why the change could not be judged this run, when it could
	// not: a measurement that would have decided it failed. See unmeasured.
	unmeasured string
	// packageOnly is set when the whole change is moving Packages.
	packageOnly bool
	// envs is the release sequence Deployments were placed in, kept to name the
	// positions environmentSpan collects.
	envs []config.Environment
}

// PackageOnly reports a ticket whose change is moving Packages in the images' own
// build and nothing else: no newer base exists, or the one on offer clears none of
// what made them actionable. A template should say a rebuild will not fix it.
func (d TemplateData) PackageOnly() bool { return d.packageOnly }

// SummaryCVEs names the CVEs the package moves clear, for a summary: the first
// three, worst first, and how many more. Reconciliation reads CVE identifiers in
// an open ticket's summary to tell when that work is done, so a template that
// puts this in its summary gets a ticket closed on the CVEs being gone.
func (d TemplateData) SummaryCVEs() string {
	ids := d.buildFixCVEs()
	const shown = 3
	if len(ids) <= shown {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:shown], ", ") + fmt.Sprintf(" and %d more", len(ids)-shown)
}

// buildFixCVEs is every CVE the package moves clear, in Urgent's order where it
// lists them and then in the order of Packages.
func (d TemplateData) buildFixCVEs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, u := range d.Urgent {
		if u.Origin == "app" {
			add(u.ID)
		}
	}
	for _, p := range d.Packages {
		for _, id := range p.CVEs {
			add(id)
		}
	}
	return out
}

// PackageNames are the distinct packages Packages moves, in order. Shorter than
// Packages when one package needs two versions for two CVEs, which a summary
// should still call one package.
func (d TemplateData) PackageNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range d.Packages {
		if !seen[p.Name] {
			seen[p.Name] = true
			out = append(out, p.Name)
		}
	}
	return out
}

// UrgentRemaining is how many of Urgent the ticket clears by moving Packages rather
// than by its upgrade, which is zero except on a rebuild ticket that lists package
// moves beside it. Kept for templates written against the earlier contract.
func (d TemplateData) UrgentRemaining() int {
	return len(d.Urgent) - d.UrgentCleared - d.UrgentUnknown
}

// UrgentAllCleared reports that there is a measured list and the ticket's upgrade
// clears all of it, which is true whenever Urgent is non-empty and no row is
// cleared by moving a package instead. Kept for templates written against the
// earlier contract.
func (d TemplateData) UrgentAllCleared() bool {
	return len(d.Urgent) > 0 && d.UrgentCleared == len(d.Urgent)
}

// Deployment is one tag of a repository and where it runs.
type Deployment struct {
	// Ref is the full image reference, Repo the bare repository and Tag its tag
	// alone. A grouped ticket lists several images, and a table of tags with no
	// repository beside them cannot be read: two of them are often the same
	// version of different things.
	Ref  string
	Repo string
	Tag  string
	// Accounts and Namespaces are where this particular tag runs.
	Accounts   []string
	Namespaces []string
	// Environment is the sequence position guessed from the account and namespace
	// names ("development", "test", "staging", "production", or "" when nothing in
	// them matched). A guess, and labelled as one: it orders the list and must not
	// be read as a fact about the estate.
	//
	// A tag running in several environments is labelled with the LATEST it reaches,
	// so one running in development, pre-production and production reads as
	// "production". It used to be the earliest, which labelled a tag already in
	// production "development": the opposite of what a reader planning a release
	// needs, which is how far this tag has got. The accounts are still carried
	// alongside it, because the label names one environment of a span and the
	// accounts name all of it.
	Environment string

	// reaches is the position of every environment this tag was recognised in, so
	// the span a ticket covers can be stated without being read off the labels,
	// which name only the last of each row.
	reaches []int
}

// searchTerm is what to search the queue for when there is no single service to
// open: the shared change target, most specific part first.
//
// Empty when a service is named (the deep link is better) or when the group has
// no shared target, since a search matching nothing is worse than no search: the
// reader gets an empty queue and no way to tell whether that means "fixed" or
// "the link was wrong".
func (d TemplateData) searchTerm() string {
	if d.Repository() != "" {
		return ""
	}
	if d.SourcePath != "" {
		return d.SourcePath
	}
	return d.Source
}

// Vuln is one CVE as a ticket template sees it.
type Vuln struct {
	ID           string
	Severity     string
	CVSS         float64
	FixedVersion string
	// EPSS is the probability of exploitation in the next 30 days (0..1); KEV
	// marks CISA known-exploited membership. A CVSS 10 at EPSS 0.008 is less
	// urgent than a CVSS 5 at EPSS 0.93, so a ticket should show both.
	EPSS float64
	KEV  bool
}

// ImageUpgrade is one image's version move within a ticket.
type ImageUpgrade struct {
	// Ref is the full image reference, tag included.
	Ref  string
	Repo string
	// Current and Latest are the versions of what moves. For a chart bump they are
	// this image's own tags, not the chart's: Latest is the tag the target chart
	// deploys, and empty when that could not be read from it.
	Current string
	Latest  string
	// LatestFrom says where a chart bump's Latest was read: "values", "appVersion"
	// when values left the tag empty and the target chart's appVersion stands in,
	// or "" when Latest is unknown or not a chart's.
	LatestFrom string
	// LatestRepo is the repository, registry included, the target chart deploys
	// this image from, set only when the bump moves it away from Repo.
	LatestRepo string
	// Chart, ChartCurrent and ChartLatest name the Helm chart whose bump moves this
	// image, and its versions, when a chart owns the image's version. Empty
	// otherwise.
	Chart        string
	ChartCurrent string
	ChartLatest  string
	// Source and SourcePath are this image's own change target. They matter on a
	// grouped ticket whose members each have their own (every Crossplane package
	// has its own ProviderRevision), where a single ticket-level target would name
	// one member and mislead about the rest.
	Source     string
	SourcePath string
	// Managed names the controller owning the version; empty means direct.
	Managed string
	Direct  bool

	// unmoved marks an image the change was measured to leave on its tag.
	unmoved bool
}

// UpgradeData is the version move a ticket asks for.
type UpgradeData struct {
	// Kind is "chart", "image", "base" or "package": the sort of artefact whose
	// version moves.
	Kind    string
	Name    string
	Current string
	Latest  string
	// Managed names the controller that owns the version ("helm", "operator")
	// when the bump is not applied to the image directly. Empty means direct.
	Managed string
	// Source is where to make the change: a repository URL, or the owning custom
	// resource when an operator holds the version.
	Source string
	// SourcePath is the directory within Source, stated separately so Source
	// stays a usable link.
	SourcePath string
	// Direct reports whether this is applied to the image itself.
	Direct bool
}

func newTemplateData(tg ticketGroup, envs []config.Environment, urgentEPSS float64) TemplateData {
	group := tg.all()
	d := TemplateData{}

	d.packageOnly = group[0].Upgrade != nil && group[0].Upgrade.Kind == "package"
	for _, u := range urgent(group, urgentEPSS) {
		if !u.Cleared {
			continue
		}
		d.Urgent = append(d.Urgent, u)
		if d.packageOnly || u.Origin != "app" {
			d.UrgentCleared++
		}
	}
	d.Packages = buildFixes(group, urgentEPSS)
	d.clearsNone = clearsNone(group, urgentEPSS)
	d.unmeasured = unmeasured(group, urgentEPSS)

	d.envs = orDefault(envs)
	d.Deployments = deployments(group, envs)

	accounts, namespaces, teams, buildRepos := &set{}, &set{}, &set{}, &set{}
	images, refs := &set{}, &set{}
	seenCVE := map[string]bool{}

	for _, f := range group {
		images.add(f.Repository)
		refs.add(f.Image)
		for _, a := range f.Dimensions["account"] {
			accounts.add(a)
		}
		for _, n := range f.Dimensions["namespace"] {
			namespaces.add(n)
		}
		if f.Owner.Team != "" {
			teams.add(f.Owner.Team)
		}
		if f.BuildRepo != "" {
			buildRepos.add(f.BuildRepo)
		}
		d.WorkloadCount += f.WorkloadCount
		if f.ProviderAssessed {
			d.ProviderAssessed = true
		}
		if f.KnownExploited {
			d.KnownExploited = true
		}
		if higherPriority(f.Priority, d.Priority) {
			d.Priority = f.Priority
		}
		for _, v := range f.Vulns {
			if v.EPSS > d.MaxEPSS {
				d.MaxEPSS = v.EPSS
			}
			// De-duplicate across grouped findings: the same CVE in a shared base
			// layer would otherwise be listed once per image.
			if v.Severity == "critical" && v.FixAvailable && !seenCVE[v.ID] {
				seenCVE[v.ID] = true
				d.FixableCriticals = append(d.FixableCriticals, Vuln{
					ID: v.ID, Severity: v.Severity, CVSS: v.CVSS,
					FixedVersion: v.FixedVersion, EPSS: v.EPSS, KEV: v.KEV,
				})
			}
		}
	}

	d.CriticalCount, d.HighCount = grouping.WorstCounts(group)
	d.Images, d.Refs = images.sorted(), refs.sorted()
	d.ImageCount = len(d.Images)
	d.Accounts, d.Namespaces, d.Teams = accounts.sorted(), namespaces.sorted(), teams.sorted()
	d.BuildRepos = buildRepos.sorted()

	// Highest EPSS first: a ticket should lead with the CVE most likely to be
	// exploited, not whichever the scanner happened to emit first.
	sort.SliceStable(d.FixableCriticals, func(i, j int) bool {
		if d.FixableCriticals[i].EPSS != d.FixableCriticals[j].EPSS {
			return d.FixableCriticals[i].EPSS > d.FixableCriticals[j].EPSS
		}
		return d.FixableCriticals[i].ID < d.FixableCriticals[j].ID
	})

	d.Upgrades = imageUpgrades(tg.primary)
	d.Fixes = moving(imageUpgrades(tg.dependents))

	// Only claim a single target version when every image in the group actually
	// shares it. Otherwise leave Upgrade nil so a template cannot state one
	// image's version as if it were the ticket's.
	// Only state a ticket-level change target when every image really shares it.
	// Grouping collapses per-object sources into a family, so the members of a
	// collapsed group each have their own; naming the first would misdescribe the
	// rest. Their individual targets are on .Upgrades instead.
	if u := group[0].Upgrade; u != nil && sharesOneSource(d.Upgrades) {
		d.Source, d.SourcePath = u.Source, u.SourcePath
	}
	// An operator-chosen image folded as a managed upgrade has no target tag of its
	// own, so there is no single version for a summary to promise.
	if u := group[0].Upgrade; u != nil && u.Latest != "" && sharesOneTarget(d.Upgrades) {
		d.Upgrade = &UpgradeData{
			Kind: u.Kind, Name: u.Name, Current: u.Current, Latest: u.Latest,
			Managed: u.Managed, Source: u.Source, SourcePath: u.SourcePath,
			Direct: u.Actionable,
		}
	}
	// A package change moves no image, so it has no Upgrades to share a target; it
	// has one version to promise when the whole group moves one package to one.
	if d.packageOnly && len(d.Packages) == 1 {
		p := d.Packages[0]
		d.Upgrade = &UpgradeData{Kind: "package", Name: p.Name, Current: p.Current, Latest: p.Fixed, Direct: true}
	}
	// Filtered only now: whether the group shares one source and one target is a
	// question about the change, which the images it leaves alone are still part of.
	d.Upgrades = moving(d.Upgrades)
	d.ServiceName = serviceName(group[0], d.Upgrade, d.ImageCount)
	// The noun describes what is grouped, and only the per-service key names a thing:
	// a campaign key names a change, and "images" is the honest word for what it
	// covers.
	d.GroupNoun = groupNoun(groupKey(group[0], false))
	return d
}

// serviceName picks the name a human would use for the thing being upgraded.
//
// When a group covers several images, naming it after the first one would be a
// lie: a ticket titled "Upgrade helm-controller" that actually moves six Flux
// controllers misdirects whoever picks it up. In that case the shared grouping
// subject (the chart, operator, or GitOps path they have in common) is the
// truthful name.
func serviceName(f sink.FindingView, u *UpgradeData, imageCount int) string {
	if imageCount > 1 {
		if u != nil && u.Kind == "chart" && u.Name != "" {
			return u.Name
		}
		if name := lastSegment(groupKey(f, false)); name != "" {
			return name
		}
	}
	if u != nil && u.Kind == "chart" && u.Name != "" {
		return u.Name
	}
	repo := f.Repository
	if i := strings.LastIndex(repo, "/"); i >= 0 && i < len(repo)-1 {
		return repo[i+1:]
	}
	if repo != "" {
		return repo
	}
	return f.Image
}

// imageUpgrades converts findings to their version moves, in a stable order.
func imageUpgrades(findings []sink.FindingView) []ImageUpgrade {
	out := make([]ImageUpgrade, 0, len(findings))
	for _, f := range findings {
		u := f.Upgrade
		// A package change is not a version move of the image: its rows are Packages.
		if u == nil || u.Kind == "package" {
			continue
		}
		up := ImageUpgrade{
			Ref: f.Image, Repo: f.Repository, Current: u.Current, Latest: u.Latest,
			Source: u.Source, SourcePath: u.SourcePath,
			Managed: u.Managed, Direct: u.Actionable,
			unmoved: unmoved(f),
		}
		if u.Kind == "chart" {
			up.Chart, up.ChartCurrent, up.ChartLatest = u.Name, u.Current, u.Latest
			up.Current, up.Latest = u.ImageCurrent, u.ImageLatest
			up.LatestFrom, up.LatestRepo = u.ImageLatestFrom, u.ImageLatestRepo
			if up.Current == "" {
				up.Current = f.Tag
			}
		}
		out = append(out, up)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// move is the version change the ticket asks somebody to make for this image:
// the chart's, when a chart owns the image's version, else the image's own.
func (u ImageUpgrade) move() (from, to string) {
	if u.Chart != "" {
		return u.ChartCurrent, u.ChartLatest
	}
	return u.Current, u.Latest
}

// moving drops the images the change was measured to leave where they are.
func moving(ups []ImageUpgrade) []ImageUpgrade {
	out := make([]ImageUpgrade, 0, len(ups))
	for _, u := range ups {
		if !u.unmoved {
			out = append(out, u)
		}
	}
	return out
}

// sharesOneTarget reports whether every image moves to the same version, which
// is what makes a single "upgrade to X" summary truthful.
func sharesOneTarget(ups []ImageUpgrade) bool {
	if len(ups) == 0 {
		return false
	}
	from, to := ups[0].move()
	for _, u := range ups[1:] {
		if f, t := u.move(); f != from || t != to {
			return false
		}
	}
	return true
}

// groupNoun turns a grouping key into the plural noun for what it groups. A key
// of "ProviderRevision/crossplane-system" is a set of providers; anything else
// is described generically as images.
func groupNoun(key string) string {
	kind, _, ok := strings.Cut(key, "/")
	if !ok || kind == "" || kind[0] < 'A' || kind[0] > 'Z' {
		return "images"
	}
	// Controllers name these objects "<Thing>Revision"; the thing is the useful
	// half ("ProviderRevision" -> "providers").
	noun := strings.TrimSuffix(kind, "Revision")
	if noun == "" {
		return "images"
	}
	return strings.ToLower(noun) + "s"
}

// sharesOneSource reports whether every image has the same change target.
func sharesOneSource(ups []ImageUpgrade) bool {
	if len(ups) == 0 {
		return false
	}
	for _, u := range ups[1:] {
		if u.Source != ups[0].Source || u.SourcePath != ups[0].SourcePath {
			return false
		}
	}
	return true
}

// lastSegment returns the final path-ish component of a grouping key, which for
// a chart repo URL or a GitOps path is the recognisable name of the thing.
func lastSegment(key string) string {
	trimmed := strings.TrimRight(key, "/")
	if i := strings.LastIndex(trimmed, "/"); i >= 0 && i < len(trimmed)-1 {
		return trimmed[i+1:]
	}
	return trimmed
}

// higherPriority reports whether a outranks b on the model's ladder, which is
// the single definition of that ordering.
func higherPriority(a, b string) bool {
	return model.PriorityRank(a) > model.PriorityRank(b)
}

// set is a small sorted-unique string collector.
type set struct{ m map[string]bool }

func (s *set) add(v string) {
	if v == "" {
		return
	}
	if s.m == nil {
		s.m = map[string]bool{}
	}
	s.m[v] = true
}

func (s *set) sorted() []string {
	out := make([]string, 0, len(s.m))
	for v := range s.m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// environments are the sequence a release moves through, earliest first, with the
// tokens that identify each. A heuristic on names rather than configuration: it only
// decides the ORDER of a list in a ticket body, so a wrong guess costs a reader a
// moment and never changes a verdict. Anything unmatched sorts last, since an
// unrecognised environment is more likely to be a one-off than the first step.
// defaultEnvironments is the sequence used when a deployment configures none.
// The words are the ones most estates happen to use; an estate whose names are
// local configures its own rather than being described wrongly.
var defaultEnvironments = []config.Environment{
	{Name: "development", Match: []string{"dev", "sandbox", "local"}},
	{Name: "test", Match: []string{"test", "qa", "integration"}},
	{Name: "staging", Match: []string{"stag", "preprod", "pre-prod", "preproduction", "uat", "perf"}},
	{Name: "production", Match: []string{"prod", "live"}},
}

// environmentOf guesses where in a release sequence a deployment sits, returning
// the name and position of the LATEST environment it reaches, which labels a row
// and orders it among the others.
//
// Each account is classified on its own and the furthest along wins. Joining them
// into one string and taking the first environment that matched, as this used to,
// labelled a tag running in development, pre-production and production as
// "development", because development is tested first. Testing production first
// instead is not the fix: see classify.
//
// Namespaces are consulted only when no account is recognised. Accounts are where
// an estate draws its environment boundaries; namespace names are free text the
// tokens match inside of by accident ("delivery" contains "live", "devices"
// contains "dev"). While the earliest match won, a stray hit like that was usually
// outranked by the account. With the latest winning, a "delivery" namespace in a
// development account would label the row production. An estate whose accounts
// say nothing about environment, one shared account with environments by
// namespace, still gets its answer from the namespaces.
func environmentOf(envs []config.Environment, accounts, namespaces []string) (string, int) {
	envs = orDefault(envs)
	at := reaches(envs, accounts, namespaces)
	if len(at) == 0 {
		return "", len(envs)
	}
	last := at[len(at)-1]
	return envs[last].Name, last
}

// reaches is the position of every environment the accounts are recognised in,
// or failing those the namespaces, by the rule environmentOf describes. Ascending
// and de-duplicated; empty when nothing was recognised.
func reaches(envs []config.Environment, accounts, namespaces []string) []int {
	at := classifyAll(envs, accounts)
	if len(at) == 0 {
		at = classifyAll(envs, namespaces)
	}
	return at
}

func classifyAll(envs []config.Environment, names []string) []int {
	var at []int
	for _, n := range names {
		if i := classify(envs, n); i >= 0 && !slices.Contains(at, i) {
			at = append(at, i)
		}
	}
	slices.Sort(at)
	return at
}

// classify is the position of the environment one account or namespace name
// belongs to, or -1 when it matches none.
//
// The FIRST environment whose token matches wins, and the order matters for one
// specific reason: "preproduction" contains "prod", so staging has to be tested
// before production or a pre-production account is labelled production and a
// ticket tells somebody to release to pre-production after production. That is
// why a span takes the latest across names classified one at a time, rather than
// reversing this order over all of them at once.
func classify(envs []config.Environment, name string) int {
	name = strings.ToLower(name)
	for i, env := range envs {
		for _, tok := range env.Match {
			if strings.Contains(name, strings.ToLower(tok)) {
				return i
			}
		}
	}
	return -1
}

func orDefault(envs []config.Environment) []config.Environment {
	if len(envs) == 0 {
		return defaultEnvironments
	}
	return envs
}

// deployments lists each grouped tag with where it runs, ordered by release
// sequence so a ticket reads as a promotion rather than a set: by the latest
// environment each reaches, so the tag furthest along is last.
func deployments(group []sink.FindingView, envs []config.Environment) []Deployment {
	envs = orDefault(envs)
	out := make([]Deployment, 0, len(group))
	rank := map[string]int{}
	for _, f := range group {
		accounts := append([]string{}, f.Dimensions["account"]...)
		namespaces := append([]string{}, f.Dimensions["namespace"]...)
		sort.Strings(accounts)
		sort.Strings(namespaces)
		env, r := environmentOf(envs, accounts, namespaces)
		d := Deployment{
			Ref: f.Image, Repo: f.Repository, Tag: f.Tag,
			Accounts: accounts, Namespaces: namespaces, Environment: env,
			reaches: reaches(envs, accounts, namespaces),
		}
		rank[f.Image] = r
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Ref] != rank[out[j].Ref] {
			return rank[out[i].Ref] < rank[out[j].Ref]
		}
		return out[i].Ref < out[j].Ref
	})
	return out
}

// BuildRepo is the single repository that builds these images, else "". A ticket
// covering images from two repositories cannot name one as the place to work.
func (d TemplateData) BuildRepo() string {
	if len(d.BuildRepos) == 1 {
		return d.BuildRepos[0]
	}
	return ""
}

// environmentSpan is the distinct environments this ticket covers, in promotion
// order. Empty when none were recognised.
//
// Every environment each tag reaches, not the rows' labels: a label names only the
// latest, so a ticket for one tag running in development and pre-production covers
// both, and a disambiguated summary saying "(staging)" would hide the half that
// moves first.
func (d TemplateData) environmentSpan() []string {
	var at []int
	for _, dep := range d.Deployments {
		for _, i := range dep.reaches {
			if !slices.Contains(at, i) {
				at = append(at, i)
			}
		}
	}
	slices.Sort(at)
	out := make([]string, 0, len(at))
	for _, i := range at {
		out = append(out, d.envs[i].Name)
	}
	return out
}

// Team is the single owning team when there is exactly one, else "". Used to build a
// deep link: a ticket covering two teams cannot link to one team's view.
func (d TemplateData) Team() string {
	if len(d.Teams) == 1 {
		return d.Teams[0]
	}
	return ""
}

// Repository is the single bare repository this ticket covers, else "". Grouping is by
// repository for base upgrades, so this is set for exactly the tickets whose queue
// entry is one work item.
func (d TemplateData) Repository() string {
	if len(d.Images) == 1 {
		return d.Images[0]
	}
	return ""
}
