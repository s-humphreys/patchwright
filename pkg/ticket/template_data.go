package ticket

import (
	"sort"
	"strings"

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
	Upgrade *UpgradeData
	// Upgrades is the version move(s) to APPLY. For a chain-merged ticket this is
	// the managing component only, since bumping it is the whole action.
	Upgrades []ImageUpgrade
	// Fixes are images updated as a consequence of Upgrades, listed for context
	// rather than as work. Empty on an ordinary ticket. A template should not
	// present these as things to bump: nobody can, which is why they were merged
	// into this ticket in the first place.
	Fixes []ImageUpgrade

	// Source and SourcePath are the change target shared by everything on this
	// ticket: the repository (or owning custom resource) and the directory within
	// it. They sit at the top level, not under Upgrade, because grouping is BY
	// source — so a grouped ticket has one even when its images move to different
	// versions, and that is precisely the ticket where "where do I make the
	// change?" matters most.
	Source     string
	SourcePath string

	// Priority is the highest policy priority across the grouped findings.
	Priority string
	// Accounts and Namespaces are the sorted, de-duplicated places this runs.
	Accounts   []string
	Namespaces []string
	// Teams are the attributed owning teams; empty when none could be resolved.
	Teams []string
	// WorkloadCount is the total number of workloads affected.
	WorkloadCount int

	// CriticalCount is the provider's critical count, and ProviderAssessed
	// reports whether the provider assessed these images at all. When false the
	// counts are zero through ignorance, so a template should not present them
	// as evidence.
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
	Ref     string
	Repo    string
	Current string
	Latest  string
	// Source and SourcePath are this image's own change target. They matter on a
	// grouped ticket whose members each have their own (every Crossplane package
	// has its own ProviderRevision), where a single ticket-level target would name
	// one member and mislead about the rest.
	Source     string
	SourcePath string
	// Managed names the controller owning the version; empty means direct.
	Managed string
	Direct  bool
}

// UpgradeData is the version move a ticket asks for.
type UpgradeData struct {
	// Kind is "chart" or "image": the sort of artefact whose version moves.
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

func newTemplateData(tg ticketGroup) TemplateData {
	group := tg.all()
	d := TemplateData{}

	accounts, namespaces, teams := &set{}, &set{}, &set{}
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
		d.WorkloadCount += f.WorkloadCount
		d.CriticalCount += f.Counts["critical"]
		d.HighCount += f.Counts["high"]
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

	d.Images, d.Refs = images.sorted(), refs.sorted()
	d.ImageCount = len(d.Images)
	d.Accounts, d.Namespaces, d.Teams = accounts.sorted(), namespaces.sorted(), teams.sorted()

	// Highest EPSS first: a ticket should lead with the CVE most likely to be
	// exploited, not whichever the scanner happened to emit first.
	sort.SliceStable(d.FixableCriticals, func(i, j int) bool {
		if d.FixableCriticals[i].EPSS != d.FixableCriticals[j].EPSS {
			return d.FixableCriticals[i].EPSS > d.FixableCriticals[j].EPSS
		}
		return d.FixableCriticals[i].ID < d.FixableCriticals[j].ID
	})

	d.Upgrades = imageUpgrades(tg.primary)
	d.Fixes = imageUpgrades(tg.dependents)

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
	if u := group[0].Upgrade; u != nil && sharesOneTarget(d.Upgrades) {
		d.Upgrade = &UpgradeData{
			Kind: u.Kind, Name: u.Name, Current: u.Current, Latest: u.Latest,
			Managed: u.Managed, Source: u.Source, SourcePath: u.SourcePath,
			Direct: u.Actionable,
		}
	}
	d.ServiceName = serviceName(group[0], d.Upgrade, d.ImageCount)
	d.GroupNoun = groupNoun(groupKey(group[0]))
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
		if name := lastSegment(groupKey(f)); name != "" {
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
		if u := f.Upgrade; u != nil {
			out = append(out, ImageUpgrade{
				Ref: f.Image, Repo: f.Repository, Current: u.Current, Latest: u.Latest,
				Source: u.Source, SourcePath: u.SourcePath,
				Managed: u.Managed, Direct: u.Actionable,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// sharesOneTarget reports whether every image moves to the same version, which
// is what makes a single "upgrade to X" summary truthful.
func sharesOneTarget(ups []ImageUpgrade) bool {
	if len(ups) == 0 {
		return false
	}
	for _, u := range ups[1:] {
		if u.Latest != ups[0].Latest || u.Current != ups[0].Current {
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
