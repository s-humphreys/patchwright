package mcp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/group"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// ServiceReport is everything known about one service, which is the question most
// often asked and the one a queue row only partly answers.
//
// Reported per SERVICE rather than per image. A service is typically deployed at
// several tags at once - a release, a preview, an rc - and answering about one of
// them when somebody named the service is the same mistake as a queue row that opens
// a single deployment. The service is what a team owns and rebuilds.
type ServiceReport struct {
	Freshness Freshness `json:"freshness"`

	Service string `json:"service"`
	Team    string `json:"team,omitempty"`
	Class   string `json:"class,omitempty"`

	Priority      string   `json:"priority,omitempty"`
	PriorityWhere string   `json:"priority_where,omitempty"`
	Rule          string   `json:"rule,omitempty"`
	Signals       []string `json:"signals,omitempty"`
	// Exposure is measured from the clusters where hostnames are configured, not
	// taken from the scan provider.
	Exposure string `json:"exposure"`

	// BuildRepo is the source repository that built the image, from the labels named by
	// remediation.base.repoLabels. Absent means the image records none.
	BuildRepo string `json:"build_repo,omitempty"`

	Deployments []Deployment `json:"deployments"`
	// ImageAgeDays is how long ago the newest deployed image was built. An old one
	// means this has not shipped, which is a different conversation from a team
	// ignoring a finding.
	ImageAgeDays *int `json:"image_age_days,omitempty"`

	Vulnerabilities VulnSummary    `json:"vulnerabilities"`
	Upgrade         *UpgradeAdvice `json:"upgrade,omitempty"`
	InProgress      *InProgress    `json:"in_progress,omitempty"`

	// Caveats are the things this answer cannot support. Present in the payload so
	// they survive being summarised.
	Caveats []string `json:"caveats,omitempty"`
}

// Deployment is one running tag of the service.
type Deployment struct {
	Image      string   `json:"image"`
	Tag        string   `json:"tag,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	Accounts   []string `json:"accounts,omitempty"`
	Scanned    bool     `json:"scanned"`
	// Suppressed marks a deployment policy has ruled out of the queue. Reported here
	// rather than filtered out: somebody asking about a service wants all of it, and
	// a hidden deployment is how a suppression rule outlives its reason.
	Suppressed bool `json:"suppressed,omitempty"`
}

// VulnSummary counts what the service carries. Counts are absent rather than zero
// where nothing was assessed.
type VulnSummary struct {
	// Total is distinct CVEs across the service's deployments.
	Total int `json:"total"`
	// Critical and High are the scan provider's own counts for the WORST single
	// deployment, not distinct CVEs and not a sum - a different unit from everything
	// else here, so the names say so.
	Critical int `json:"critical_worst_deployment"`
	High     int `json:"high_worst_deployment"`
	// KnownExploited and EPSSHigh are the two that decide urgency, both DISTINCT CVEs.
	// EPSSHigh counted deployments while KnownExploited counted CVEs, in adjacent
	// fields with no way to tell them apart.
	KnownExploited int     `json:"known_exploited"`
	EPSSHigh       int     `json:"epss_high_cves"`
	TopEPSS        float64 `json:"top_epss,omitempty"`
	TopPercentile  float64 `json:"top_epss_percentile,omitempty"`
	// Assessed and Scanned say how much of the service these numbers describe.
	// Short of Deployments they are the worst KNOWN rather than the worst.
	AssessedOf [2]int `json:"assessed_of"`
	ScannedOf  [2]int `json:"scanned_of"`
}

// UpgradeAdvice is what moving the base image would buy, which is the question a
// team asks the moment they are told to upgrade.
type UpgradeAdvice struct {
	Kind string `json:"kind"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// Move says whether this is a rebuild on the same tag or a version change,
	// because "rebuilding" understates a runtime migration to whoever has to do it.
	Move string `json:"move,omitempty"`
	// Newest is the furthest version available when policy recommends a nearer one,
	// and Rule names the policy that decided.
	Newest string `json:"newest,omitempty"`
	Rule   string `json:"rule,omitempty"`
	// Support is the maintenance status of the line this sits on.
	Support string `json:"support,omitempty"`
	// Strategy is how far policy allowed the move to go: patch, minor, latest.
	Strategy string `json:"strategy,omitempty"`
	// Ceiling is the version prefix policy will not pass, and CeilingReason why - written
	// by whoever set it. It is the answer to "there is a newer version, why am I being
	// told this one", and without it a reader either guesses or ignores the policy.
	Ceiling       string `json:"ceiling,omitempty"`
	CeilingReason string `json:"ceiling_reason,omitempty"`
	// CeilingExpired marks a ceiling whose end date has passed, so it no longer applies.
	CeilingExpired bool `json:"ceiling_expired,omitempty"`
	// Yours is true when the team that builds the image applies this themselves. False
	// means a chart or an operator owns the tag, and AppliedIn says which - bumping the
	// Dockerfile would do nothing.
	Yours     bool   `json:"yours"`
	AppliedIn string `json:"applied_in,omitempty"`
	// OutOfTrack marks a move that leaves the current line because that line is no longer
	// maintained: a migration to plan, not a bump to take.
	OutOfTrack bool `json:"out_of_track,omitempty"`
	// ClearsKnownExploited and LeavesKnownExploited split the exploited CVEs by whether
	// this move deals with them. The first is what justifies the work; the second is what
	// still needs a decision afterwards.
	ClearsKnownExploited int `json:"clears_known_exploited"`
	LeavesKnownExploited int `json:"leaves_known_exploited"`
	// Exploited names them. A count tells somebody how much; the identifiers are what
	// goes in a pull request description and what is re-checked when it lands.
	Exploited []ExploitedCVE `json:"exploited,omitempty"`
	// State says which kind of answer this is, because four of them are not moves:
	// "upgrade" has a version to go to, "latest" is already on the newest available,
	// "held" is a newer version policy declined, "unresolved" is a lookup that could
	// not answer. Only the first is a pull request; the rest need a person.
	State string `json:"state"`

	// Measured is true when a base differential actually ran. Without it the counts
	// below are absent rather than zero - "we did not check" and "it fixes nothing"
	// are different answers.
	Measured bool `json:"measured"`
	// DeploymentsMeasured is how many of the service's deployments a differential ran
	// for, so a partial answer can be read as partial.
	DeploymentsMeasured int `json:"deployments_measured"`
	// Clears, Leaves and Introduces are DISTINCT CVEs, on the same footing as
	// vulnerabilities.total, so the four numbers can be read against each other:
	// clears + leaves + from_application + unattributed is the total.
	Clears int `json:"clears"`
	Leaves int `json:"leaves"`
	// Introduces is the worst any single deployment reports, not a sum: it describes
	// what the candidate base adds, which is not in the image's own CVEs to dedupe.
	Introduces int `json:"introduces"`

	// Remainder splits what is left after the upgrade by who can act on it.
	Remainder *Remainder `json:"remainder,omitempty"`
}

// Remainder is what survives the upgrade, split by whose problem it is. This is the
// half that turns "you have 6,746 vulnerabilities" into a conversation.
type Remainder struct {
	// StillInBase is upstream's: the new base carries them too, and the team has no
	// action available.
	StillInBase int `json:"still_in_base"`
	// FromApplication is the team's: in the image and not in its base, so something
	// the build installed.
	FromApplication int `json:"from_application"`
	// Unattributed is neither, because no base scan covered them.
	Unattributed int `json:"unattributed,omitempty"`
	// Packages names what the base-image remainder is concentrated in, worst first.
	// Absent for application CVEs, whose layer nothing scanned.
	Packages []PackageCount `json:"packages,omitempty"`
	// Application names the CVEs the build itself introduced, worst first.
	//
	// This is the only part of the remainder the team can patch in its own repository,
	// and for a long time it was the only part reported as a bare number while the base
	// remainder - the part nobody here can act on - was broken down by package. The
	// classification already has each CVE in hand to decide it is application-origin, so
	// the identifiers cost nothing to carry and turn the count into a task.
	//
	// Capped at maxApplicationCVEs; FromApplication is always the true total.
	Application []ApplicationCVE `json:"application_cves,omitempty"`
}

// ApplicationCVE is one CVE the build introduced, with what a caller needs to act on
// it. There is no package name - nothing scanned that layer - so the identifier is the
// handle, and FixedVersion is what to move to where the provider published one.
type ApplicationCVE struct {
	ID           string  `json:"id"`
	Severity     string  `json:"severity,omitempty"`
	CVSS         float64 `json:"cvss,omitempty"`
	EPSS         float64 `json:"epss,omitempty"`
	KEV          bool    `json:"known_exploited,omitempty"`
	FixAvailable bool    `json:"fix_available"`
	FixedVersion string  `json:"fixed_version,omitempty"`
	Reference    string  `json:"reference"`
}

// PackageCount is one package and how many of the remaining CVEs it accounts for.
type PackageCount struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"`
	CVEs      int    `json:"cves"`
}

// InProgress is work already under way, so a tool never asks for something somebody
// is already doing.
type InProgress struct {
	PullRequest string `json:"pull_request,omitempty"`
	Title       string `json:"title,omitempty"`
	OpenDays    int    `json:"open_days,omitempty"`
	// Stale is an upgrade opened months ago and never merged, which is a different
	// problem from one in progress and must not read as covered.
	Stale bool `json:"stale,omitempty"`
	// Exact is false when the pull request moves the same dependency to a different
	// version than the one recommended, so it does not close this item.
	Exact bool `json:"exact"`
}

// baseDiffsAmong counts this service's deployments a differential actually measured.
func baseDiffsAmong(r ServiceReport) int {
	if r.Upgrade != nil && r.Upgrade.Measured {
		return 1
	}
	return 0
}

// maxRemainderPackages bounds the package breakdown. Past a handful it stops
// answering "is this one stubborn package or a long tail" and becomes the tail.
const maxRemainderPackages = 8

// maxApplicationCVEs bounds the application remainder. Higher than the package cap
// because these are individually actionable - each one is a thing to go and fix -
// rather than a shape to recognise.
const maxApplicationCVEs = 20

// serviceReport builds the report for one service, or false when nothing matches.
//
// Matching is on the repository, and deliberately forgiving: somebody asking about
// "storefront" means the service, not "the image whose full reference I typed".
func serviceReport(a Assessment, name string) (ServiceReport, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	var mine []sink.FindingView
	for _, f := range a.Findings {
		if strings.ToLower(f.Repository) == name || strings.ToLower(f.Image) == name ||
			strings.HasSuffix(strings.ToLower(f.Repository), "/"+name) {
			mine = append(mine, f)
		}
	}
	if len(mine) == 0 {
		return ServiceReport{}, false
	}

	// Group over the active deployments for the verdict, since a suppressed one is
	// not work - but fall back to everything when they are all suppressed, so the
	// answer is "suppressed" rather than "no such service".
	active := make([]sink.FindingView, 0, len(mine))
	for _, f := range mine {
		if !f.Suppressed {
			active = append(active, f)
		}
	}
	grouped := active
	if len(grouped) == 0 {
		grouped = mine
	}
	items := group.Items(grouped)
	lead := items[0] // Items sorts worst first.

	out := ServiceReport{
		Service: lead.Repository, Team: lead.Team, Class: lead.Class,
		Priority: lead.Priority, PriorityWhere: lead.PriorityWhere, Rule: lead.Rule,
		Signals: lead.Signals, Exposure: lead.Exposure,
	}
	for _, f := range mine {
		out.Deployments = append(out.Deployments, Deployment{
			Image: f.Image, Tag: f.Tag, Scanned: f.Scanned, Suppressed: f.Suppressed,
			Namespaces: f.Dimensions["namespace"], Accounts: f.Dimensions["account"],
		})
		if f.ImageAgeDays != nil && (out.ImageAgeDays == nil || *f.ImageAgeDays < *out.ImageAgeDays) {
			d := *f.ImageAgeDays
			out.ImageAgeDays = &d
		}
	}
	out.Freshness = freshness(a)
	for _, f := range mine {
		if f.BuildRepo != "" {
			out.BuildRepo = f.BuildRepo
			break
		}
	}
	out.Vulnerabilities = summariseVulns(mine, lead)
	out.Upgrade = upgradeAdvice(mine, lead)
	out.InProgress = inProgress(lead)
	out.Caveats = caveats(a, out)
	return out, true
}

func summariseVulns(mine []sink.FindingView, lead group.Item) VulnSummary {
	v := VulnSummary{
		Critical:   lead.Critical,
		High:       lead.High,
		AssessedOf: [2]int{lead.AssessedImages, lead.Deployments},
	}
	// Counted here rather than taken from the group, which reports the scanned FLAG:
	// see hasCVEDetail. A deployment nothing assessed, marked scanned with no CVEs,
	// would otherwise be counted as covered.
	v.ScannedOf = [2]int{0, len(mine)}
	for _, f := range mine {
		if hasCVEDetail(f) {
			v.ScannedOf[0]++
		}
	}
	seen := map[string]bool{}
	for _, f := range mine {
		for _, cve := range f.Vulns {
			if seen[cve.ID] {
				continue
			}
			seen[cve.ID] = true
			v.Total++
			if cve.KEV {
				v.KnownExploited++
			}
			if cve.EPSS >= epssUrgent {
				v.EPSSHigh++
			}
			// Score and percentile from the SAME CVE. Taking each as an independent
			// maximum pairs the worst score with another CVE's ranking and describes a
			// vulnerability that does not exist.
			if cve.EPSS > v.TopEPSS {
				v.TopEPSS, v.TopPercentile = cve.EPSS, cve.EPSSPercentile
			}
		}
	}
	return v
}

// epssUrgent matches the threshold the analytics use, so a service report and a team
// report cannot disagree about what counts as pressing.
const epssUrgent = 0.5

func upgradeAdvice(mine []sink.FindingView, lead group.Item) *UpgradeAdvice {
	if lead.Upgrade == nil {
		return nil
	}
	u := lead.Upgrade
	out := &UpgradeAdvice{
		Kind: u.Kind, From: u.Current, Newest: u.Newest, Rule: u.Rule,
		State: upgradeState(u),
	}
	// To is the version to move TO, so it is only set when there is one. A chart already
	// on its newest version reports that version as Latest with Available false, and
	// copying it here rendered "1.11.0 -> 1.11.0": an urgent row asking for a pull
	// request that would change nothing, instead of saying the fix is not a bump.
	if u.Available {
		out.To = u.Latest
	}
	out.Strategy, out.Ceiling, out.CeilingReason = u.Strategy, u.Ceiling, u.CeilingReason
	out.CeilingExpired, out.OutOfTrack = u.CeilingExpired, u.OutOfTrack
	out.Yours = u.Actionable
	if !u.Actionable {
		// Managed names the mechanism, Manager the thing running it. Either is more use
		// than "not actionable", which reads as "nothing to do".
		out.AppliedIn = u.Managed
		if u.Manager != "" {
			out.AppliedIn = strings.TrimSpace(u.Managed + " " + u.Manager)
		}
	}
	if u.Support != nil && u.Support.Known {
		if u.Support.Supported {
			out.Support = fmt.Sprintf("%s %s maintained until %s", u.Support.Product, u.Support.Cycle, u.Support.EOL)
		} else {
			out.Support = fmt.Sprintf("%s %s is END OF LIFE (ended %s)", u.Support.Product, u.Support.Cycle, u.Support.EOL)
		}
	}

	// The differential, counted in DISTINCT CVEs across the service's deployments.
	//
	// Summing each deployment's own counts was wrong, and wrong in the way that matters
	// most: a service deployed at three tags of one build carries the same CVEs three
	// times, so storefront was reported as clearing 17,571 of its 6,746 vulnerabilities. A
	// team cannot act on that - the arithmetic is visibly impossible, and the number they
	// would put in a ticket is three times the truth.
	//
	// Deduped, the same data closes exactly: 5,857 cleared plus 880 still in the base
	// plus 9 from the application is 6,746, the total. Every CVE count in this report is
	// therefore distinct CVEs on this service, one unit throughout.
	out.Remainder = &Remainder{}
	seen := map[string]bool{}
	pkgs := map[string]map[string]bool{}
	pkgMeta := map[string]PackageCount{}
	var app []ApplicationCVE
	// Two passes, because coverage can be partial. A base whose recorded digest or tag
	// has been deleted from the registry cannot be scanned - on this estate fifteen
	// services have some deployments measured and some not - and a CVE seen only on an
	// unmeasured deployment belongs in no origin bucket. Classifying from the measured
	// deployments alone would leave it out of the split while the total still counted it,
	// so the four numbers would stop adding up. The second pass puts it where it belongs:
	// unattributed, which is what "nothing established its origin" means.
	for _, f := range mine {
		d := f.BaseDiff
		if d == nil || !d.Determined {
			continue
		}
		out.Measured = true
		out.From, out.To = d.FromRef, d.ToRef
		out.DeploymentsMeasured++
		// Introduces cannot come from the image's own CVEs: it is what the candidate base
		// ADDS, which by definition is not there yet. So it is the worst any single
		// deployment reports rather than a sum - identical where they share a base pair,
		// which grouping by upgrade target makes the normal case.
		if d.Introduces > out.Introduces {
			out.Introduces = d.Introduces
		}
		for _, cve := range f.Vulns {
			if seen[cve.ID] {
				continue
			}
			seen[cve.ID] = true
			switch {
			case !cve.OriginDetermined:
				out.Remainder.Unattributed++
			case cve.FixedByUpgrade:
				out.Clears++
				if cve.KEV {
					out.ClearsKnownExploited++
					out.Exploited = append(out.Exploited, exploited(cve, true))
				}
			case cve.Origin == "base":
				out.Leaves++
				out.Remainder.StillInBase++
				if cve.KEV {
					out.LeavesKnownExploited++
					out.Exploited = append(out.Exploited, exploited(cve, false))
				}
				for _, pkg := range cve.Packages {
					key := pkg.Ecosystem + "/" + pkg.Name
					if pkgs[key] == nil {
						pkgs[key] = map[string]bool{}
						pkgMeta[key] = PackageCount{Name: pkg.Name, Ecosystem: pkg.Ecosystem}
					}
					pkgs[key][cve.ID] = true
				}
			default:
				out.Remainder.FromApplication++
				app = append(app, applicationCVE(cve))
			}
		}
	}
	if !out.Measured {
		out.Remainder = nil
		return out
	}
	// Everything the measured deployments did not account for.
	for _, f := range mine {
		for _, cve := range f.Vulns {
			if seen[cve.ID] {
				continue
			}
			seen[cve.ID] = true
			out.Remainder.Unattributed++
		}
	}
	out.Remainder.Packages = topPackages(pkgs, pkgMeta)
	out.Remainder.Application = topApplicationCVEs(app)
	out.Move = moveKind(out.From, out.To)
	return out
}

// upgradeState names which of the four answers this is. Absent versions and no-op
// versions are different states, and a consumer that cannot tell them apart reports a
// decision as a bump.
func upgradeState(u *sink.UpgradeView) string {
	switch {
	case !u.Resolved:
		return "unresolved"
	case u.Available && u.Latest != "":
		return "upgrade"
	case u.HeldBack:
		return "held"
	default:
		return "latest"
	}
}

// exploited records one known-exploited CVE and whether this move deals with it.
// applicationCVE carries one build-introduced CVE out of the classification.
func applicationCVE(v sink.VulnView) ApplicationCVE {
	return ApplicationCVE{
		ID: v.ID, Severity: v.Severity, CVSS: v.CVSS, EPSS: v.EPSS, KEV: v.KEV,
		FixAvailable: v.FixAvailable, FixedVersion: v.FixedVersion,
		Reference: "https://www.cve.org/CVERecord?id=" + v.ID,
	}
}

// topApplicationCVEs orders the build-introduced remainder worst first and caps it.
//
// Worst first rather than fixable first, to match every other list here: fix_available
// is on each row for a caller that wants to start with what it can actually move.
func topApplicationCVEs(in []ApplicationCVE) []ApplicationCVE {
	sort.Slice(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		return a.ID < b.ID
	})
	if len(in) > maxApplicationCVEs {
		in = in[:maxApplicationCVEs]
	}
	return in
}

func exploited(v sink.VulnView, cleared bool) ExploitedCVE {
	return ExploitedCVE{
		ID: v.ID, ClearedByThis: cleared, Severity: v.Severity,
		FixedVersion: v.FixedVersion,
		Reference:    "https://www.cve.org/CVERecord?id=" + v.ID,
	}
}

// moveKind separates a rebuild from a version change. A base pinned to a floating
// tag moves by digest - same tag, newer content - and calling a runtime migration
// "a rebuild" understates it to whoever has to do it.
func moveKind(from, to string) string {
	if to == "" {
		return ""
	}
	if strings.Contains(to, "@sha256:") {
		return "rebuild on the same tag (newer digest)"
	}
	if i := strings.LastIndex(to, ":"); i >= 0 {
		return "version change to " + to[i+1:]
	}
	return ""
}

// topPackages ranks the packages the remaining base CVEs sit in, worst first.
//
// A package's count is DISTINCT CVEs in that package. The counts across packages still
// overlap, because one CVE can affect several packages built from the same source - the
// binutils family accounts for seven of them, each reporting the same 171 - so they
// cannot be summed. The report says so rather than leaving a reader to add them up and
// get a number larger than the remainder they came from.
func topPackages(sets map[string]map[string]bool, meta map[string]PackageCount) []PackageCount {
	out := make([]PackageCount, 0, len(sets))
	for key, ids := range sets {
		p := meta[key]
		p.CVEs = len(ids)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CVEs != out[j].CVEs {
			return out[i].CVEs > out[j].CVEs
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > maxRemainderPackages {
		out = out[:maxRemainderPackages]
	}
	return out
}

func inProgress(lead group.Item) *InProgress {
	if lead.InFlight == nil {
		return nil
	}
	return &InProgress{
		PullRequest: lead.InFlight.URL,
		Title:       lead.InFlight.Title,
		OpenDays:    lead.InFlight.OpenDays,
		Stale:       lead.InFlight.Stale,
		Exact:       lead.InFlight.Exact,
	}
}

// caveats states what this answer cannot support, so the limits survive being
// summarised into prose.
func caveats(a Assessment, r ServiceReport) []string {
	// Configuration first, for the same reason as the estate summary: a signal
	// nobody asked for is explained by the command line, not by this service.
	out := configCaveats(a, Coverage{
		Scanned: r.Vulnerabilities.ScannedOf[0], Total: r.Vulnerabilities.ScannedOf[1],
		BaseDiffs: baseDiffsAmong(r),
	})
	if r.Vulnerabilities.AssessedOf[0] < r.Vulnerabilities.AssessedOf[1] {
		out = append(out, fmt.Sprintf(
			"The scan provider never assessed %d of %d deployments; their counts are absent data, not zero.",
			r.Vulnerabilities.AssessedOf[1]-r.Vulnerabilities.AssessedOf[0], r.Vulnerabilities.AssessedOf[1]))
	}
	// Only worth saying when the differential was enabled: when it was not, the
	// configuration caveat above has already said why, and repeating it as a
	// property of this service points at the wrong thing.
	if r.Upgrade != nil && r.Upgrade.Measured && r.Upgrade.DeploymentsMeasured < len(r.Deployments) {
		out = append(out, fmt.Sprintf(
			"A base differential ran for %d of %d deployments. The rest usually means the base "+
				"image recorded in the build has since been deleted from its registry, so nothing "+
				"can establish where their CVEs came from; those are counted as unattributed.",
			r.Upgrade.DeploymentsMeasured, len(r.Deployments)))
	}
	if a.Sources.BaseDiff && r.Upgrade != nil && !r.Upgrade.Measured {
		out = append(out, "The base differential is enabled but did not measure this service, so what an "+
			"upgrade would clear is unknown rather than nothing - its base could not be resolved or scanned.")
	}
	if a.Sources.Exposure && r.Exposure == "unknown" {
		out = append(out, "Exposure was measured across the estate but nothing reported it for this service, "+
			"so it is unknown rather than internal.")
	}
	var suppressed int
	for _, d := range r.Deployments {
		if d.Suppressed {
			suppressed++
		}
	}
	if suppressed > 0 {
		out = append(out, fmt.Sprintf(
			"%d of %d deployments are suppressed by policy: excluded from the queue by a decision, "+
				"not by being clean.", suppressed, len(r.Deployments)))
	}
	if r.Upgrade != nil && r.Upgrade.Remainder != nil && r.Upgrade.Remainder.FromApplication > 0 {
		out = append(out, "Application-introduced CVEs carry no package name, because nothing "+
			"scanned that layer. They are listed by identifier in remainder.application_cves.")
	}
	return out
}
