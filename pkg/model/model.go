// Package model defines patchwright's canonical, vendor-neutral data model.
//
// The core reasons only over universal primitives — images, vulnerabilities
// (CVEs), aggregate counts, and resources carrying free-form key/value
// dimensions and labels. Nothing here encodes any single organization's
// taxonomy (environment names, regions, team structure) or any single
// scanner's schema. Those concerns live at the edges:
//
//   - Scanner-specific parsing lives in a Provider (pkg/provider/...).
//   - Organization-specific interpretation lives in user CEL configuration,
//     which reasons over the generic dimensions/labels/counts/vulns below.
package model

import (
	"sort"
	"time"
)

// Image identifies a container image reference, decomposed for matching.
// Digest is populated when known (e.g. from live reconciliation or a digest-
// pinned reference); aggregate sources may leave it empty and key on Ref.
type Image struct {
	Registry   string // e.g. "acme.example.com", "mcr.microsoft.com"
	Repository string // e.g. "orders", "oss/v2/kubernetes-csi/livenessprobe"
	Tag        string // e.g. "1.0.381-rc", "v2.18.0"
	Digest     string // "sha256:..." when known
	Ref        string // the original, unparsed image reference
}

// Key returns the stable dedupe key for an image: digest when available,
// otherwise the full reference.
func (i Image) Key() string {
	if i.Digest != "" {
		return i.Digest
	}
	return i.Ref
}

// Severity bucket names. These are conventional, near-universal labels used by
// most scanners; they are NOT an exhaustive enum. Providers may emit other
// bucket names (e.g. "negligible") and they flow through unchanged.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityUnknown  = "unknown"
)

// Conventional priority labels. Finding.Priority is free-form and defined by
// policy config; these are merely the values the bundled example rules and the
// report ordering understand. Any string is valid, but a label not listed here
// is unranked and sorts after all of these — so a custom tier needs adding to
// priorityRank too, or it lands at the bottom of the report.
const (
	PriorityUrgent = "urgent"
	PriorityHigh   = "high"
	PriorityMedium = "medium"
	PriorityLow    = "low"
)

// PriorityRank orders the conventional priority labels for display and
// comparison; unknown labels rank 0 and therefore sort after all of them. This
// is the single definition: a second copy elsewhere would let the two ladders
// drift, and a tier missing from the ladder silently sinks to the bottom.
func PriorityRank(p string) int {
	switch p {
	case PriorityUrgent:
		return 4
	case PriorityHigh:
		return 3
	case PriorityMedium:
		return 2
	case PriorityLow:
		return 1
	default:
		return 0
	}
}

// Vulnerability is a single CVE/advisory affecting an image. It is populated
// when a provider exposes per-CVE detail (e.g. the Rapid7 API, Trivy, Grype).
// Aggregate-only sources (such as the Rapid7 InsightCloudSec CSV export) leave
// this empty and populate Counts instead. FixAvailable/FixedVersion are the
// signals that make a vulnerability truly actionable.
type Vulnerability struct {
	ID           string  // e.g. "CVE-2024-1234"
	Severity     string  // one of the Severity* names, lowercased
	CVSS         float64 // base score when known
	FixAvailable bool
	FixedVersion string
	Description  string
	Links        []string

	// FirstSeen is when the scan provider first observed this CVE, populated by an
	// age source. Zero when unknown.
	//
	// The queue has no other time dimension: without it, a critical found this
	// morning and one open since June are indistinguishable, and neither an SLA nor
	// an "oldest first" triage order is expressible.
	FirstSeen time.Time

	// Exploitability signals, populated by an exploit-intelligence enricher.
	// They approximate "is this actually worth acting on" without code-level
	// reachability analysis. EPSS is the probability of exploitation in the next
	// 30 days (0..1, FIRST.org); KEV marks membership of CISA's Known Exploited
	// Vulnerabilities catalog (exploited in the wild).
	EPSS float64
	// EPSSPercentile ranks that probability against every scored CVE (0..1). The
	// score alone misleads: nearly every CVE scores near zero, so 0.08 reads as
	// negligible when it is in fact the 94th percentile.
	EPSSPercentile float64
	KEV            bool
	// Origin says where this CVE came from, established by scanning the base image
	// rather than inferred from a package name: "base" if the base image as built
	// already had it, "app" if the image has it and its base does not, "" if no
	// base scan was available. FixedByUpgrade is true only when the CVE is absent
	// from the base being recommended.
	//
	// OriginDetermined reports whether a candidate base was actually scanned.
	// Without it, "this upgrade will not fix it" cannot be told apart from "we
	// never checked", and those must not render the same way.
	Origin           string
	FixedByUpgrade   bool
	OriginDetermined bool

	// Packages names the packages carrying this CVE, and the version that fixes
	// each. Populated only for CVEs the base scan found, where a scanner measured
	// both in the same pass.
	//
	// Empty for application-introduced CVEs: their packages live in a layer
	// nothing scanned, so there is nothing to name. Empty is the honest answer,
	// and specifically better than the alternative that was tried - the provider
	// reports a package per CVE from a generic remediation record, and 66% of
	// those name an ecosystem the image does not contain.
	Packages []AffectedPackage

	// RiskScore is a scanner's own composite ranking for this CVE, on whatever
	// scale that scanner uses (Rapid7's is roughly 0..1000). Deliberately kept
	// apart from EPSS: EPSS is a calibrated probability, this is a weighting, and
	// a rule thresholding one at 0.5 would fire on every CVE if given the other.
	// Zero means unknown, since no scanner scores a real CVE at zero.
	RiskScore float64
	// ExploitKnown reports that the scanner has a public exploit on record for
	// this CVE. Weaker than KEV, which is confirmed exploitation in the wild.
	ExploitKnown bool
}

// Counts holds aggregate vulnerability counts keyed by severity name. A map
// (rather than a fixed struct) keeps non-standard buckets intact across
// providers.
type Counts map[string]int

// Get returns the count for a severity (0 if absent).
func (c Counts) Get(severity string) int { return c[severity] }

// standardSeverities are always exposed to CEL rules so an expression like
// counts['critical'] never fails on an image that happens to have none.
var standardSeverities = []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}

// Normalized returns a copy of c guaranteed to contain every standard severity
// key (missing ones set to 0), so rule expressions can index them safely.
func (c Counts) Normalized() Counts {
	out := make(Counts, len(c)+len(standardSeverities))
	for _, s := range standardSeverities {
		out[s] = 0
	}
	for k, v := range c {
		out[k] = v
	}
	return out
}

// Total sums all severity buckets.
func (c Counts) Total() int {
	n := 0
	for _, v := range c {
		n += v
	}
	return n
}

// Owner is the attributed responsible party for a resource. Both Class and Team
// are free-form strings defined entirely by user configuration — patchwright
// pins no ownership taxonomy. Class is intended for coarse routing (a common
// convention is "platform" / "cloud-provider" / "engineering", but any values
// are valid); Team is the specific owner.
type Owner struct {
	Class string // coarse routing bucket, e.g. "platform" (user-defined)
	Team  string // specific owning team (user-defined)
	Rule  string // name of the ownership rule that matched (for explainability)
}

// Resource is a place an image runs — one row from a provider. Its semantics
// are carried entirely by generic Dimensions and Labels so no organizational
// taxonomy is baked in. Type/Name/ID are surfaced for convenience but are also
// available within Dimensions.
type Resource struct {
	ID         string
	Type       string            // e.g. "containerdeployment", "kubernetesjob"
	Name       string            // human-readable resource name
	Dimensions map[string]string // all raw, vendor-neutral attributes (cloud, account, namespace, cluster, ...)
	Labels     map[string]string // resource/namespace labels or tags (e.g. "team")
}

// Occurrence is one image running on one resource — the raw unit a provider
// emits. The same image typically occurs across many resources; dedupe
// collapses these while attribution assigns an Owner to each.
type Occurrence struct {
	Image     Image
	Resource  Resource
	Counts    Counts          // aggregate counts when per-CVE detail is absent
	Vulns     []Vulnerability // per-CVE detail when the provider supplies it
	RiskScore float64
	LastSeen  time.Time
	Owner     Owner // assigned by the attribution stage

	// Exposed reports whether this workload is reachable from the internet, when
	// something knows. Nil means unknown, which is not the same as internal: a
	// provider that does not report reachability, or an export without the column,
	// must not make everything look safely internal.
	Exposed *bool

	// Assessed reports whether the scan provider actually assessed this
	// workload's image. It is NOT the same as "has no vulnerabilities": a
	// provider that never scanned an image (e.g. a private registry it has no
	// credentials for) reports zero counts, which is indistinguishable from a
	// clean result unless this is carried through. Deliberately independent of
	// vuln-source scanning, which is optional and off by default.
	Assessed bool

	// AssessmentStatus and AssessmentError are the provider's own account of the
	// assessment, when it gives one. Assessed alone says an image was not
	// assessed; these say why, which is the difference between a coverage
	// statistic and a fixable problem. On a real estate the overwhelming
	// majority of a 4,243-row inventory was failing for one reason — a registry
	// credential the platform could not use — and no amount of reporting
	// "unassessed" would have surfaced that.
	//
	// Empty when the provider does not report it (the CSV export does not), so
	// absent means "not stated", never "no problem".
	AssessmentStatus string
	AssessmentError  string

	// Reconciled is set once a live-reconciliation enricher has run against
	// this occurrence; Live then reports whether the image is actually running
	// in a cluster right now. When Reconciled is false, liveness is unknown.
	Reconciled bool
	Live       bool
}

// InFlight is remediation somebody has already started: an open pull request that
// would apply this upgrade.
//
// A finding with one is not work waiting on a decision, it is work waiting on a review.
// Raising a ticket for it duplicates a queue that already exists, and the useful signal
// is the opposite one — a fix that has been sitting in review for weeks.
type InFlight struct {
	// Repository is the repository the pull request is in, which is also the
	// repository that builds this image. A pull request only remediates the image
	// built from it; one that bumps a shared base image does not fix the images
	// consuming that base, which still have to rebuild.
	Repository string
	Title      string
	URL        string
	Author     string
	Opened     time.Time
	// Exact is true when both the dependency and the target version matched. When
	// false the dependency matched but the version did not, so something is being
	// worked on and it may not be this: consumers must not treat it as remediation.
	Exact bool
	// Stale is true when the pull request has been open past the configured
	// threshold. A fix nobody has merged in four months is a different problem from
	// one opened this morning, and the more urgent of the two.
	Stale bool
}

// Age reports how long the pull request has been open.
func (i InFlight) Age() time.Duration { return time.Since(i.Opened) }

// AssessedImage is the dedupe unit: one image plus every occurrence of it.
type AssessedImage struct {
	Image       Image
	Counts      Counts
	Vulns       []Vulnerability
	RiskScore   float64
	Occurrences []Occurrence

	// Scanned is true once a vuln source successfully scanned this image;
	// ScanError holds the reason when a scan was attempted but failed (e.g. a
	// private image with no credentials). A failed scan does not fail the run.
	Scanned   bool
	ScanError string

	// Fallback* record a scan run ONLY because the scan provider never assessed
	// this image, so that a coverage gap is answered with something rather than
	// with nothing.
	//
	// Deliberately separate from Scanned/ScanError, which describe the vuln source
	// configured for the whole estate. Folding the two together would make the
	// fallback's success indistinguishable from the primary source working, and
	// the entire point of the fallback is that the primary did not.
	//
	// FallbackSource is the source that was asked (empty means the fallback never
	// ran for this image, including because it was skipped); FallbackScanned that
	// it answered; FallbackError why it could not.
	FallbackSource  string
	FallbackScanned bool
	FallbackError   string

	// CountsSource names who produced Counts. Empty means the scan provider, which
	// is every image the fallback did not fill in.
	//
	// Severity is not a shared scale. The provider's "critical" and a fallback
	// scanner's "critical" come from different vendor feeds, so a total summed
	// across both is a blend of two taxonomies. Carrying the source per image is
	// what lets a reader see which rows are which, instead of a single number that
	// silently means two things.
	CountsSource string

	// InFlight is set when an open pull request would apply this image's upgrade.
	// InFlightChecked reports whether detection ran, so a nil InFlight can be told
	// apart from "nobody has started this".
	InFlight        *InFlight
	InFlightChecked bool
	// InFlightReason is set when detection ran but this image could never be
	// matched — it records no build repository, so no pull request can be tied to
	// it. Distinct from a nil InFlight with no reason, which means the repository
	// was known and no pull request was found. "Cannot be matched" is a build
	// pipeline fix; "no pull request" is work nobody has started.
	InFlightReason string

	// ExploitChecked is true once an exploit source has run, so consumers can
	// distinguish "0 known-exploited CVEs" from "exploit intel not gathered".
	ExploitChecked bool

	// Upgrade, when set, describes a newer version available for how this image
	// is deployed (e.g. a newer Helm chart) — the remediation path. Populated by
	// remediation detection.
	//
	// RemediationChecked reports whether that detection ran. A nil Upgrade with
	// RemediationChecked true means detection ran and could not resolve a
	// version (e.g. tags unlistable in a private registry), which is a coverage
	// gap rather than "already on the latest".
	Upgrade            *Upgrade
	RemediationChecked bool

	// BaseDiff summarises what the base image accounts for, and what upgrading it
	// would fix. Nil means the differential did not run for this image, which is
	// not the same as it finding nothing.
	BaseDiff *BaseDiff

	// BuildRepo is the source repository that built this image, read from the labels
	// named by remediation.base.repoLabels. Empty when the image records none, which is
	// a real answer: nothing can point at the code that produced it.
	BuildRepo string
	// ImageBuilt is when the image was built, per its own config. Zero when it was
	// not read or the image records none - never "built at the epoch".
	//
	// It is the difference between "you ignored this" and "this has not shipped
	// since March", which are different conversations to have with a team.
	ImageBuilt time.Time
}

// ProviderAssessed reports whether the scan provider assessed any workload of
// this image. Mirrors Finding.ProviderAssessed at the dedupe unit, which is where
// scanning decisions are made.
//
// It deliberately keeps saying false after a fallback scan has filled the counts
// in. The question it answers is "did the provider look", and a fallback answering
// in its place does not change that answer - it is the reason the question is
// being asked.
func (a AssessedImage) ProviderAssessed() bool {
	for _, o := range a.Occurrences {
		if o.Assessed {
			return true
		}
	}
	return false
}

// CountsFromVulns aggregates per-CVE detail into severity counts.
//
// Used to fill Counts for an image the provider never assessed, where the
// alternative on the report is a "?" for a scan that did in fact happen. Severity
// is taken verbatim from the vulnerability, so a scanner's non-standard bucket
// survives here exactly as it does from a provider.
func CountsFromVulns(vulns []Vulnerability) Counts {
	if len(vulns) == 0 {
		return nil
	}
	out := make(Counts, len(standardSeverities))
	for _, v := range vulns {
		sev := v.Severity
		if sev == "" {
			sev = SeverityUnknown
		}
		out[sev]++
	}
	return out
}

// AffectedPackage is a package carrying a CVE, and the version that fixes it.
//
// Name and FixedIn come from the same scan of the same image, which is what keeps
// them consistent: a fix version sourced separately from the package name can
// belong to a different ecosystem entirely.
type AffectedPackage struct {
	Name      string
	Ecosystem string
	FixedIn   string
}

// BaseDiff is what scanning an image's base established: how much of its
// vulnerability count the base accounts for, and how much of that a specific
// upgrade would remove.
//
// The counts are what makes a queue row worth working. "A newer base exists" asks
// a team for an upgrade of unknown value; "this clears 3,664 of your 4,890" does
// not.
type BaseDiff struct {
	// FromRef is the base as built, digest-pinned when the build recorded one.
	// ToRef is the base compared against, empty when none was.
	FromRef  string
	ToRef    string
	OSFamily string

	Total      int // CVEs considered
	FromBase   int // present in the base as built
	FromApp    int // in the image but not in its base, so the team owns them
	Unknown    int // not attributed
	Clears     int // removed by moving to ToRef
	Leaves     int // from the base and still present in ToRef
	Introduces int // in ToRef but not in the base as built

	// Determined reports whether a candidate base was scanned. When false, Clears
	// and Leaves are both zero because the question was not asked - which must not
	// be shown as "this upgrade fixes nothing".
	Determined bool
}

// Upgrade describes a newer version available for the artifact that deploys an
// image — the concrete remediation. Kind is the deployment source that would be
// bumped ("chart" for Helm today; "image"/"git"/"oci" to follow). Source is
// where the change lands (the Helm repo URL, git URL, ...).
type Upgrade struct {
	Kind      string
	Name      string // e.g. chart name
	Current   string // deployed version
	Latest    string // latest available version
	Available bool   // Latest is newer than Current
	Source    string // where to make the change (repo URL, or an owning CR ref)
	// Manager is the bare name of the component that owns this image's version
	// (e.g. "flux-operator"), when known. Distinct from Managed, which says only
	// what KIND of thing owns it ("helm", "operator"): Manager names it, which is
	// what lets a report or a ticket point at the component to upgrade.
	Manager string
	// SourcePath is the directory within Source when Source is a repository.
	// Separate from the URL so consumers can render a clickable link; joining
	// them with kustomize's "//" notation produces a string that looks like a
	// URL and is not one.
	SourcePath string

	// Resolved reports whether the source actually obtained the list of
	// available versions. When false, Available being false means "we could not
	// find out" (e.g. a private registry whose tags we cannot list) and MUST NOT
	// be read as "already on the latest version" — an unreachable registry
	// otherwise reports every image it holds as up to date.
	Resolved bool
	// Newest is the furthest version available in track, when policy recommends
	// something nearer. Empty when they are the same. Reported so a ticket can say
	// "3.12.14 now, 3.14.7 when you are ready" rather than picking for the reader.
	Newest string
	// Strategy is how far this recommendation was allowed to move: patch, minor or
	// latest.
	Strategy string
	// Ceiling is the version prefix policy will not recommend beyond, with the reason
	// somebody gave for it. CeilingExpired reports a ceiling whose end date has
	// passed: it was NOT applied, and the constraint is due a revisit.
	Ceiling        string
	CeilingReason  string
	CeilingExpired bool
	// HeldBack is true when a newer version exists but policy recommends none of it.
	// Distinct from having no upgrade at all, which is what silence would imply.
	HeldBack bool
	// Rule names the upgrade rule that decided this, when one did. Reported because a
	// restrained recommendation and an exhausted one look identical otherwise: without
	// it, a reader cannot tell "policy says stop here" from "this is all there is".
	Rule string

	// FromRef and ToRef are the exact references a base differential would scan:
	// the base this image was actually built on, and the base this recommendation
	// would move it to. FromRef is digest-pinned whenever the build recorded one,
	// so the scan describes what the image was built on rather than whatever the
	// tag points at today.
	//
	// Populated only for Kind "base". ToRef is empty when there is nothing to move
	// to, and also when the recommendation belongs to a deeper link in the base
	// chain: ownership is still answerable from FromRef, but "what would this
	// upgrade fix" is a question about a different pair of images and must not be
	// answered by comparing the wrong two.
	FromRef string
	ToRef   string

	// Comparison says how the verdict was reached: "version" when tags were
	// compared, "digest" when the reference is a floating tag with no version and
	// the digest it resolves to was compared instead.
	//
	// Worth stating because it changes what the numbers mean. A digest comparison
	// reports two opaque hashes, so "1e37a823 -> c4b29bf3" is only intelligible
	// alongside the tag that moved.
	Comparison string
	// Reason explains an unresolved upgrade, in terms a reader can act on. "We
	// could not find out" is only useful with the "because": an unreadable registry
	// and an image that never recorded its base need different people to do
	// different things, and both are fixable once named.
	Reason string

	// Support is the maintenance status of the line this image is built on, when it
	// was checked. Nil means it was not: no support source ran, or the base image is
	// not one the source recognises. Nil MUST NOT be read as supported.
	Support *Support
	// OutOfTrack reports that Latest leaves the current major or minor line, because
	// that line is no longer maintained and staying on it has no upgrade path at all.
	//
	// Kept distinct from an ordinary upgrade because the work is different in kind: a
	// rebuild on a newer patch is a version bump, while crossing a runtime major is a
	// migration somebody has to plan. A queue that presents them identically gets one
	// of them wrong, and it is usually this one.
	OutOfTrack bool

	// Actionable reports whether the upgrade can be applied directly at this
	// level. A newer image tag for a workload managed by a Helm chart or an
	// operator is Available but NOT Actionable: the version is controlled
	// elsewhere (bump the chart/operator instead). Managed records why.
	Actionable bool
	Managed    string // controller that owns the version ("helm", "operator"), when not actionable
}

// Support is what is known about whether an image's underlying line is still
// maintained, and where a team could go instead.
//
// This exists because "no upgrade available" has two opposite meanings. On a maintained
// line it means "you are current", which is good news. On a dead one it means "nothing
// newer will ever be published", which is the worst news in the queue: every future CVE
// on that image is permanent. Both render as an empty Fix column unless the difference
// is carried explicitly, so it is carried here.
type Support struct {
	// Product is the software identified ("nodejs"), and Cycle the line it is on
	// ("20"). Reported so a reader can check the claim rather than trust it.
	Product string
	Cycle   string
	// EOL is when that line stops being maintained, as stated by the source. Empty
	// when no date was given.
	EOL string
	// Supported is the verdict, and Known says whether there was one to give. Known
	// false means the source had nothing to say about this line: the page must render
	// that as unchecked, never as supported.
	Supported bool
	Known     bool
	// Recommended is the newest line a team could adopt today: maintained, and
	// already long-term supported where the product designates LTS at all. Nearest
	// is the smallest supported move instead, so a ticket can offer both rather than
	// deciding how much migration somebody can afford.
	Recommended string
	Nearest     string
	// Newest is the newest line that exists, which is deliberately not always the
	// recommendation. A runtime's newest major is often one nobody should adopt yet,
	// and recommending it is how a tool earns the right to be ignored.
	Newest string
	// Source names who said so, for the same reason the rest of this struct exists:
	// an unattributed claim about somebody's runtime being dead invites an argument
	// rather than a fix.
	Source string
}

// Finding is the output unit: one image, one owner, and the verdict. An image
// running under multiple owners produces multiple findings so each team gets a
// precise, independently-actionable slice.
//
// Dimensions and Labels aggregate the per-occurrence values into the union of
// distinct values seen across this finding's occurrences, which is what policy
// rules evaluate against (e.g. "Production EU" in dimensions["account"]).
type Finding struct {
	Image       Image
	Counts      Counts
	Vulns       []Vulnerability
	RiskScore   float64
	Owner       Owner
	Occurrences []Occurrence        // the subset of the image's occurrences for this owner
	Dimensions  map[string][]string // union of dimension values across occurrences
	Labels      map[string][]string // union of label values across occurrences

	// Reconciled is set when liveness data was available for this finding.
	// Live reports whether any of the finding's workloads is actually running.
	Reconciled bool
	Live       bool

	// Scanned/ScanError mirror the assessed image: whether a vuln scan
	// succeeded, and why it didn't when attempted. ExploitChecked reports
	// whether exploit intel (EPSS/KEV) was gathered.
	Scanned        bool
	ScanError      string
	ExploitChecked bool

	// Fallback* and CountsSource mirror the assessed image: a scan run only
	// because the provider never assessed this image, and who produced Counts.
	// See AssessedImage for why these are not folded into Scanned/ScanError.
	FallbackSource  string
	FallbackScanned bool
	FallbackError   string
	CountsSource    string

	// Upgrade, when set, is the newer version available for how this image is
	// deployed (the remediation path). RemediationChecked reports whether
	// detection ran, so a nil Upgrade can be told apart from an unresolved one.
	Upgrade            *Upgrade
	RemediationChecked bool
	// InFlight is set when an open pull request would apply that upgrade.
	// InFlightChecked reports whether detection ran, and InFlightReason why an
	// image could never be matched.
	InFlight        *InFlight
	InFlightChecked bool
	InFlightReason  string
	// BaseDiff is what scanning this image's base established. Nil when the
	// differential did not run.
	BaseDiff *BaseDiff
	// BuildRepo is the source repository that built this image, when it records one.
	BuildRepo string
	// ImageBuilt is when the image was built, per its own config. Zero when unread
	// or unstated.
	ImageBuilt time.Time

	Actionable bool
	Suppressed bool
	Priority   string   // free-form, defined by policy config
	Reasons    []string // human-readable explanation of the verdict
}

// OldestVuln returns the earliest FirstSeen across this finding's CVEs, and whether
// any was known.
//
// The oldest is the interesting one: an image carrying a CVE since June has been
// exposed since June, whatever else has been added since.
func (f Finding) OldestVuln() (time.Time, bool) {
	var oldest time.Time
	for _, v := range f.Vulns {
		if v.FirstSeen.IsZero() {
			continue
		}
		if oldest.IsZero() || v.FirstSeen.Before(oldest) {
			oldest = v.FirstSeen
		}
	}
	return oldest, !oldest.IsZero()
}

// AssessmentIssues returns the distinct reasons this finding's workloads were not
// assessed, in the provider's own words, most common first.
//
// The point is to make a coverage gap diagnosable instead of merely countable.
// "This image was never assessed" invites a shrug; "Can't authenticate to the
// registry"
// names a credential someone can go and fix, and one such reason accounted for
// the overwhelming majority of an entire estate's missing coverage.
//
// Empty when every workload was assessed, or when the provider gives no reason.
func (f Finding) AssessmentIssues() []string {
	counts := map[string]int{}
	var order []string
	for _, o := range f.Occurrences {
		if o.Assessed || o.AssessmentError == "" {
			continue
		}
		if _, seen := counts[o.AssessmentError]; !seen {
			order = append(order, o.AssessmentError)
		}
		counts[o.AssessmentError]++
	}
	sort.SliceStable(order, func(i, j int) bool { return counts[order[i]] > counts[order[j]] })
	return order
}

// ProviderAssessed reports whether the scan provider assessed any of this
// finding's workloads. When false, Counts being zero reflects ignorance rather
// than health, and the report must not present it as a clean result.
//
// This is separate from Scanned (an optional vuln source) on purpose: a vuln
// source is off by default, so its absence says nothing about whether data
// exists, while a provider that never assessed an image is a real coverage gap.
func (f Finding) ProviderAssessed() bool {
	for _, o := range f.Occurrences {
		if o.Assessed {
			return true
		}
	}
	return false
}

// Exposure values. Unknown is its own answer: an estate where nothing reports
// reachability must not read as an estate where nothing is reachable.
const (
	ExposurePublic   = "public"
	ExposureInternal = "internal"
	ExposureUnknown  = "unknown"
)

// Exposure aggregates reachability across a finding's workloads. Any workload
// reachable from the internet makes the finding public: the image is exposed
// somewhere, and that is the fact that matters for prioritising it.
func (f Finding) Exposure() string {
	known := false
	for _, o := range f.Occurrences {
		if o.Exposed == nil {
			continue
		}
		known = true
		if *o.Exposed {
			return ExposurePublic
		}
	}
	if known {
		return ExposureInternal
	}
	return ExposureUnknown
}

// Signal names one notable fact about a finding, for display and for rules.
//
// A set rather than a column each: the table cannot grow a column per attribute,
// and a signal that is also available to policy can change the ordering instead of
// merely being readable.
const (
	SignalExposed      = "exposed"
	SignalKnownExploit = "kev"
	SignalInFlight     = "in-flight"
	SignalStaleFix     = "stale-fix"
	SignalUnassessed   = "unassessed"
	SignalSuppressed   = "suppressed"
	// SignalFallbackScan marks a finding whose counts came from the fallback
	// scanner rather than the scan provider, because the provider never assessed
	// the image.
	//
	// It rides ALONGSIDE unassessed rather than replacing it: the coverage gap is
	// still a coverage gap, and the numbers on the row are from a different feed
	// than every other row. A reader comparing this row's criticals against the one
	// above it is comparing two scanners, and has to be told so.
	SignalFallbackScan = "fallback-scan"
	// SignalEndOfLife marks a finding whose base image sits on a line nobody
	// maintains any more. It is a statement about the FUTURE, which no severity count
	// captures: the CVEs on it today are the fewest it will ever have, because no
	// further fix is coming to that tag.
	SignalEndOfLife = "end-of-life"
)

// Signals lists what is notable about this finding, in a stable order.
//
// Every signal is a positive statement. Absence of a signal never asserts the
// opposite: no "exposed" signal covers both an internal workload and one whose
// reachability nobody reported, which is why Exposure() exists alongside this.
func (f Finding) Signals() []string {
	var out []string
	if f.Exposure() == ExposurePublic {
		out = append(out, SignalExposed)
	}
	for _, v := range f.Vulns {
		if v.KEV {
			out = append(out, SignalKnownExploit)
			break
		}
	}
	if f.InFlight != nil {
		out = append(out, SignalInFlight)
		if f.InFlight.Stale {
			out = append(out, SignalStaleFix)
		}
	}
	if !f.ProviderAssessed() {
		out = append(out, SignalUnassessed)
	}
	if f.FallbackScanned {
		out = append(out, SignalFallbackScan)
	}
	if f.Suppressed {
		out = append(out, SignalSuppressed)
	}
	if f.Upgrade != nil && f.Upgrade.Support != nil {
		st := f.Upgrade.Support
		// Known AND unsupported. An unchecked line asserts nothing, and a signal is a
		// positive statement: emitting one on missing data would let rules act on an
		// absence.
		if st.Known && !st.Supported {
			out = append(out, SignalEndOfLife)
		}
	}
	return out
}

// Sources is which optional stages an assessment was CONFIGURED with.
//
// Separate from whether they produced anything, and the distinction is the whole
// point. A run with no vuln source reports zero CVEs, and so does a run whose
// scanner was refused by every registry; without this, the two are one number and a
// reader blames the wrong thing. On the first real MCP session against this, a model
// was told "0 of 817 scanned" and concluded the scan provider was broken, when the
// run simply had no --vuln-source.
//
// Empty strings and false mean NOT CONFIGURED, which is why an absent value here can
// safely be read as "we never asked" - the one absence in this codebase that is
// unambiguous.
type Sources struct {
	Provider   string
	VulnSource string
	// FallbackVulnSource is the source asked about images the provider never
	// assessed. Empty means no fallback was configured, so an unassessed image is
	// unassessed full stop - which is a different report from one where the
	// fallback ran and could not pull the image either.
	FallbackVulnSource string
	ExploitSource      string
	AgeSource          string
	LiveSource         string
	SupportSource      string

	// Remediation is whether upgrades were looked for at all; BaseDiff whether base
	// images were scanned to establish what an upgrade clears; InFlight whether open
	// pull requests were matched; Exposure whether internet reachability was measured.
	Remediation bool
	BaseDiff    bool
	InFlight    bool
	Exposure    bool

	// ScanDisabled records config turning scanning off despite a source being named,
	// which otherwise looks exactly like no source at all.
	ScanDisabled bool
}

// SourceFailure is an enrichment that could not run.
//
// An enrichment is not the assessment, so losing one does not lose the other — but the
// absence has to be visible. A missing signal nobody can see looks exactly like a signal
// that found nothing, and on this estate the two lead to opposite conclusions: "no
// exploited CVEs" and "we could not ask about exploitation" are not the same sentence.
type SourceFailure struct {
	// Stage is what could not run: "exploit", "age".
	Stage string
	// Error is the reason, as reported, so somebody can act on it rather than only
	// know that something went wrong.
	Error string
}
