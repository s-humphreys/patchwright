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
	KEV  bool
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

	// InFlight is set when an open pull request would apply this image's upgrade.
	// InFlightChecked reports whether detection ran, so a nil InFlight can be told
	// apart from "nobody has started this".
	InFlight        *InFlight
	InFlightChecked bool

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

	// Actionable reports whether the upgrade can be applied directly at this
	// level. A newer image tag for a workload managed by a Helm chart or an
	// operator is Available but NOT Actionable: the version is controlled
	// elsewhere (bump the chart/operator instead). Managed records why.
	Actionable bool
	Managed    string // controller that owns the version ("helm", "operator"), when not actionable
}

// Finding is the output unit: one image, one owner, and the verdict. An image
// running under multiple owners produces multiple findings so each team gets a
// precise, independently-actionable slice.
//
// Dimensions and Labels aggregate the per-occurrence values into the union of
// distinct values seen across this finding's occurrences, which is what policy
// rules evaluate against (e.g. "Production UK" in dimensions["account"]).
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

	// Upgrade, when set, is the newer version available for how this image is
	// deployed (the remediation path). RemediationChecked reports whether
	// detection ran, so a nil Upgrade can be told apart from an unresolved one.
	Upgrade            *Upgrade
	RemediationChecked bool
	// InFlight is set when an open pull request would apply that upgrade.
	// InFlightChecked reports whether detection ran.
	InFlight        *InFlight
	InFlightChecked bool

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
