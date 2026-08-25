package sink

import (
	"encoding/json"
	"io"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// JSON renders findings as a stable JSON array for machine consumers (later
// phases: Jira, GitOps). It emits a purpose-built view rather than the internal
// model so the output format is decoupled from internal types. Suppressed
// findings are included only when ShowSuppressed is set.
type JSON struct {
	ShowSuppressed bool
	Indent         bool
}

type FindingView struct {
	Image      string         `json:"image"`
	Registry   string         `json:"registry"`
	Repository string         `json:"repository"`
	Tag        string         `json:"tag,omitempty"`
	Digest     string         `json:"digest,omitempty"`
	Owner      OwnerView      `json:"owner"`
	Counts     map[string]int `json:"counts"`
	Risk       float64        `json:"risk"`
	Actionable bool           `json:"actionable"`
	Suppressed bool           `json:"suppressed"`
	Priority   string         `json:"priority,omitempty"`
	Reasons    []string       `json:"reasons"`
	// Exposure is "public", "internal" or "unknown": reachability from the internet
	// where something reports it. Unknown is a real answer and must not be read as
	// internal.
	Exposure string `json:"exposure"`
	// Signals are the notable facts about this finding (exposed, kev, in-flight,
	// stale-fix, unassessed, suppressed). Each is a positive statement; absence
	// asserts nothing.
	Signals         []string `json:"signals,omitempty"`
	WorkloadCount   int      `json:"workload_count"`
	FixableCritical int      `json:"fixable_critical,omitempty"`
	KnownExploited  bool     `json:"known_exploited,omitempty"`
	// ProviderAssessed is false when the scan provider never assessed the image,
	// making Counts zero through ignorance rather than health. Consumers MUST
	// check this before treating zero counts as a clean result.
	ProviderAssessed bool `json:"provider_assessed"`
	// AssessmentIssues are the provider's own reasons this image was not
	// assessed, most common first. Present so a consumer can act on a coverage
	// gap rather than only count it: these say "fix this credential", where
	// provider_assessed:false only says "we do not know".
	AssessmentIssues []string `json:"assessment_issues,omitempty"`
	// Scanned and ExploitChecked are always emitted (no omitempty): false is
	// the meaningful value. Without them an empty vulns list is ambiguous —
	// a consumer cannot tell "scanned, nothing found" from "never scanned"
	// (skipped by config, or no --vuln-source at all).
	Scanned        bool   `json:"scanned"`
	ExploitChecked bool   `json:"exploit_checked"`
	ScanError      string `json:"scan_error,omitempty"`
	// OldestCVEDays is how long the earliest-known CVE on this image has been known
	// to the scan provider. Nil when no CVE has a date — no age source ran, or the
	// provider has never seen these CVEs. Zero and unknown are different answers, so
	// this is a pointer rather than a 0.
	OldestCVEDays *int       `json:"oldest_cve_days,omitempty"`
	OldestCVESeen *time.Time `json:"oldest_cve_first_seen,omitempty"`

	// RemediationChecked distinguishes "no upgrade found" from "we never looked".
	// A consumer that skips findings without an upgrade MUST check this, or it
	// will silently skip images whose versions simply could not be resolved.
	RemediationChecked bool         `json:"remediation_checked"`
	Upgrade            *UpgradeView `json:"upgrade,omitempty"`
	// InFlight is set when an open pull request would apply this finding's
	// upgrade. Absent means no pull request was matched, which includes the case
	// where in-flight detection did not run at all — consumers must not read its
	// absence as "nobody is working on this".
	InFlight *InFlightView `json:"in_flight,omitempty"`
	// InFlightChecked distinguishes "no pull request found" from "we never looked".
	// Always emitted: false is the meaningful value.
	InFlightChecked bool `json:"in_flight_checked"`
	// InFlightReason explains an image that can never be matched (it records no
	// build repository), as opposed to one with no open pull request.
	InFlightReason string              `json:"in_flight_reason,omitempty"`
	Liveness       *LivenessView       `json:"liveness,omitempty"`
	Dimensions     map[string][]string `json:"dimensions"`
	Labels         map[string][]string `json:"labels,omitempty"`
	Vulns          []VulnView          `json:"vulns,omitempty"`
}

// LivenessView is emitted only when reconciliation ran, so output for
// un-reconciled runs is unchanged.
type LivenessView struct {
	Live bool `json:"live"`
}

// OwnerView is the attributed owner of a finding.
type OwnerView struct {
	Class string `json:"class"`
	Team  string `json:"team"`
	Rule  string `json:"rule,omitempty"`
}

// UpgradeView is the newer version available for how an image is deployed.
type UpgradeView struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Current   string `json:"current"`
	Latest    string `json:"latest,omitempty"`
	Available bool   `json:"available"`
	Resolved  bool   `json:"resolved"`
	// Newest is the furthest version available when the recommendation is nearer,
	// so a consumer can offer both: the patch to take now, and the migration to plan.
	// Absent when they are the same.
	Newest string `json:"newest,omitempty"`
	// Strategy is how far the recommendation was allowed to move: patch, minor, latest.
	Strategy string `json:"strategy,omitempty"`
	// Ceiling is the version prefix policy will not go beyond, and CeilingReason why.
	// CeilingExpired marks a ceiling whose end date has passed — it was not applied.
	Ceiling        string `json:"ceiling,omitempty"`
	CeilingReason  string `json:"ceiling_reason,omitempty"`
	CeilingExpired bool   `json:"ceiling_expired,omitempty"`
	// HeldBack is true when newer versions exist and policy recommends none of them.
	// Without it, "no upgrade available" and "held back deliberately" look identical.
	HeldBack bool `json:"held_back,omitempty"`

	// Comparison is "version" or "digest": how the verdict was reached. A digest
	// comparison means the reference is a floating tag, so current and latest are
	// short digests rather than versions.
	Comparison string `json:"comparison,omitempty"`
	// Reason explains an unresolved upgrade: what stopped the lookup, and therefore
	// what would fix it. An unreadable registry and an image that never recorded its
	// base need different people to do different things.
	Reason     string `json:"reason,omitempty"`
	Actionable bool   `json:"actionable"`
	Managed    string `json:"managed,omitempty"`
	Manager    string `json:"manager,omitempty"`
	Source     string `json:"source,omitempty"`
	SourcePath string `json:"source_path,omitempty"`
}

// InFlightView is remediation already under way for a finding.
type InFlightView struct {
	// Repository is the repository the pull request is in, which is the repository
	// that builds this image.
	Repository string    `json:"repository"`
	Title      string    `json:"title"`
	URL        string    `json:"url,omitempty"`
	Author     string    `json:"author,omitempty"`
	Opened     time.Time `json:"opened"`
	OpenDays   int       `json:"open_days"`
	// Stale is true when the pull request has been open past the configured
	// threshold: a fix nobody merged in months, rather than progress.
	Stale bool `json:"stale"`
	// Exact is false when the pull request bumps the same dependency to a
	// different version than the one recommended. Consumers MUST NOT treat a
	// non-exact match as this upgrade being applied.
	Exact bool `json:"exact"`
}

// VulnView is one CVE affecting an image.
type VulnView struct {
	ID           string     `json:"id"`
	Severity     string     `json:"severity"`
	FirstSeen    *time.Time `json:"first_seen,omitempty"`
	CVSS         float64    `json:"cvss,omitempty"`
	FixAvailable bool       `json:"fix_available"`
	FixedVersion string     `json:"fixed_version,omitempty"`
	EPSS         float64    `json:"epss,omitempty"`
	KEV          bool       `json:"kev,omitempty"`
	// RiskScore is the scan provider's own composite ranking, on its own scale
	// (Rapid7's is roughly 0..1000). Not comparable with epss, which is a
	// probability. Absent means unscored.
	RiskScore    float64 `json:"risk_score,omitempty"`
	ExploitKnown bool    `json:"exploit_known,omitempty"`
}

// Emit implements Sink.
func (j JSON) Emit(w io.Writer, findings []model.Finding) error {
	findings = SortForReport(findings)
	views := make([]FindingView, 0, len(findings))
	for _, f := range findings {
		if f.Suppressed && !j.ShowSuppressed {
			continue
		}
		views = append(views, ToFindingView(f))
	}

	enc := json.NewEncoder(w)
	if j.Indent {
		enc.SetIndent("", "  ")
	}
	enc.SetEscapeHTML(false)
	return enc.Encode(views)
}

// NDJSON renders findings as newline-delimited JSON — one finding object per
// line. This is the log-friendly format for deployed runs: monitoring/log
// pipelines parse each line as a self-contained record, unlike the pretty
// (multi-line) JSON array. Suppressed findings are included only when
// ShowSuppressed is set.
type NDJSON struct {
	ShowSuppressed bool
}

// Emit implements Sink.
func (n NDJSON) Emit(w io.Writer, findings []model.Finding) error {
	findings = SortForReport(findings)
	enc := json.NewEncoder(w) // Encode writes one compact object + "\n" per call
	enc.SetEscapeHTML(false)
	for _, f := range findings {
		if f.Suppressed && !n.ShowSuppressed {
			continue
		}
		if err := enc.Encode(ToFindingView(f)); err != nil {
			return err
		}
	}
	return nil
}

func ToFindingView(f model.Finding) FindingView {
	vulns := make([]VulnView, 0, len(f.Vulns))
	knownExploited := false
	for _, v := range f.Vulns {
		if v.KEV {
			knownExploited = true
		}
		vulns = append(vulns, VulnView{
			ID:           v.ID,
			Severity:     v.Severity,
			FirstSeen:    firstSeen(v),
			CVSS:         v.CVSS,
			FixAvailable: v.FixAvailable,
			FixedVersion: v.FixedVersion,
			EPSS:         v.EPSS,
			KEV:          v.KEV,
			RiskScore:    v.RiskScore,
			ExploitKnown: v.ExploitKnown,
		})
	}
	var liveness *LivenessView
	if f.Reconciled {
		liveness = &LivenessView{Live: f.Live}
	}
	// Dated from the oldest known CVE: an image carrying one since June has been
	// exposed since June, whatever was added later.
	var oldestDays *int
	var oldestSeen *time.Time
	if t, ok := f.OldestVuln(); ok {
		days := int(time.Since(t).Hours() / 24)
		oldestDays, oldestSeen = &days, &t
	}
	var upgrade *UpgradeView
	if f.Upgrade != nil {
		upgrade = &UpgradeView{
			Kind: f.Upgrade.Kind, Name: f.Upgrade.Name,
			Current: f.Upgrade.Current, Latest: f.Upgrade.Latest,
			Available: f.Upgrade.Available, Resolved: f.Upgrade.Resolved,
			Reason:         f.Upgrade.Reason,
			Newest:         f.Upgrade.Newest,
			Strategy:       f.Upgrade.Strategy,
			Ceiling:        f.Upgrade.Ceiling,
			CeilingReason:  f.Upgrade.CeilingReason,
			CeilingExpired: f.Upgrade.CeilingExpired,
			HeldBack:       f.Upgrade.HeldBack,
			Comparison:     f.Upgrade.Comparison,
			Actionable:     f.Upgrade.Actionable,
			Managed:        f.Upgrade.Managed, Manager: f.Upgrade.Manager,
			Source: f.Upgrade.Source, SourcePath: f.Upgrade.SourcePath,
		}
	}
	var inflight *InFlightView
	if f.InFlight != nil {
		inflight = &InFlightView{
			Repository: f.InFlight.Repository, Title: f.InFlight.Title,
			URL: f.InFlight.URL, Author: f.InFlight.Author,
			Opened:   f.InFlight.Opened,
			OpenDays: int(f.InFlight.Age().Hours() / 24),
			Stale:    f.InFlight.Stale,
			Exact:    f.InFlight.Exact,
		}
	}
	return FindingView{
		Image:              f.Image.Ref,
		Registry:           f.Image.Registry,
		Repository:         f.Image.Repository,
		Tag:                f.Image.Tag,
		Digest:             f.Image.Digest,
		Owner:              OwnerView{Class: f.Owner.Class, Team: f.Owner.Team, Rule: f.Owner.Rule},
		Counts:             map[string]int(f.Counts),
		Risk:               f.RiskScore,
		Actionable:         f.Actionable,
		Suppressed:         f.Suppressed,
		Priority:           f.Priority,
		Reasons:            f.Reasons,
		Exposure:           f.Exposure(),
		Signals:            f.Signals(),
		WorkloadCount:      len(f.Occurrences),
		FixableCritical:    fixableCriticals(f),
		KnownExploited:     knownExploited,
		ProviderAssessed:   f.ProviderAssessed(),
		AssessmentIssues:   f.AssessmentIssues(),
		Scanned:            f.Scanned,
		ExploitChecked:     f.ExploitChecked,
		ScanError:          f.ScanError,
		OldestCVEDays:      oldestDays,
		OldestCVESeen:      oldestSeen,
		RemediationChecked: f.RemediationChecked,
		Liveness:           liveness,
		Upgrade:            upgrade,
		InFlight:           inflight,
		InFlightChecked:    f.InFlightChecked,
		InFlightReason:     f.InFlightReason,
		Dimensions:         f.Dimensions,
		Labels:             f.Labels,
		Vulns:              vulns,
	}
}

// firstSeen returns the CVE's first-seen time, or nil when unknown — never a zero
// time, which would render as 1970 and sort as the oldest thing in the queue.
func firstSeen(v model.Vulnerability) *time.Time {
	if v.FirstSeen.IsZero() {
		return nil
	}
	t := v.FirstSeen
	return &t
}
