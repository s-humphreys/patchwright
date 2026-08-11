package sink

import (
	"encoding/json"
	"io"

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
	Image           string         `json:"image"`
	Registry        string         `json:"registry"`
	Repository      string         `json:"repository"`
	Tag             string         `json:"tag,omitempty"`
	Digest          string         `json:"digest,omitempty"`
	Owner           OwnerView      `json:"owner"`
	Counts          map[string]int `json:"counts"`
	Risk            float64        `json:"risk"`
	Actionable      bool           `json:"actionable"`
	Suppressed      bool           `json:"suppressed"`
	Priority        string         `json:"priority,omitempty"`
	Reasons         []string       `json:"reasons"`
	WorkloadCount   int            `json:"workload_count"`
	FixableCritical int            `json:"fixable_critical,omitempty"`
	KnownExploited  bool           `json:"known_exploited,omitempty"`
	// ProviderAssessed is false when the scan provider never assessed the image,
	// making Counts zero through ignorance rather than health. Consumers MUST
	// check this before treating zero counts as a clean result.
	ProviderAssessed bool `json:"provider_assessed"`
	// Scanned and ExploitChecked are always emitted (no omitempty): false is
	// the meaningful value. Without them an empty vulns list is ambiguous —
	// a consumer cannot tell "scanned, nothing found" from "never scanned"
	// (skipped by config, or no --vuln-source at all).
	Scanned        bool   `json:"scanned"`
	ExploitChecked bool   `json:"exploit_checked"`
	ScanError      string `json:"scan_error,omitempty"`
	// RemediationChecked distinguishes "no upgrade found" from "we never looked".
	// A consumer that skips findings without an upgrade MUST check this, or it
	// will silently skip images whose versions simply could not be resolved.
	RemediationChecked bool                `json:"remediation_checked"`
	Upgrade            *UpgradeView        `json:"upgrade,omitempty"`
	Liveness           *LivenessView       `json:"liveness,omitempty"`
	Dimensions         map[string][]string `json:"dimensions"`
	Labels             map[string][]string `json:"labels,omitempty"`
	Vulns              []VulnView          `json:"vulns,omitempty"`
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
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Current    string `json:"current"`
	Latest     string `json:"latest,omitempty"`
	Available  bool   `json:"available"`
	Resolved   bool   `json:"resolved"`
	Actionable bool   `json:"actionable"`
	Managed    string `json:"managed,omitempty"`
	Manager    string `json:"manager,omitempty"`
	Source     string `json:"source,omitempty"`
	SourcePath string `json:"source_path,omitempty"`
}

// VulnView is one CVE affecting an image.
type VulnView struct {
	ID           string  `json:"id"`
	Severity     string  `json:"severity"`
	CVSS         float64 `json:"cvss,omitempty"`
	FixAvailable bool    `json:"fix_available"`
	FixedVersion string  `json:"fixed_version,omitempty"`
	EPSS         float64 `json:"epss,omitempty"`
	KEV          bool    `json:"kev,omitempty"`
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
			CVSS:         v.CVSS,
			FixAvailable: v.FixAvailable,
			FixedVersion: v.FixedVersion,
			EPSS:         v.EPSS,
			KEV:          v.KEV,
		})
	}
	var liveness *LivenessView
	if f.Reconciled {
		liveness = &LivenessView{Live: f.Live}
	}
	var upgrade *UpgradeView
	if f.Upgrade != nil {
		upgrade = &UpgradeView{
			Kind: f.Upgrade.Kind, Name: f.Upgrade.Name,
			Current: f.Upgrade.Current, Latest: f.Upgrade.Latest,
			Available: f.Upgrade.Available, Resolved: f.Upgrade.Resolved,
			Actionable: f.Upgrade.Actionable,
			Managed:    f.Upgrade.Managed, Manager: f.Upgrade.Manager,
			Source: f.Upgrade.Source, SourcePath: f.Upgrade.SourcePath,
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
		WorkloadCount:      len(f.Occurrences),
		FixableCritical:    fixableCriticals(f),
		KnownExploited:     knownExploited,
		ProviderAssessed:   f.ProviderAssessed(),
		Scanned:            f.Scanned,
		ExploitChecked:     f.ExploitChecked,
		ScanError:          f.ScanError,
		RemediationChecked: f.RemediationChecked,
		Liveness:           liveness,
		Upgrade:            upgrade,
		Dimensions:         f.Dimensions,
		Labels:             f.Labels,
		Vulns:              vulns,
	}
}
