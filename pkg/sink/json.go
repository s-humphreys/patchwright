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

type findingView struct {
	Image           string              `json:"image"`
	Registry        string              `json:"registry"`
	Repository      string              `json:"repository"`
	Tag             string              `json:"tag,omitempty"`
	Digest          string              `json:"digest,omitempty"`
	Owner           ownerView           `json:"owner"`
	Counts          map[string]int      `json:"counts"`
	Risk            float64             `json:"risk"`
	Actionable      bool                `json:"actionable"`
	Suppressed      bool                `json:"suppressed"`
	Priority        string              `json:"priority,omitempty"`
	Reasons         []string            `json:"reasons"`
	WorkloadCount   int                 `json:"workload_count"`
	FixableCritical int                 `json:"fixable_critical,omitempty"`
	KnownExploited  bool                `json:"known_exploited,omitempty"`
	ScanError       string              `json:"scan_error,omitempty"`
	Upgrade         *upgradeView        `json:"upgrade,omitempty"`
	Liveness        *livenessView       `json:"liveness,omitempty"`
	Dimensions      map[string][]string `json:"dimensions"`
	Vulns           []vulnView          `json:"vulns,omitempty"`
}

// livenessView is emitted only when reconciliation ran, so output for
// un-reconciled runs is unchanged.
type livenessView struct {
	Live bool `json:"live"`
}

type ownerView struct {
	Class string `json:"class"`
	Team  string `json:"team"`
	Rule  string `json:"rule,omitempty"`
}

type upgradeView struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Current   string `json:"current"`
	Latest    string `json:"latest,omitempty"`
	Available bool   `json:"available"`
	Source    string `json:"source,omitempty"`
}

type vulnView struct {
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
	views := make([]findingView, 0, len(findings))
	for _, f := range findings {
		if f.Suppressed && !j.ShowSuppressed {
			continue
		}
		views = append(views, toView(f))
	}

	enc := json.NewEncoder(w)
	if j.Indent {
		enc.SetIndent("", "  ")
	}
	enc.SetEscapeHTML(false)
	return enc.Encode(views)
}

func toView(f model.Finding) findingView {
	vulns := make([]vulnView, 0, len(f.Vulns))
	knownExploited := false
	for _, v := range f.Vulns {
		if v.KEV {
			knownExploited = true
		}
		vulns = append(vulns, vulnView{
			ID:           v.ID,
			Severity:     v.Severity,
			CVSS:         v.CVSS,
			FixAvailable: v.FixAvailable,
			FixedVersion: v.FixedVersion,
			EPSS:         v.EPSS,
			KEV:          v.KEV,
		})
	}
	var liveness *livenessView
	if f.Reconciled {
		liveness = &livenessView{Live: f.Live}
	}
	var upgrade *upgradeView
	if f.Upgrade != nil {
		upgrade = &upgradeView{
			Kind: f.Upgrade.Kind, Name: f.Upgrade.Name,
			Current: f.Upgrade.Current, Latest: f.Upgrade.Latest,
			Available: f.Upgrade.Available, Source: f.Upgrade.Source,
		}
	}
	return findingView{
		Image:           f.Image.Ref,
		Registry:        f.Image.Registry,
		Repository:      f.Image.Repository,
		Tag:             f.Image.Tag,
		Digest:          f.Image.Digest,
		Owner:           ownerView{Class: f.Owner.Class, Team: f.Owner.Team, Rule: f.Owner.Rule},
		Counts:          map[string]int(f.Counts),
		Risk:            f.RiskScore,
		Actionable:      f.Actionable,
		Suppressed:      f.Suppressed,
		Priority:        f.Priority,
		Reasons:         f.Reasons,
		WorkloadCount:   len(f.Occurrences),
		FixableCritical: fixableCriticals(f),
		KnownExploited:  knownExploited,
		ScanError:       f.ScanError,
		Liveness:        liveness,
		Upgrade:         upgrade,
		Dimensions:      f.Dimensions,
		Vulns:           vulns,
	}
}
