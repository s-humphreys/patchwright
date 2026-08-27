package group

import (
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// CVE is one vulnerability across the estate: how bad, how far it reaches, and how
// much of that reach has a fix.
//
// This is the question a security team asks and the queue cannot answer: the queue is
// per service, so "how many images carry this CVE" means reading every row.
type CVE struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// CVSS, EPSS and RiskScore are the worst reported anywhere. Zero means nothing
	// reported one — for EPSS that means no exploit source ran, not a low score.
	CVSS      float64 `json:"cvss,omitempty"`
	EPSS      float64 `json:"epss,omitempty"`
	RiskScore float64 `json:"risk_score,omitempty"`
	KEV       bool    `json:"kev"`

	// Images and Services are the two scope numbers, and they answer different
	// questions: images is how many deployments carry it, services how many pieces of
	// work fixing it takes. One base image CVE on hundreds of images is a handful of rebuilds.
	Images   int `json:"images"`
	Services int `json:"services"`
	// Fixable is how many affected images have a published fix. Short of Images means
	// part of the reach is waiting on upstream rather than on anybody here.
	Fixable int `json:"fixable"`
	// Teams are the owners who would be involved.
	Teams []string `json:"teams,omitempty"`
	// FixedVersions are the versions that resolve it, as reported per image.
	FixedVersions []string `json:"fixed_versions,omitempty"`
	// Affected lists every image carrying it. Populated by CVEDetail, omitted from
	// the list view: 10,000 CVEs each carrying 500 references is a payload nobody
	// asked for.
	Affected []Affected `json:"affected,omitempty"`

	// ScannedImages and TotalImages describe what this was aggregated over. A CVE
	// list built from a third of the estate is not the estate, and a consumer cannot
	// tell without being told.
	ScannedImages int `json:"scanned_images"`
	TotalImages   int `json:"total_images"`
}

// Affected is one image carrying a CVE.
type Affected struct {
	Image      string `json:"image"`
	Repository string `json:"repository"`
	Team       string `json:"team,omitempty"`
	// FixedVersion is the version resolving it for this image, empty when none is
	// published — the distinction between waiting and neglected.
	FixedVersion string `json:"fixed_version,omitempty"`
	// FixPath is where this image's own upgrade would be applied, so a scope list
	// doubles as a work list.
	FixPath  string   `json:"fix_path,omitempty"`
	Priority string   `json:"priority,omitempty"`
	Accounts []string `json:"accounts,omitempty"`
}

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

// CVEs inverts findings into vulnerabilities, worst first: known-exploited, then
// severity, then exploitation pressure, then reach.
//
// Only scanned findings carry per-CVE detail, so the count of what was aggregated over
// travels with every row rather than being left for the caller to assume.
func CVEs(findings []sink.FindingView, withAffected bool) []CVE {
	scanned, total := 0, len(findings)
	byID := map[string]*CVE{}
	teams := map[string]*set{}
	services := map[string]*set{}
	fixedVersions := map[string]*set{}

	for _, f := range findings {
		if !f.Scanned {
			continue
		}
		scanned++
		for _, v := range f.Vulns {
			c := byID[v.ID]
			if c == nil {
				c = &CVE{ID: v.ID, Severity: v.Severity}
				byID[v.ID] = c
				teams[v.ID], services[v.ID], fixedVersions[v.ID] = &set{}, &set{}, &set{}
			}
			// The worst rating reported anywhere: the same CVE is rated differently
			// by distro, and the urgent rating is the one that matters.
			if severityRank[v.Severity] > severityRank[c.Severity] {
				c.Severity = v.Severity
			}
			if v.CVSS > c.CVSS {
				c.CVSS = v.CVSS
			}
			if v.EPSS > c.EPSS {
				c.EPSS = v.EPSS
			}
			if v.RiskScore > c.RiskScore {
				c.RiskScore = v.RiskScore
			}
			c.KEV = c.KEV || v.KEV
			c.Images++
			if v.FixAvailable {
				c.Fixable++
			}
			teams[v.ID].add(f.Owner.Team)
			services[v.ID].add(f.Owner.Team + "|" + f.Repository)
			fixedVersions[v.ID].add(v.FixedVersion)
			if withAffected {
				c.Affected = append(c.Affected, Affected{
					Image: f.Image, Repository: f.Repository, Team: f.Owner.Team,
					FixedVersion: v.FixedVersion, FixPath: fixPath(f),
					Priority: f.Priority, Accounts: f.Dimensions["account"],
				})
			}
		}
	}

	out := make([]CVE, 0, len(byID))
	for id, c := range byID {
		c.Teams = teams[id].sorted()
		c.Services = len(services[id].m)
		c.FixedVersions = fixedVersions[id].sorted()
		c.ScannedImages, c.TotalImages = scanned, total
		sort.Slice(c.Affected, func(i, j int) bool { return c.Affected[i].Image < c.Affected[j].Image })
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		if a.Images != b.Images {
			return a.Images > b.Images
		}
		return a.ID < b.ID
	})
	return out
}

// fixPath mirrors the queue's fix column, so a CVE's scope list says where each
// image's fix would be applied rather than only that one exists.
func fixPath(f sink.FindingView) string {
	if !f.RemediationChecked {
		return "unchecked"
	}
	if f.Upgrade == nil || !f.Upgrade.Resolved {
		return "unknown"
	}
	if !f.Upgrade.Available {
		return "none"
	}
	if f.Upgrade.Actionable {
		return "direct"
	}
	return "managed"
}

// FindCVE returns one CVE with every affected image, or nil when nothing scanned
// carries it. Nil is not "no such CVE": an unscanned estate carries no CVEs here at
// all, which is why ScannedImages travels with the answer.
func FindCVE(findings []sink.FindingView, id string) *CVE {
	want := strings.ToUpper(strings.TrimSpace(id))
	for _, c := range CVEs(findings, true) {
		if strings.ToUpper(c.ID) == want {
			out := c
			return &out
		}
	}
	return nil
}
