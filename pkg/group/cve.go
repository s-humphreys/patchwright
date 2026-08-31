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
	return aggregate(findings, withAffected, "")
}

// aggregate is the rollup behind both CVEs and FindCVE.
//
// `only` narrows it to one CVE id. That exists for a measured reason: answering "tell
// me about CVE-2026-1234" used to build the entire estate's rollup with every affected
// image and then pick one row out of it - 120ms and 117MB of allocation, per request,
// to produce a few kilobytes. Narrowing first makes it a single pass and a few
// allocations, and it is the same code, so the one-CVE answer cannot drift from the
// row in the list.
func aggregate(findings []sink.FindingView, withAffected bool, only string) []CVE {
	scanned, total := 0, len(findings)
	// One map, and the sets hang off the row rather than living in three parallel maps
	// keyed by the same id. That was three hash lookups and three map writes per
	// occurrence - 208,697 times on a real estate.
	byID := make(map[string]*cveAccumulator, expectedCVEs(findings, only))

	for _, f := range findings {
		if !f.Scanned {
			continue
		}
		scanned++
		for _, v := range f.Vulns {
			if only != "" && !strings.EqualFold(v.ID, only) {
				continue
			}
			c := byID[v.ID]
			if c == nil {
				c = &cveAccumulator{CVE: CVE{ID: v.ID, Severity: v.Severity}}
				byID[v.ID] = c
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
			c.teams.add(f.Owner.Team)
			c.services.add(f.Owner.Team + "|" + f.Repository)
			c.fixedVersions.add(v.FixedVersion)
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
	for _, c := range byID {
		c.Teams = c.teams.sorted()
		c.Services = len(c.services.m)
		c.FixedVersions = c.fixedVersions.sorted()
		c.ScannedImages, c.TotalImages = scanned, total
		sort.Slice(c.Affected, func(i, j int) bool { return c.Affected[i].Image < c.Affected[j].Image })
		out = append(out, c.CVE)
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
	want := strings.TrimSpace(id)
	if want == "" {
		return nil
	}
	rows := aggregate(findings, true, want)
	if len(rows) == 0 {
		return nil
	}
	// At most one row: the aggregation is keyed by id and only that id was collected.
	return &rows[0]
}

// cveAccumulator is a row being built, with the sets it needs while building.
//
// The sets are here rather than in maps keyed by CVE id so that adding a team costs
// one pointer dereference instead of a hash lookup. On a real estate that is 208,697
// occurrences times three maps.
type cveAccumulator struct {
	CVE
	teams         set
	services      set
	fixedVersions set
}

// expectedCVEs sizes the map so it does not rehash its way up from nothing.
//
// A guess, deliberately rough: on the estate this was measured against, 208,697
// occurrences were about 10,000 distinct CVEs, so a twentieth of the occurrence count
// is a reasonable starting capacity. Narrowed to one id, one entry is all it needs.
func expectedCVEs(findings []sink.FindingView, only string) int {
	if only != "" {
		return 1
	}
	var occurrences int
	for _, f := range findings {
		occurrences += len(f.Vulns)
	}
	if n := occurrences / 20; n > 0 {
		return n
	}
	return len(findings)
}
