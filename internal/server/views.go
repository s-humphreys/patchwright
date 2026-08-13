package server

import (
	"sort"
	"time"

	"github.com/s-humphreys/patchwright/internal/metrics"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// summaryView is the fleet-wide headline.
//
// Every count except Suppressed and UniqueImages is over the unsuppressed
// findings, so ProviderAssessed + ProviderUnassessed == Findings and a client can
// verify the arithmetic rather than guess at denominators.
type summaryView struct {
	Findings       int `json:"findings"`
	Actionable     int `json:"actionable"`
	Suppressed     int `json:"suppressed"`
	KnownExploited int `json:"known_exploited"`
	Upgradable     int `json:"upgradable"` // actionable upgrade available
	UniqueImages   int `json:"unique_images"`

	// Coverage. Without these, a client reading "N actionable" cannot tell a
	// healthy estate from one the scan provider never looked at, and every
	// consumer of this API would have to rediscover that on its own. On a real
	// estate this was 98 assessed out of 820, so the difference is not academic.
	//
	// ProviderAssessed counts findings the scan provider actually assessed;
	// ProviderUnassessed is the rest, whose zero severity counts mean absence of
	// data rather than health. RemediationUnresolved counts findings where no
	// available version could be determined, so "no upgrade" is unproven.
	ProviderAssessed      int `json:"provider_assessed"`
	ProviderUnassessed    int `json:"provider_unassessed"`
	RemediationUnresolved int `json:"remediation_unresolved"`
	// ActionableUnassessed counts actionable findings on images the provider never
	// assessed: they are actionable only because a vulnerability scanner looked
	// where the provider did not. Reporting it prevents the opposite error to the
	// one the coverage counts prevent — concluding that the actionable queue
	// describes only the assessed findings, when a large share of it does not.
	ActionableUnassessed int `json:"actionable_unassessed"`

	// ProviderDataNewest and ProviderDataOldest are when the scan provider last
	// looked, taken from the assessment timestamps in its own data.
	//
	// This is NOT the same as the assessment's generated_at, which is when this
	// pipeline last ran. A server refreshing hourly over a mounted export will
	// report a fresh assessment forever while the vulnerability data underneath it
	// ages, and a stale export is indistinguishable from a current one unless the
	// provider's own timestamps are surfaced. Nil when nothing carried one.
	ProviderDataNewest *time.Time `json:"provider_data_newest,omitempty"`
	ProviderDataOldest *time.Time `json:"provider_data_oldest,omitempty"`

	// Scanned and ExploitChecked count findings a vulnerability scanner and an
	// exploit source actually looked at.
	//
	// Reported because their absence disables whole tiers of the policy, silently.
	// Every rule of the form vulns.exists(...) — fix availability, EPSS, KEV — is
	// false when no scanner ran, so the urgent and high tiers simply never fire and
	// the queue looks calm rather than uninformed. A consumer cannot infer this
	// from the findings alone without inspecting every one of them.
	Scanned        int `json:"scanned"`
	ExploitChecked int `json:"exploit_checked"`

	// UnassessedReasons counts findings by the provider's stated reason for not
	// assessing them, worst first. This turns the coverage gap from a number
	// into a work list: on a real estate a single registry credential accounted
	// for the overwhelming majority of it, and no coverage percentage could have
	// said so. Empty when the provider states no reasons (the CSV export does
	// not), which is not the same as there being no problem.
	UnassessedReasons []reasonCount `json:"unassessed_reasons,omitempty"`
}

// ownerStats is a per-team triage row.
type ownerStats struct {
	Class      string `json:"class"`
	Team       string `json:"team"`
	Total      int    `json:"total"`
	Actionable int    `json:"actionable"`
	Fixable    int    `json:"fixable"`    // has a fix-available critical
	Upgradable int    `json:"upgradable"` // has an actionable upgrade
	// Unassessed counts findings the scan provider never assessed. Coverage is
	// uneven by team in practice, and a team with few actionable findings because
	// nothing scanned its images looks identical to a team in good shape unless
	// this is reported alongside.
	Unassessed int `json:"unassessed"`

	// Direct and Managed split the actionable findings by where the fix is applied:
	// Direct can be bumped on the image, Managed needs a chart or operator change.
	// The split matters more than the total, because it is the difference between
	// work a team can do alone and work that crosses a boundary.
	Direct  int `json:"direct"`
	Managed int `json:"managed"`
	// CVEs sums the scan provider's per-severity counts across this row, and
	// CVEsFrom says how many findings contributed. The denominator is not
	// decoration: coverage is uneven by team, so a total is only interpretable
	// next to how much of the row it was drawn from, and a row with CVEsFrom 0
	// has no CVE data at all rather than no CVEs.
	//
	// Provider counts only, matching the report's CRIT/HIGH columns. Findings
	// that exist solely because a vulnerability scanner looked where the
	// provider did not contribute nothing here, so this is a floor on the CVEs
	// present, never a ceiling.
	CVEs     model.Counts `json:"cves"`
	CVEsFrom int          `json:"cves_from"`

	// Ticketed counts actionable findings with an open ticket covering the image, so
	// "is this being tracked?" is answerable per team rather than by reading Jira.
	// Always 0 when Jira is not configured, which is why the API reports whether it
	// is: see the tickets field on findings.
	Ticketed int `json:"ticketed"`
}

// reasonCount is one stated reason and how many findings it accounts for.
type reasonCount struct {
	Reason   string `json:"reason"`
	Findings int    `json:"findings"`
}

func buildSummary(findings []model.Finding) summaryView {
	var s summaryView
	images := map[string]struct{}{}
	reasons := map[string]int{}
	for i := range findings {
		f := &findings[i]
		images[f.Image.Key()] = struct{}{}
		if f.Suppressed {
			s.Suppressed++
			continue
		}
		s.Findings++
		if f.Actionable {
			s.Actionable++
		}
		if hasKnownExploited(f) {
			s.KnownExploited++
		}
		if hasActionableUpgrade(f) {
			s.Upgradable++
		}
		if f.ProviderAssessed() {
			s.ProviderAssessed++
		} else {
			s.ProviderUnassessed++
			if f.Actionable {
				s.ActionableUnassessed++
			}
			// One finding, one vote for its primary reason. Counting every
			// reason on every finding would make the shares sum past the
			// unassessed total and read as though the problem were larger than
			// the estate.
			if issues := f.AssessmentIssues(); len(issues) > 0 {
				reasons[issues[0]]++
			}
		}
		if !remediationResolved(f) {
			s.RemediationUnresolved++
		}
		if f.Scanned {
			s.Scanned++
		}
		if f.ExploitChecked {
			s.ExploitChecked++
		}
	}
	s.UniqueImages = len(images)
	s.ProviderDataOldest, s.ProviderDataNewest = providerDataRange(findings)
	s.UnassessedReasons = rankReasons(reasons)
	return s
}

// rankReasons orders stated reasons by how much coverage each one costs, worst
// first, so the largest single fixable cause is the first thing read.
func rankReasons(reasons map[string]int) []reasonCount {
	if len(reasons) == 0 {
		return nil
	}
	out := make([]reasonCount, 0, len(reasons))
	for reason, n := range reasons {
		out = append(out, reasonCount{Reason: reason, Findings: n})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Findings != out[j].Findings {
			return out[i].Findings > out[j].Findings
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

// providerDataRange returns the oldest and newest assessment timestamps the
// provider supplied. Suppressed findings are included: how old the data is is a
// fact about the whole export, not about the queue.
func providerDataRange(findings []model.Finding) (oldest, newest *time.Time) {
	for i := range findings {
		for _, o := range findings[i].Occurrences {
			if o.LastSeen.IsZero() {
				continue // never assessed, so it carries no timestamp
			}
			t := o.LastSeen
			if oldest == nil || t.Before(*oldest) {
				oldest = &t
			}
			if newest == nil || t.After(*newest) {
				newest = &t
			}
		}
	}
	return oldest, newest
}

func buildOwnerStats(findings []model.Finding, tickets map[string][]ticketRef) []ownerStats {
	type key struct{ class, team string }
	acc := map[key]*ownerStats{}
	var order []key
	for i := range findings {
		f := &findings[i]
		if f.Suppressed {
			continue
		}
		k := key{f.Owner.Class, f.Owner.Team}
		st := acc[k]
		if st == nil {
			st = &ownerStats{Class: f.Owner.Class, Team: f.Owner.Team, CVEs: model.Counts{}}
			acc[k] = st
			order = append(order, k)
		}
		st.Total++
		if f.Actionable {
			st.Actionable++
		}
		if fixableCriticals(f) > 0 {
			st.Fixable++
		}
		if hasActionableUpgrade(f) {
			st.Upgradable++
		}
		if !f.ProviderAssessed() {
			st.Unassessed++
		} else {
			// Only assessed findings contribute: adding a zero from an image
			// nobody looked at would dilute the total toward "healthy".
			st.CVEsFrom++
			for sev, n := range f.Counts {
				st.CVEs[sev] += n
			}
		}
		if f.Actionable {
			switch fixPath(f) {
			case "direct":
				st.Direct++
			case "managed":
				st.Managed++
			}
			if len(tickets[f.Image.Repository]) > 0 {
				st.Ticketed++
			}
		}
	}
	out := make([]ownerStats, 0, len(order))
	for _, k := range order {
		// Normalized so a client can index every standard severity without
		// having to distinguish "no criticals" from "key absent".
		acc[k].CVEs = acc[k].CVEs.Normalized()
		out = append(out, *acc[k])
	}
	// Most actionable first, then by team for stability.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Actionable != out[j].Actionable {
			return out[i].Actionable > out[j].Actionable
		}
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].Team < out[j].Team
	})
	return out
}

func fixableCriticals(f *model.Finding) int {
	n := 0
	for _, v := range f.Vulns {
		if v.FixAvailable && v.Severity == model.SeverityCritical {
			n++
		}
	}
	return n
}

func hasKnownExploited(f *model.Finding) bool {
	for _, v := range f.Vulns {
		if v.KEV {
			return true
		}
	}
	return false
}

func hasActionableUpgrade(f *model.Finding) bool {
	return f.Upgrade != nil && f.Upgrade.Available && f.Upgrade.Actionable
}

// fixPath classifies where a finding's fix is applied, matching the vocabulary the
// report and the status page use. Kept here rather than duplicated per consumer so
// the API and the table cannot disagree about what "direct" means.
func fixPath(f *model.Finding) string {
	switch {
	case f.Upgrade == nil:
		if f.RemediationChecked {
			return "unknown"
		}
		return "?"
	case !f.Upgrade.Resolved:
		return "unknown"
	case !f.Upgrade.Available:
		return "none"
	case f.Upgrade.Actionable:
		return "direct"
	default:
		return "managed"
	}
}

// remediationResolved reports whether the available versions for an image were
// actually determined. False covers both "detection did not run" and "it ran and
// could not read the registry", which demand different responses from a human but
// are equally not a statement that the image is up to date.
func remediationResolved(f *model.Finding) bool {
	return f.Upgrade != nil && f.Upgrade.Resolved
}

// metricsSnapshot projects a cached assessment onto the metrics surface.
//
// A translation rather than a shared struct: metrics are an operational contract
// that outlives any refactor of the view types, and coupling them would mean a
// rename here silently renaming a metric someone is alerting on.
func metricsSnapshot(snap *snapshot) metrics.Snapshot {
	out := metrics.Snapshot{
		Findings:           snap.summary.Findings,
		Actionable:         snap.summary.Actionable,
		Suppressed:         snap.summary.Suppressed,
		ProviderAssessed:   snap.summary.ProviderAssessed,
		ProviderUnassessed: snap.summary.ProviderUnassessed,
		Scanned:            snap.summary.Scanned,
		ExploitChecked:     snap.summary.ExploitChecked,
		Upgradable:         snap.summary.Upgradable,
		KnownExploited:     snap.summary.KnownExploited,
		RemediationUnknown: snap.summary.RemediationUnresolved,
		ActionableBlind:    snap.summary.ActionableUnassessed,
		UniqueImages:       snap.summary.UniqueImages,
	}
	if snap.summary.ProviderDataNewest != nil {
		out.ProviderDataNewest = *snap.summary.ProviderDataNewest
	}
	for _, o := range snap.owners {
		out.Owners = append(out.Owners, metrics.OwnerSnapshot{
			Class: o.Class, Team: o.Team, Findings: o.Total,
			Actionable: o.Actionable, Unassessed: o.Unassessed, Ticketed: o.Ticketed,
		})
	}
	for _, r := range snap.summary.UnassessedReasons {
		out.Reasons = append(out.Reasons, metrics.ReasonCount{Reason: r.Reason, Findings: r.Findings})
	}
	return out
}
