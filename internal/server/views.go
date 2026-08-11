package server

import (
	"sort"

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
}

func buildSummary(findings []model.Finding) summaryView {
	var s summaryView
	images := map[string]struct{}{}
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
		}
		if !remediationResolved(f) {
			s.RemediationUnresolved++
		}
	}
	s.UniqueImages = len(images)
	return s
}

func buildOwnerStats(findings []model.Finding) []ownerStats {
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
			st = &ownerStats{Class: f.Owner.Class, Team: f.Owner.Team}
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
		}
	}
	out := make([]ownerStats, 0, len(order))
	for _, k := range order {
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

// remediationResolved reports whether the available versions for an image were
// actually determined. False covers both "detection did not run" and "it ran and
// could not read the registry", which demand different responses from a human but
// are equally not a statement that the image is up to date.
func remediationResolved(f *model.Finding) bool {
	return f.Upgrade != nil && f.Upgrade.Resolved
}
