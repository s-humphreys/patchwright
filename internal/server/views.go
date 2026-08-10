package server

import (
	"sort"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// summaryView is the fleet-wide headline.
type summaryView struct {
	Findings       int `json:"findings"`
	Actionable     int `json:"actionable"`
	Suppressed     int `json:"suppressed"`
	KnownExploited int `json:"known_exploited"`
	Upgradable     int `json:"upgradable"` // actionable upgrade available
	UniqueImages   int `json:"unique_images"`
}

// ownerStats is a per-team triage row.
type ownerStats struct {
	Class      string `json:"class"`
	Team       string `json:"team"`
	Total      int    `json:"total"`
	Actionable int    `json:"actionable"`
	Fixable    int    `json:"fixable"`    // has a fix-available critical
	Upgradable int    `json:"upgradable"` // has an actionable upgrade
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
