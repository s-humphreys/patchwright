package mcp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Configuration is what the run was set up to do, on every answer.
//
// It is here because of a real failure. Asked what to do about an estate where
// nothing was scanned, a model read "0 of 817 scanned" and advised finding out why
// the scan provider was assessing almost nothing - when the run had simply been
// started without a vuln source. The numbers were right and the conclusion was
// wrong, because the payload could not say which stages had been asked to run.
//
// Every field states whether the stage was CONFIGURED. Combined with the coverage
// counts, that separates the three cases a bare zero collapses into: not asked for,
// asked for and refused, asked for and genuinely clean.
type Configuration struct {
	Provider string `json:"scan_provider,omitempty"`
	// VulnSource is what produced per-CVE detail. "none" means no CVE-level data was
	// requested, so every CVE count in this answer is zero by construction.
	VulnSource string `json:"vuln_source"`
	// ExploitSource supplies EPSS and KEV. Without it nothing is known to be
	// exploited, which is not the same as nothing being exploited.
	ExploitSource string `json:"exploit_source"`
	AgeSource     string `json:"age_source"`
	LiveSource    string `json:"live_source"`
	SupportSource string `json:"support_source,omitempty"`

	Remediation      bool `json:"upgrades_looked_for"`
	BaseDifferential bool `json:"base_differential"`
	InFlight         bool `json:"pull_requests_matched"`
	Exposure         bool `json:"exposure_measured"`
}

const notConfigured = "none"

func configuration(a Assessment) Configuration {
	s := a.Sources
	return Configuration{
		Provider:         s.Provider,
		VulnSource:       orNone(s.VulnSource),
		ExploitSource:    orNone(s.ExploitSource),
		AgeSource:        orNone(s.AgeSource),
		LiveSource:       orNone(s.LiveSource),
		SupportSource:    s.SupportSource,
		Remediation:      s.Remediation,
		BaseDifferential: s.BaseDiff,
		InFlight:         s.InFlight,
		Exposure:         s.Exposure,
	}
}

func orNone(s string) string {
	if s == "" {
		return notConfigured
	}
	return s
}

// configCaveats explains an absent signal by naming its cause, in the words of
// whoever can fix it. "No base differential ran" sent a reader to the wrong place;
// "the run was started without it" sends them to the command line.
//
// A stage that WAS configured and still produced nothing gets the opposite reading:
// that is a failure to investigate, not a setting to change.
func configCaveats(a Assessment, cov Coverage) []string {
	s := a.Sources
	var out []string

	switch {
	case s.ScanDisabled:
		out = append(out, "Image scanning is turned off in config (scan.disabled), so there is no "+
			"per-CVE detail for any deployment however many CVEs exist. Every CVE count here is zero by configuration.")
	case s.VulnSource == "":
		out = append(out, "This run was started WITHOUT a vulnerability source (--vuln-source), so no "+
			"per-CVE detail was gathered for any deployment. Every CVE count here is zero by "+
			"configuration, not by measurement, and this is a setting rather than a fault in the scan provider.")
	case cov.Scanned == 0:
		out = append(out, fmt.Sprintf(
			"A vulnerability source (%s) was configured and yet scanned none of the %d deployments. "+
				"That is a failure worth investigating - registry credentials or egress are the usual causes.",
			s.VulnSource, cov.Total))
	case cov.Scanned < cov.Total:
		out = append(out, fmt.Sprintf(
			"Per-CVE detail exists for %d of %d deployments, so CVE and known-exploited totals are lower bounds.",
			cov.Scanned, cov.Total))
	}

	if s.VulnSource != "" && s.ExploitSource == "" {
		out = append(out, "No exploit source (--exploit-source) was configured, so no CVE is known to be "+
			"exploited or scored for EPSS. Read 'known_exploited: 0' as unmeasured.")
	}

	switch {
	case !s.Remediation:
		out = append(out, "Remediation lookup is off (--remediation), so no upgrade was sought for anything. "+
			"An absent upgrade here means nobody looked.")
	case !s.BaseDiff:
		out = append(out, "The base differential is not enabled (remediation.baseDiff in config), so what "+
			"rebuilding would clear was never measured. This is a setting, not a finding.")
	case cov.BaseDiffs == 0:
		out = append(out, "The base differential is enabled and yet measured no deployment. Base images could "+
			"not be resolved or scanned - registry access is the usual cause.")
	}

	if !s.Exposure {
		out = append(out, "Internet exposure was not measured (it needs a live source that can read Services "+
			"and routes), so any exposure value here comes from the scan provider and may be constant.")
	}
	return out
}

// UnassessedReason is the scan provider's own reason for not assessing an image, and
// how many deployments it accounts for.
//
// This is the difference between "706 unassessed, cause unknown" and "412 need a
// registry credential". The provider already says why; the count is what turns it
// into a piece of work somebody can pick up.
type UnassessedReason struct {
	Reason      string `json:"reason"`
	Deployments int    `json:"deployments"`
}

// maxReasons bounds the list. The tail of a reason histogram is one-offs, and the
// point of this is the two or three causes that account for most of a coverage gap.
const maxReasons = 6

func unassessedReasons(findings []sink.FindingView) []UnassessedReason {
	counts := map[string]int{}
	for _, f := range findings {
		if f.ProviderAssessed {
			continue
		}
		for _, r := range f.AssessmentIssues {
			counts[strings.TrimSpace(r)]++
		}
	}
	out := make([]UnassessedReason, 0, len(counts))
	for r, n := range counts {
		out = append(out, UnassessedReason{Reason: r, Deployments: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Deployments != out[j].Deployments {
			return out[i].Deployments > out[j].Deployments
		}
		return out[i].Reason < out[j].Reason
	})
	if len(out) > maxReasons {
		out = out[:maxReasons]
	}
	return out
}
