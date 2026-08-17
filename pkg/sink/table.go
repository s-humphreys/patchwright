package sink

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// Table renders findings as a human-readable table, grouped by owner class so
// each team sees its own slice. Suppressed findings are shown only when
// ShowSuppressed is set.
type Table struct {
	ShowSuppressed bool
}

// Emit implements Sink.
func (t Table) Emit(w io.Writer, findings []model.Finding) error {
	findings = SortForReport(findings)

	// Group by owner class, preserving a stable class order.
	byClass := map[string][]model.Finding{}
	var classOrder []string
	for _, f := range findings {
		if f.Suppressed && !t.ShowSuppressed {
			continue
		}
		if _, seen := byClass[f.Owner.Class]; !seen {
			classOrder = append(classOrder, f.Owner.Class)
		}
		byClass[f.Owner.Class] = append(byClass[f.Owner.Class], f)
	}
	sort.Strings(classOrder)

	if len(classOrder) == 0 {
		fmt.Fprintln(w, "no findings")
		return nil
	}

	writeLegend(w)

	for _, class := range classOrder {
		group := byClass[class]
		actionable := 0
		for _, f := range group {
			if f.Actionable {
				actionable++
			}
		}
		fmt.Fprintf(w, "== owner class: %s (%d findings, %d actionable%s) ==\n",
			class, len(group), actionable, fixSummary(group))

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "FIX\tPRIORITY\tTEAM\tNAMESPACE\tIMAGE\tCRIT\tHIGH\tFIXCRIT\tKEV\tEPSS\tAGE\tRISK\tWORKLOADS\tLIVE\tUPGRADE\tACCOUNTS")
		for _, f := range group {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.0f\t%d\t%s\t%s\t%s\n",
				fixPathMark(f),
				priorityMark(f),
				dash(f.Owner.Team),
				joinValues(f.Dimensions["namespace"]),
				imageLabel(f.Image),
				countMark(f, model.SeverityCritical),
				countMark(f, model.SeverityHigh),
				fixMark(f),
				kevMark(f),
				epssMark(f),
				ageMark(f),
				f.RiskScore,
				len(f.Occurrences),
				liveMark(f),
				upgradeMark(f),
				joinValues(f.Dimensions["account"]),
			)
		}
		tw.Flush()
		fmt.Fprintln(w)
	}
	return nil
}

// writeLegend explains the marks once at the top of the report. The table
// carries four different unknown-states, and they mean genuinely different
// things: "the provider never looked", "we could not resolve versions", "you
// did not ask for detection", and "no data gathered". Left unexplained they all
// read as "probably fine", which is precisely the reading the marks exist to
// prevent.
func writeLegend(w io.Writer) {
	fmt.Fprintln(w, "LEGEND")
	fmt.Fprintln(w, "  FIX        direct = bump this image now | managed = version owned by a chart/operator |")
	fmt.Fprintln(w, "             none = already on the latest | unknown = versions could not be resolved |")
	fmt.Fprintln(w, "             ? = upgrade detection did not run")
	fmt.Fprintln(w, "  PRIORITY   policy verdict. supp = suppressed, with the rule in the JSON reasons")
	fmt.Fprintln(w, "  CRIT/HIGH  severity counts from the scan provider. ? = the provider NEVER ASSESSED this")
	fmt.Fprintln(w, "             image, so nothing is known about it. Not the same as 0.")
	fmt.Fprintln(w, "  FIXCRIT    criticals with a fix available, from the vuln scanner. - = not scanned, err = failed")
	fmt.Fprintln(w, "  AGE        days since the scan provider first saw the oldest CVE on the image; \"-\" when")
	fmt.Fprintln(w, "             no CVE is dated (no --age-source, or the provider has not seen them)")
	fmt.Fprintln(w, "  KEV/EPSS   known-exploited count, and the highest exploitation probability (0-1) across the")
	fmt.Fprintln(w, "             image's CVEs. - = exploit intel not gathered, so 0/0.00 means checked and clear")
	fmt.Fprintln(w, "  LIVE       running in a cluster right now. ? = no live reconciliation ran")
	fmt.Fprintln(w, "  TEAM       - = no ownership rule could attribute this workload to a real team")
	fmt.Fprintln(w)
}

// upgradeMark shows the remediation at a glance:
//   - "current->latest" when a newer version can be applied directly (actionable)
//   - "current->latest (managed)" when a newer version exists but is controlled
//     by a chart/operator (not directly actionable)
//   - "-" when on the latest version
//   - "?" when no version was resolved. FIX separates the two reasons for that
//     (detection not run vs. run-but-unresolved); this column stays terse.
//
// Chart upgrades are prefixed with "chart " because their versions are the
// chart's, not the image tag shown in the IMAGE column — without the marker a
// chart bump like "1.21.5->2.0.0" reads as an image bump for tag "v1.9.5".
func upgradeMark(f model.Finding) string {
	u := f.Upgrade
	if u == nil || !u.Resolved {
		return "?"
	}
	if !u.Available {
		return "-"
	}
	bump := u.Current + "->" + u.Latest
	switch u.Kind {
	case "chart":
		bump = "chart " + bump
	case "base":
		// Named, because for a first-party image a bare version range reads as the
		// application's own version moving — which is the confusion this kind of
		// upgrade exists to remove. What moves is the base, and which base matters:
		// it is what the rebuild points at.
		//
		// A digest comparison names the tag as well. "1e37a823->c4b29bf3" is two
		// opaque hashes; what a reader needs is that mcr.microsoft.com/dotnet/aspnet
		// :10.0-alpine has moved under them, which is the line in their Dockerfile.
		if u.Comparison == "digest" && u.Source != "" {
			bump = "base " + u.Source + " moved " + bump
		} else {
			bump = "base " + u.Name + " " + bump
		}
	}
	if !u.Actionable {
		if u.Managed != "" {
			return bump + " (" + u.Managed + ")"
		}
		return bump + " (managed)"
	}
	return bump
}

// fixSummary breaks the actionable findings in a group down by fix path, so the
// header answers "how many of these can I actually do something about?" rather
// than only "how many matched a policy rule". "32 actionable" of which 3 have
// nothing to upgrade to is a materially different day's work from 32 direct
// bumps. Returns "" when nothing is actionable, so the header stays terse.
func fixSummary(group []model.Finding) string {
	counts := map[string]int{}
	total := 0
	for _, f := range group {
		if !f.Actionable {
			continue
		}
		counts[fixPathMark(f)]++
		total++
	}
	if total == 0 {
		return ""
	}
	var parts []string
	// Fixed order, most immediately useful first; zero counts are omitted.
	for _, k := range []string{"direct", "managed", "none", "unknown", "?"} {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	return ": " + strings.Join(parts, ", ")
}

// fixPathMark answers "can I do something about this, and how?" — the question
// a queue is read to answer. It reports the remediation *path*, not the policy
// verdict (which PRIORITY already carries):
//
//   - "direct"  a newer version this image can move to now
//   - "managed" a newer version exists, but a chart/operator owns the tag, so
//     the fix is applied there — still real work, just not here
//   - "none"    already on the latest version; nothing to upgrade to. Worth
//     seeing rather than hiding: criticals with nowhere to go need a human
//     (wait for upstream, rebuild, or accept), not a bump.
//   - "unknown" detection ran but could not resolve the available versions (e.g.
//     a private registry whose tags we cannot list, or a non-semver tag). A gap
//     to chase, NOT "on the latest" — reporting it as such would let an
//     unreachable registry declare everything it holds up to date.
//   - "?"       detection didn't run at all (no --remediation)
func fixPathMark(f model.Finding) string {
	u := f.Upgrade
	if u == nil {
		if f.RemediationChecked {
			return "unknown"
		}
		return "?"
	}
	if !u.Resolved {
		return "unknown"
	}
	if !u.Available {
		return "none"
	}
	if u.Actionable {
		return "direct"
	}
	return "managed"
}

// priorityMark shows the policy verdict. Suppressed findings report "supp"
// rather than their (absent) priority, so that in --show-suppressed views they
// stay distinguishable from findings that simply matched no actionable rule.
func priorityMark(f model.Finding) string {
	if f.Suppressed {
		return "supp"
	}
	return dash(f.Priority)
}

// fixMark shows the count of fix-available critical CVEs, "err" when the scan
// failed (e.g. private image, no credentials), or "-" when no scan ran.
func fixMark(f model.Finding) string {
	if f.ScanError != "" {
		return "err"
	}
	if !f.Scanned && len(f.Vulns) == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", fixableCriticals(f))
}

// kevMark shows the count of known-exploited (CISA KEV) CVEs, or "-" when
// exploit enrichment has not run (so "0" always means "checked, none").
func kevMark(f model.Finding) string {
	if f.ScanError != "" {
		return "err"
	}
	if !f.ExploitChecked {
		return "-"
	}
	n := 0
	for _, v := range f.Vulns {
		if v.KEV {
			n++
		}
	}
	return fmt.Sprintf("%d", n)
}

// countMark shows a severity count from the scan provider, or "?" when the
// provider never assessed the image. Zero counts from an unassessed image mean
// "nobody looked", and rendering that as "0" reads as a clean result — the
// single most misleading thing a vulnerability report can do.
//
// Note this is about the *provider*. An optional vuln source (Trivy) not having
// run is not a coverage gap, so it never produces "?" here; its findings surface
// in FIXCRIT independently.
func countMark(f model.Finding, severity string) string {
	if !f.ProviderAssessed() {
		return "?"
	}
	return fmt.Sprintf("%d", f.Counts.Get(severity))
}

// ageMark shows how long the oldest known CVE on the image has been known, in days.
//
// "-" when no CVE carries a date: either no age source ran, or the provider has
// never seen these CVEs. Printing 0 there would make everything look brand new,
// which is the reading that removes any pressure to act.
func ageMark(f model.Finding) string {
	t, ok := f.OldestVuln()
	if !ok {
		return "-"
	}
	days := int(time.Since(t).Hours() / 24)
	if days < 1 {
		return "<1d"
	}
	return fmt.Sprintf("%dd", days)
}

// epssMark shows the highest EPSS across a finding's CVEs — the exploitation
// pressure on the image, where KEV is confirmed exploitation and EPSS is the
// predicted probability over the next 30 days. The maximum (not a mean) is what
// matters: one CVE at 0.93 makes the image urgent regardless of how many quiet
// ones sit alongside it. "-" when exploit enrichment has not run, so "0.00"
// always means "checked, no pressure".
func epssMark(f model.Finding) string {
	if f.ScanError != "" {
		return "err"
	}
	if !f.ExploitChecked {
		return "-"
	}
	max := 0.0
	for _, v := range f.Vulns {
		if v.EPSS > max {
			max = v.EPSS
		}
	}
	return fmt.Sprintf("%.2f", max)
}

// liveMark reports liveness: yes/no when reconciled, "?" when liveness is
// unknown (no reconciliation ran).
func liveMark(f model.Finding) string {
	if !f.Reconciled {
		return "?"
	}
	if f.Live {
		return "yes"
	}
	return "no"
}

func imageLabel(i model.Image) string {
	repo := i.Repository
	if i.Registry != "" {
		repo = i.Registry + "/" + i.Repository
	}
	if i.Tag != "" {
		return repo + ":" + i.Tag
	}
	return repo
}

func joinValues(vals []string) string {
	if len(vals) == 0 {
		return "-"
	}
	if len(vals) <= 3 {
		return strings.Join(vals, ",")
	}
	return fmt.Sprintf("%s (+%d)", strings.Join(vals[:3], ","), len(vals)-3)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
