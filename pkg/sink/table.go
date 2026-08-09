package sink

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

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

	for _, class := range classOrder {
		group := byClass[class]
		actionable := 0
		for _, f := range group {
			if f.Actionable {
				actionable++
			}
		}
		fmt.Fprintf(w, "== owner class: %s (%d findings, %d actionable) ==\n", class, len(group), actionable)

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ACT\tPRIORITY\tTEAM\tIMAGE\tCRIT\tHIGH\tFIXCRIT\tKEV\tRISK\tWORKLOADS\tLIVE\tACCOUNTS")
		for _, f := range group {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\t%.0f\t%d\t%s\t%s\n",
				actionableMark(f),
				dash(f.Priority),
				dash(f.Owner.Team),
				imageLabel(f.Image),
				f.Counts.Get(model.SeverityCritical),
				f.Counts.Get(model.SeverityHigh),
				fixMark(f),
				kevMark(f),
				f.RiskScore,
				len(f.Occurrences),
				liveMark(f),
				joinValues(f.Dimensions["account"]),
			)
		}
		tw.Flush()
		fmt.Fprintln(w)
	}
	return nil
}

func actionableMark(f model.Finding) string {
	switch {
	case f.Suppressed:
		return "supp"
	case f.Actionable:
		return "yes"
	default:
		return "-"
	}
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

// kevMark shows the count of known-exploited (CISA KEV) CVEs, or "-" when no
// exploit enrichment has run.
func kevMark(f model.Finding) string {
	if f.ScanError != "" {
		return "err"
	}
	if !f.Scanned && len(f.Vulns) == 0 {
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
