package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// outputSpec is one destination for a completed assessment: a format, the view
// of the finding set to render, and where to write it.
type outputSpec struct {
	format string
	view   string // "", "queue", or "full" — "" means use the global display flags
	path   string // "-" for stdout
}

// Output view names. A single assessment is usually wanted in two scopes: the
// actionable queue someone works through, and the complete record (including
// suppressed findings and why) for archival and querying. Naming them lets one
// run write both, instead of paying for the whole pipeline twice.
const (
	viewQueue = "queue" // actionable, unsuppressed findings only
	viewFull  = "full"  // every finding, suppressed ones included
)

// parseOutputs parses repeatable --output values of the form
// "format[:view]=path". A path of "-" means stdout.
func parseOutputs(vals []string) ([]outputSpec, error) {
	specs := make([]outputSpec, 0, len(vals))
	for _, v := range vals {
		lhs, path, ok := strings.Cut(v, "=")
		if !ok || lhs == "" || path == "" {
			return nil, fmt.Errorf("invalid --output %q, want format[:view]=path (e.g. json=findings.json or table:queue=-)", v)
		}
		format, view, hasView := strings.Cut(lhs, ":")
		if hasView && view != viewQueue && view != viewFull {
			return nil, fmt.Errorf("invalid --output %q: unknown view %q (want %s or %s)", v, view, viewQueue, viewFull)
		}
		// Validate the format up front so a typo fails before the pipeline runs
		// rather than after a long scan.
		if _, err := selectSink(format, false); err != nil {
			return nil, fmt.Errorf("invalid --output %q: %w", v, err)
		}
		specs = append(specs, outputSpec{format: format, view: view, path: path})
	}
	return specs, nil
}

// emitOutputs renders findings to every spec. Each output gets its own view of
// the same assessment, so the queue and the full record can be written from one
// run. Files are created (truncated); "-" writes to stdout.
func emitOutputs(specs []outputSpec, findings []model.Finding, stdout io.Writer, ownerClass string, includeAll, showSuppressed bool) error {
	for _, spec := range specs {
		all, suppressed := includeAll, showSuppressed
		switch spec.view {
		case viewQueue:
			all, suppressed = false, false
		case viewFull:
			all, suppressed = true, true
		}

		s, err := selectSink(spec.format, suppressed)
		if err != nil {
			return err
		}
		view := filterFindings(findings, ownerClass, all, suppressed)

		if err := emitTo(spec, s, view, stdout); err != nil {
			return err
		}
	}
	return nil
}

// emitTo writes one rendered view, closing the file it opened before returning
// so a multi-output run doesn't hold every handle until the end.
func emitTo(spec outputSpec, s sink.Sink, findings []model.Finding, stdout io.Writer) error {
	if spec.path == "-" {
		return s.Emit(stdout, findings)
	}
	f, err := os.Create(spec.path)
	if err != nil {
		return fmt.Errorf("create output %s: %w", spec.path, err)
	}
	if err := s.Emit(f, findings); err != nil {
		f.Close()
		return fmt.Errorf("write %s output to %s: %w", spec.format, spec.path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close output %s: %w", spec.path, err)
	}
	return nil
}
