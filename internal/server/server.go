// Package server exposes patchwright's assessment as a read-only HTTP/JSON API.
// It runs assessments on a schedule and on demand, caches the latest result in
// memory, and serves it — the API-first foundation the CLI, a UI, Backstage,
// and (later) Jira actioning all build on.
package server

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Assessor runs a full assessment and returns findings. The CLI's assessor
// satisfies it; tests provide a stub.
type Assessor interface {
	Run(ctx context.Context) ([]model.Finding, error)
}

// snapshot is the cached result of one assessment.
type snapshot struct {
	views       []sink.FindingView
	summary     summaryView
	owners      []ownerStats
	byImage     map[string]sink.FindingView
	generatedAt time.Time
	err         string
}

// Server holds the assessor and the latest cached assessment.
type Server struct {
	assessor Assessor

	mu                sync.RWMutex
	latest            *snapshot
	running           bool
	includeSuppressed bool // whether the cache retains suppressed findings
}

// New builds a Server. Suppressed findings are retained in the cache so the API
// can expose them on request.
func New(a Assessor) *Server {
	return &Server{assessor: a, includeSuppressed: true}
}

// Refresh runs an assessment and replaces the cached snapshot. Concurrent
// refreshes are collapsed: if one is already running, Refresh returns without
// starting another.
func (s *Server) Refresh(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	slog.InfoContext(ctx, "server: running assessment")
	findings, err := s.assessor.Run(ctx)
	snap := &snapshot{generatedAt: time.Now()}
	if err != nil {
		snap.err = err.Error()
		slog.ErrorContext(ctx, "server: assessment failed", "error", err)
	} else {
		snap.views = buildViews(findings, s.includeSuppressed)
		snap.summary = buildSummary(findings)
		snap.owners = buildOwnerStats(findings)
		snap.byImage = indexByImage(snap.views)
		slog.InfoContext(ctx, "server: assessment cached", "findings", len(snap.views))
	}

	s.mu.Lock()
	// Preserve the last good data if this run errored but a previous succeeded.
	if snap.err != "" && s.latest != nil && s.latest.err == "" {
		s.latest.err = snap.err
		s.latest.generatedAt = snap.generatedAt
	} else {
		s.latest = snap
	}
	s.mu.Unlock()
}

// Start runs an initial assessment, then refreshes on interval until ctx is
// cancelled. It blocks; run it in a goroutine.
func (s *Server) Start(ctx context.Context, interval time.Duration) {
	s.Refresh(ctx)
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Refresh(ctx)
		}
	}
}

// buildViews converts findings to API views, optionally including suppressed.
func buildViews(findings []model.Finding, includeSuppressed bool) []sink.FindingView {
	sorted := sink.SortForReport(findings)
	out := make([]sink.FindingView, 0, len(sorted))
	for _, f := range sorted {
		if f.Suppressed && !includeSuppressed {
			continue
		}
		out = append(out, sink.ToFindingView(f))
	}
	return out
}

func indexByImage(views []sink.FindingView) map[string]sink.FindingView {
	m := make(map[string]sink.FindingView, len(views))
	for _, v := range views {
		m[v.Image] = v
	}
	return m
}
