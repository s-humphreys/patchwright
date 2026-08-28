// Package server exposes patchwright's assessment as a read-only HTTP/JSON API.
// It runs assessments on a schedule and on demand, caches the latest result in
// memory, and serves it — the API-first foundation the CLI, a UI, Backstage,
// and (later) Jira actioning all build on.
package server

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/s-humphreys/patchwright/pkg/ticket"

	"github.com/s-humphreys/patchwright/internal/metrics"
	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Assessor runs a full assessment and returns findings. The CLI's assessor
// satisfies it; tests provide a stub.
type Assessor interface {
	Run(ctx context.Context) ([]model.Finding, error)
}

// FailureReporter is an Assessor that can say which enrichments could not run.
//
// Optional, and separate from Run's error, because these are the failures that did NOT
// fail the assessment: exploit intel or CVE ages that could not be gathered. The
// findings are still worth serving, and the gap is still worth stating — a missing
// signal nobody can see looks exactly like a signal that found nothing.
type FailureReporter interface {
	Failures() []model.SourceFailure
}

// TicketIndex reports the open tickets covering each image repository. It is
// optional: without Jira configured the server simply has nothing to say about
// tickets, rather than failing or pretending there are none.
type TicketIndex interface {
	OpenByImage(ctx context.Context) (map[string][]ticket.Existing, error)
}

// snapshot is the cached result of one assessment.
type snapshot struct {
	views       []sink.FindingView
	summary     summaryView
	owners      []ownerStats
	analytics   AnalyticsView
	byImage     map[string]sink.FindingView
	generatedAt time.Time
	err         string
	// tickets maps an image repository to the open tickets covering it. Kept
	// beside the findings rather than inside them: a ticket is external state
	// someone else can change, not a fact the assessment measured.
	tickets map[string][]ticketRef
}

// ticketRef is the client-facing shape of an open ticket.
type ticketRef struct {
	Key     string `json:"key"`
	Status  string `json:"status"`
	Summary string `json:"summary,omitempty"`
	URL     string `json:"url,omitempty"`
	// Category is Jira's status category ("new", "indeterminate"), which is the
	// portable way to distinguish a ticket someone is working on from one merely
	// raised: status names themselves are per-project.
	Category string `json:"category,omitempty"`
}

// Server holds the assessor and the latest cached assessment.
type Server struct {
	assessor Assessor
	// configSources is the raw text of the loaded config, for GET /api/v1/config.
	configSources []config.Source
	// suppressRules is the loaded suppression policy, for reporting lapsed rules.
	suppressRules []config.PolicyRule

	// metricsAuth brings /metrics under the shared token. Off by default: a scrape
	// config needing a credential is friction where it is least tolerated.
	metricsAuth bool

	// tickets and jiraBaseURL are set only when Jira is configured.
	tickets     TicketIndex
	jiraBaseURL string
	// tokenDigest is the sha256 of the shared API token. Empty means no
	// authentication, which is the historical behaviour and must stay possible for
	// local runs.
	tokenDigest []byte
	// auth is the OIDC sign-in, when configured. Nil means sign-in is off and the
	// shared token (if any) is the only credential.
	auth *authenticator
	// ticketer and autoTicket drive ticket reconciliation. Both optional: without a
	// ticketer the endpoints report that ticketing is not configured, and without
	// autoTicket nothing is raised except on request.
	ticketer   Ticketer
	autoTicket bool

	mu      sync.RWMutex
	latest  *snapshot
	running bool
	// startedAt is when the in-flight assessment began. A first full run takes
	// minutes (every cluster, every image), and a client showing nothing with no
	// indication of progress is indistinguishable from one that is broken.
	startedAt         time.Time
	includeSuppressed bool // whether the cache retains suppressed findings
}

// New builds a Server. Suppressed findings are retained in the cache so the API
// can expose them on request.
func New(a Assessor) *Server {
	return &Server{assessor: a, includeSuppressed: true}
}

// WithTickets attaches an open-ticket index, so findings can show whether someone
// is already on them. baseURL is used to build issue links and is not a secret.
func (s *Server) WithTickets(idx TicketIndex, baseURL string) *Server {
	s.tickets = idx
	s.jiraBaseURL = baseURL
	return s
}

// lookupTickets fetches the open-ticket index, if one is configured. A failure is
// logged and returns nothing: findings are the point of this service, and losing
// the ability to say "there is already a ticket" must not cost the assessment.
func (s *Server) lookupTickets(ctx context.Context) map[string][]ticketRef {
	if s.tickets == nil {
		return nil
	}
	byImage, err := s.tickets.OpenByImage(ctx)
	if err != nil {
		slog.WarnContext(ctx, "server: could not list open tickets", "error", err)
		return nil
	}
	out := make(map[string][]ticketRef, len(byImage))
	for image, issues := range byImage {
		refs := make([]ticketRef, 0, len(issues))
		for _, i := range issues {
			ref := ticketRef{Key: i.Key, Status: i.Status, Summary: i.Summary, Category: i.Category}
			if s.jiraBaseURL != "" {
				ref.URL = strings.TrimSuffix(s.jiraBaseURL, "/") + "/browse/" + i.Key
			}
			refs = append(refs, ref)
		}
		out[image] = refs
	}
	return out
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
	s.startedAt = time.Now()
	s.mu.Unlock()

	// published is set once a successful snapshot is cached, so ticketing reconciles
	// exactly what the API is serving rather than a half-built or failed cache.
	published := false
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		if published {
			s.autoReconcile(ctx)
		}
	}()

	slog.InfoContext(ctx, "server: running assessment")
	done := metrics.AssessmentStarted()
	findings, err := s.assessor.Run(ctx)
	done(err)
	snap := &snapshot{generatedAt: time.Now()}
	if err != nil {
		snap.err = err.Error()
		slog.ErrorContext(ctx, "server: assessment failed", "error", err)
	} else {
		snap.views = buildViews(findings, s.includeSuppressed)
		snap.summary = buildSummary(findings)
		snap.summary.ExpiredSuppressions = s.expiredSuppressions()
		if fr, ok := s.assessor.(FailureReporter); ok {
			for _, f := range fr.Failures() {
				snap.summary.SourceFailures = append(snap.summary.SourceFailures,
					sourceFailure{Stage: f.Stage, Error: f.Error})
			}
		}
		snap.byImage = indexByImage(snap.views)
		// Tickets first: the owner rollup counts how much of each team's work is
		// already tracked.
		snap.tickets = s.lookupTickets(ctx)
		snap.owners = buildOwnerStats(findings, snap.tickets)
		// Same findings and the same ticket index as the owner rollup, so the two
		// pages cannot disagree about the same team.
		snap.analytics = buildAnalytics(findings, snap.tickets, time.Now())
		// Published after the rollup so the owner series and the fleet totals come
		// from the same assessment; scraping between the two would show them
		// disagreeing.
		metrics.Observe(metricsSnapshot(snap))
		slog.InfoContext(ctx, "server: assessment cached",
			"findings", len(snap.views), "ticketed_images", len(snap.tickets))
	}

	s.mu.Lock()
	// Preserve the last good data if this run errored but a previous succeeded.
	if snap.err != "" && s.latest != nil && s.latest.err == "" {
		s.latest.err = snap.err
		s.latest.generatedAt = snap.generatedAt
	} else {
		s.latest = snap
		// Only reconcile tickets against a successful assessment: raising work from
		// a failed run would act on whatever the last good data happened to be
		// while reporting an error.
		published = snap.err == ""
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
