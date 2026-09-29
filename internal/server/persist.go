package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/s-humphreys/patchwright/internal/version"
	"github.com/s-humphreys/patchwright/pkg/analytics"
	"github.com/s-humphreys/patchwright/pkg/history"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
)

// Persisting the served assessment.
//
// A full assessment takes around twenty minutes, and until one completes the API
// answers 503 and the page says "first assessment in progress". Every restart paid
// that: an eviction, a config reload, a rollout. With a history store configured,
// each successful assessment is also written to the store whole, and a starting
// process serves the newest one while its own first run is in flight.
//
// A loaded assessment is served, never acted on. Tickets are reconciled and history
// recorded only from an assessment this process ran: reconciling Jira against data
// from before the restart could close a ticket on the strength of a fix that has
// since been rolled back.
//
// Without a store none of this runs, and a restart behaves as it always has.

// servedSchemaVersion names the payload encoding below. Bump it when a change to
// servedPayload or the types it carries would make an older payload decode into
// something wrong rather than merely incomplete. A payload with another version is
// ignored at start-up, which costs one cold start and nothing else.
const servedSchemaVersion = 1

// servedKeep is how many served assessments the store holds. One is enough to
// restart from; the others are there so a payload that turns out unreadable after
// an upgrade has a predecessor someone can inspect.
const servedKeep = 3

// servedPayload is everything a snapshot serves that is not derivable from the rest.
// byImage and the lazy aggregations are rebuilt from Views; the error is not kept,
// because only successful assessments are stored.
type servedPayload struct {
	Views     []sink.FindingView      `json:"views"`
	Summary   summaryView             `json:"summary"`
	Owners    []ownerStats            `json:"owners"`
	Analytics analytics.AnalyticsView `json:"analytics"`
	Tickets   map[string][]ticketRef  `json:"tickets,omitempty"`
	Sources   model.Sources           `json:"sources"`
}

// encodeServed writes a snapshot as gzipped JSON. Compressed because a real estate's
// findings are tens of megabytes of JSON that shrink by an order of magnitude, and
// streamed so the uncompressed form is never held in memory whole.
func encodeServed(snap *snapshot) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(servedPayload{
		Views: snap.views, Summary: snap.summary, Owners: snap.owners,
		Analytics: snap.analytics, Tickets: snap.tickets, Sources: snap.sources,
	}); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeServed reads a payload written by encodeServed back into a snapshot.
func decodeServed(payload []byte) (*snapshot, error) {
	zr, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("not gzip: %w", err)
	}
	defer zr.Close()
	var p servedPayload
	if err := json.NewDecoder(zr).Decode(&p); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	// encodeServed always writes a list, empty or not, and readiness reads a nil
	// one as "no assessment". A payload without one was not written by it.
	if p.Views == nil {
		return nil, errors.New("payload carries no findings list")
	}
	return &snapshot{
		views: p.Views, summary: p.Summary, owners: p.Owners, analytics: p.Analytics,
		tickets: p.Tickets, sources: p.Sources, byImage: indexByImage(p.Views),
	}, nil
}

// persistServed stores a published snapshot. A failure is logged and dropped: the
// cost is a slower next start, which is no reason to disturb this one.
func (s *Server) persistServed(ctx context.Context, snap *snapshot) {
	if s.history == nil || snap == nil || snap.err != "" {
		return
	}
	started := time.Now()
	payload, err := encodeServed(snap)
	if err != nil {
		slog.WarnContext(ctx, "history: could not encode the served assessment; a restart will wait for a fresh run", "error", err)
		return
	}
	if err := s.history.store.SaveServed(ctx, history.ServedAssessment{
		GeneratedAt: snap.generatedAt, Version: version.String(),
		SchemaVersion: servedSchemaVersion, Payload: payload,
	}, servedKeep); err != nil {
		slog.WarnContext(ctx, "history: could not store the served assessment; a restart will wait for a fresh run", "error", err)
		return
	}
	slog.InfoContext(ctx, "history: stored served assessment",
		"bytes", len(payload), "findings", len(snap.views), "took", time.Since(started).Round(time.Millisecond).String())
}

// restoreServed serves the newest stored assessment until this process's own first
// run completes. Every failure degrades to what a restart did before: nothing to
// serve until the first run finishes.
func (s *Server) restoreServed(ctx context.Context) {
	if s.history == nil {
		return
	}
	row, err := s.history.store.LatestServed(ctx, time.Time{})
	if err != nil {
		slog.WarnContext(ctx, "history: could not read the stored assessment; serving nothing until the first run completes", "error", err)
		return
	}
	if row == nil {
		slog.InfoContext(ctx, "history: no stored assessment to serve; waiting for the first run")
		return
	}
	if row.SchemaVersion != servedSchemaVersion {
		slog.WarnContext(ctx, "history: ignoring the stored assessment: it was written in a payload schema this build does not read",
			"stored_schema", row.SchemaVersion, "want_schema", servedSchemaVersion, "stored_by", row.Version)
		return
	}
	snap, err := decodeServed(row.Payload)
	if err != nil {
		slog.WarnContext(ctx, "history: ignoring the stored assessment: it could not be read",
			"id", row.ID, "stored_by", row.Version, "error", err)
		return
	}
	snap.generatedAt = row.GeneratedAt

	s.mu.Lock()
	if s.latest != nil && s.latest.views != nil {
		s.mu.Unlock()
		slog.InfoContext(ctx, "history: a fresh assessment finished before the stored one was read; not serving it")
		return
	}
	// A first run that has already failed is still worth stating over the older data.
	if s.latest != nil {
		snap.err = s.latest.err
	}
	s.latest, s.loaded = snap, true
	s.mu.Unlock()
	slog.InfoContext(ctx, "history: serving the stored assessment until a fresh one completes",
		"generated_at", row.GeneratedAt.Format(time.RFC3339), "age", time.Since(row.GeneratedAt).Round(time.Second).String(),
		"stored_by", row.Version, "findings", len(snap.views))
}
