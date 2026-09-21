// Package postgres is the history store. It is the only one, on purpose: two
// engines would be two sets of SQL to keep correct, and history is optional, so a
// deployment that does not want to run a database runs without it.
//
// Migrations are numbered SQL files embedded in the binary and applied at startup
// against a version table. One writer is assumed: the Deployment runs one replica
// and the CronJob forbids concurrency. The events table carries a uniqueness index
// so a replayed run inserts nothing twice, which is as far as the schema goes to
// tolerate a second writer.
package postgres

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/s-humphreys/patchwright/pkg/history"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Auth is how the connection authenticates.
type Auth string

const (
	// AuthPassword uses whatever the DSN carries.
	AuthPassword Auth = "password"
	// AuthAzure mints an Entra access token for Azure Database for PostgreSQL before
	// each connection and uses it as the password, following the pattern registry
	// authentication already uses for ACR. The DSN then names a user and no password.
	AuthAzure Auth = "azure"
)

// azureScope is the resource Azure Database for PostgreSQL expects a token for.
const azureScope = "https://ossrdbms-aad.database.windows.net/.default"

// Options configure the store.
type Options struct {
	DSN  string
	Auth Auth
	// Password, when set, replaces whatever the DSN carries. It exists so a
	// deployment can keep the connection string in plain configuration and the
	// password in a Secret, rather than URL-escaping one into the other.
	Password string
	// Timeout bounds every query. Zero means ten seconds.
	Timeout time.Duration
}

// Store is a history.Store on PostgreSQL.
type Store struct {
	pool    *pgxpool.Pool
	timeout time.Duration
}

// Open connects, applies migrations, and returns the store.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if strings.TrimSpace(opts.DSN) == "" {
		return nil, errors.New("history: no DSN")
	}
	cfg, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("history: parse DSN: %w", err)
	}
	switch opts.Auth {
	case "", AuthPassword:
		if opts.Password != "" {
			cfg.ConnConfig.Password = opts.Password
		}
	case AuthAzure:
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("history: azure credential: %w", err)
		}
		cfg.BeforeConnect = func(ctx context.Context, cc *pgx.ConnConfig) error {
			tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureScope}})
			if err != nil {
				return fmt.Errorf("history: azure token: %w", err)
			}
			cc.Password = tok.Token
			return nil
		}
	default:
		return nil, fmt.Errorf("history: unknown auth %q", opts.Auth)
	}
	// Small on purpose: one writer and a page's worth of readers.
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("history: connect: %w", err)
	}
	s := &Store{pool: pool, timeout: opts.Timeout}
	if s.timeout <= 0 {
		s.timeout = 10 * time.Second
	}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

func (s *Store) ctx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, s.timeout)
}

// migrate applies every embedded migration newer than the recorded version, in a
// transaction each, so a failed migration leaves the version where it was.
func (s *Store) migrate(ctx context.Context) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("history: schema_version: %w", err)
	}
	var current int
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
		return fmt.Errorf("history: read schema version: %w", err)
	}
	files, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		v, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("history: migration %s: name must start with a number", name)
		}
		if v <= current {
			continue
		}
		body, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("history: migrate %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("history: migrate %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_version (version) VALUES ($1)`, v); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("history: migrate %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("history: migrate %s: %w", name, err)
		}
		slog.InfoContext(ctx, "history: applied migration", "version", v, "file", name)
	}
	return nil
}

// Open returns every open item.
func (s *Store) Open(ctx context.Context) ([]history.State, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT id, opened_at, opened, current FROM items WHERE closed_at IS NULL ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("history: open items: %w", err)
	}
	defer rows.Close()
	var out []history.State
	for rows.Next() {
		var st history.State
		var opened, current []byte
		if err := rows.Scan(&st.ID, &st.OpenedAt, &opened, &current); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(opened, &st.Opened); err != nil {
			return nil, fmt.Errorf("history: item %d opened: %w", st.ID, err)
		}
		if err := json.Unmarshal(current, &st.Current); err != nil {
			return nil, fmt.Errorf("history: item %d current: %w", st.ID, err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// Record writes an assessment and applies its events in one transaction.
func (s *Store) Record(ctx context.Context, a history.Assessment, events []history.Event) (int64, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("history: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	risk, _ := json.Marshal(a.Risk)
	byClass, _ := json.Marshal(orEmpty(a.ByClass))
	byTeam, _ := json.Marshal(orEmpty(a.ByTeam))
	counts, _ := json.Marshal(orEmptyInts(a.Counts))
	actionableCounts, _ := json.Marshal(orEmptyInts(a.ActionableCounts))
	summary := []byte("{}")
	if a.Summary != nil {
		if b, err := json.Marshal(a.Summary); err == nil {
			summary = b
		}
	}
	var snapshot []byte
	if a.Items != nil {
		snapshot, _ = json.Marshal(a.Items)
	}
	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO assessments
		(started_at, finished_at, findings, actionable, items, risk, by_class, by_team,
		 counts, actionable_counts, distinct_cves, distinct_kev, distinct_epss_high, summary, snapshot)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING id`,
		a.StartedAt, a.FinishedAt, a.Findings, a.Actionable, a.ItemCount, risk, byClass, byTeam,
		counts, actionableCounts, a.DistinctCVEs, a.DistinctKEV, a.DistinctEPSSHigh, summary, snapshot).Scan(&id); err != nil {
		return 0, fmt.Errorf("history: insert assessment: %w", err)
	}
	if err := applyEvents(ctx, tx, id, events); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("history: commit: %w", err)
	}
	return id, nil
}

func orEmpty(m map[string]history.RiskStats) map[string]history.RiskStats {
	if m == nil {
		return map[string]history.RiskStats{}
	}
	return m
}

func orEmptyInts(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

// Append writes events against an assessment already recorded.
func (s *Store) Append(ctx context.Context, assessmentID int64, events []history.Event) error {
	if len(events) == 0 {
		return nil
	}
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("history: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := applyEvents(ctx, tx, assessmentID, events); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// applyEvents inserts events and keeps the items table in step with them.
func applyEvents(ctx context.Context, tx pgx.Tx, assessmentID int64, events []history.Event) error {
	for _, e := range events {
		itemID := e.ItemID
		switch e.Kind {
		case history.KindOpened:
			if e.Payload.Snapshot == nil {
				return fmt.Errorf("history: opened event for %s without a snapshot", e.Key)
			}
			snap, _ := json.Marshal(e.Payload.Snapshot)
			sp := e.Payload.Snapshot
			// A key that is already open is the replayed-run case: keep the row.
			if err := tx.QueryRow(ctx, `INSERT INTO items
				(key, repository, class, team, target, opened_at, opened, current)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
				ON CONFLICT (key) WHERE closed_at IS NULL DO UPDATE SET current = items.current
				RETURNING id`,
				sp.Key, sp.Repository, sp.Class, sp.Team, sp.Target, e.At, snap).Scan(&itemID); err != nil {
				return fmt.Errorf("history: open item %s: %w", e.Key, err)
			}
		case history.KindResolved, history.KindLapsed:
			if _, err := tx.Exec(ctx, `UPDATE items SET closed_at = $2, closed_kind = $3
				WHERE id = $1 AND closed_at IS NULL`, itemID, e.At, string(e.Kind)); err != nil {
				return fmt.Errorf("history: close item %d: %w", itemID, err)
			}
		case history.KindChanged:
			if e.Payload.Snapshot != nil {
				snap, _ := json.Marshal(e.Payload.Snapshot)
				if _, err := tx.Exec(ctx, `UPDATE items SET current = $2 WHERE id = $1`, itemID, snap); err != nil {
					return fmt.Errorf("history: update item %d: %w", itemID, err)
				}
			}
		case history.KindReassigned:
			if e.Payload.Snapshot != nil {
				sp := e.Payload.Snapshot
				snap, _ := json.Marshal(sp)
				if _, err := tx.Exec(ctx, `UPDATE items SET key = $2, class = $3, team = $4, current = $5
					WHERE id = $1`, itemID, sp.Key, sp.Class, sp.Team, snap); err != nil {
					return fmt.Errorf("history: reassign item %d: %w", itemID, err)
				}
			}
		}
		if itemID == 0 {
			return fmt.Errorf("history: %s event for %s has no item", e.Kind, e.Key)
		}
		payload, err := json.Marshal(e.Payload)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO events (item_id, assessment_id, kind, at, payload)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
			itemID, assessmentID, string(e.Kind), e.At, payload); err != nil {
			return fmt.Errorf("history: insert %s for %s: %w", e.Kind, e.Key, err)
		}
	}
	return nil
}

// Events returns events in [since, until), oldest first. The key is read from the
// item row so a reassigned item reports under its current owner.
func (s *Store) Events(ctx context.Context, since, until time.Time) ([]history.Event, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT e.id, e.item_id, i.key, e.kind, e.at, e.payload
		FROM events e JOIN items i ON i.id = e.item_id
		WHERE e.at >= $1 AND e.at < $2 ORDER BY e.at, e.id`, since, until)
	if err != nil {
		return nil, fmt.Errorf("history: events: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows pgx.Rows) ([]history.Event, error) {
	var out []history.Event
	for rows.Next() {
		var e history.Event
		var kind string
		var payload []byte
		if err := rows.Scan(&e.ID, &e.ItemID, &e.Key, &kind, &e.At, &payload); err != nil {
			return nil, err
		}
		e.Kind = history.Kind(kind)
		if err := json.Unmarshal(payload, &e.Payload); err != nil {
			return nil, fmt.Errorf("history: event %d payload: %w", e.ID, err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Assessments returns assessment rows in [since, until), oldest first.
func (s *Store) Assessments(ctx context.Context, since, until time.Time) ([]history.Assessment, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT id, started_at, finished_at, findings, actionable, items, risk, by_class, by_team,
		counts, actionable_counts, distinct_cves, distinct_kev, distinct_epss_high, summary
		FROM assessments WHERE finished_at >= $1 AND finished_at < $2 ORDER BY finished_at, id`, since, until)
	if err != nil {
		return nil, fmt.Errorf("history: assessments: %w", err)
	}
	defer rows.Close()
	var out []history.Assessment
	for rows.Next() {
		var a history.Assessment
		var risk, byClass, byTeam, counts, actionableCounts, summary []byte
		if err := rows.Scan(&a.ID, &a.StartedAt, &a.FinishedAt, &a.Findings, &a.Actionable, &a.ItemCount, &risk, &byClass, &byTeam,
			&counts, &actionableCounts, &a.DistinctCVEs, &a.DistinctKEV, &a.DistinctEPSSHigh, &summary); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(risk, &a.Risk); err != nil {
			return nil, fmt.Errorf("history: assessment %d risk: %w", a.ID, err)
		}
		_ = json.Unmarshal(byClass, &a.ByClass)
		_ = json.Unmarshal(byTeam, &a.ByTeam)
		_ = json.Unmarshal(counts, &a.Counts)
		_ = json.Unmarshal(actionableCounts, &a.ActionableCounts)
		if len(summary) > 0 && string(summary) != "{}" {
			a.Summary = json.RawMessage(summary)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AssessmentItems returns the work items recorded for one run.
func (s *Store) AssessmentItems(ctx context.Context, assessmentID int64) ([]history.Snapshot, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT snapshot FROM assessments WHERE id = $1`, assessmentID).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("history: assessment items: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var out []history.Snapshot
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("history: assessment %d items: %w", assessmentID, err)
	}
	return out, nil
}

// Item returns one key's record, or nil when it was never seen.
func (s *Store) Item(ctx context.Context, key string) (*history.ItemHistory, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT id, key, opened_at, closed_at, closed_kind, opened, current
		FROM items WHERE key = $1 ORDER BY opened_at, id`, key)
	if err != nil {
		return nil, fmt.Errorf("history: item: %w", err)
	}
	out := &history.ItemHistory{Key: key}
	var ids []int64
	for rows.Next() {
		var r history.ItemRow
		var closedKind *string
		var opened, current []byte
		if err := rows.Scan(&r.ID, &r.Key, &r.OpenedAt, &r.ClosedAt, &closedKind, &opened, &current); err != nil {
			rows.Close()
			return nil, err
		}
		if closedKind != nil {
			r.ClosedKind = history.Kind(*closedKind)
		}
		_ = json.Unmarshal(opened, &r.Opened)
		_ = json.Unmarshal(current, &r.Current)
		out.Items = append(out.Items, r)
		ids = append(ids, r.ID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	erows, err := s.pool.Query(ctx, `SELECT e.id, e.item_id, i.key, e.kind, e.at, e.payload
		FROM events e JOIN items i ON i.id = e.item_id
		WHERE e.item_id = ANY($1) ORDER BY e.at, e.id`, ids)
	if err != nil {
		return nil, fmt.Errorf("history: item events: %w", err)
	}
	defer erows.Close()
	out.Events, err = scanEvents(erows)
	return out, err
}

// First is when the record begins.
func (s *Store) First(ctx context.Context) (time.Time, bool, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	var t *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT MIN(finished_at) FROM assessments`).Scan(&t); err != nil {
		return time.Time{}, false, fmt.Errorf("history: first: %w", err)
	}
	if t == nil {
		return time.Time{}, false, nil
	}
	return *t, true, nil
}

// Prune applies retention. Open items are kept whatever their age: an item still in
// the queue is current state, not history.
func (s *Store) Prune(ctx context.Context, before time.Time) (history.Pruned, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	var p history.Pruned
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return p, fmt.Errorf("history: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `DELETE FROM events WHERE at < $1`, before)
	if err != nil {
		return p, fmt.Errorf("history: prune events: %w", err)
	}
	p.Events = tag.RowsAffected()
	tag, err = tx.Exec(ctx, `DELETE FROM items WHERE closed_at IS NOT NULL AND closed_at < $1`, before)
	if err != nil {
		return p, fmt.Errorf("history: prune items: %w", err)
	}
	p.Items = tag.RowsAffected()
	tag, err = tx.Exec(ctx, `DELETE FROM assessments WHERE finished_at < $1`, before)
	if err != nil {
		return p, fmt.Errorf("history: prune assessments: %w", err)
	}
	p.Assessments = tag.RowsAffected()
	return p, tx.Commit(ctx)
}

var _ history.Store = (*Store)(nil)
