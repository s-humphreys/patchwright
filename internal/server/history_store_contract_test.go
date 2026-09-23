package server

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/s-humphreys/patchwright/pkg/history"
	"github.com/s-humphreys/patchwright/pkg/history/postgres"
)

// The server's tests run on memStore, so memStore has to merge tracker tickets the
// way the real store does or the server tests prove nothing about production. The
// same script runs against memStore and, when PATCHWRIGHT_TEST_POSTGRES_DSN is set,
// against postgres.Lazy on a database of its own (the postgres package's tests
// truncate the shared one and run in parallel with this package).
func TestTicketStoreContract(t *testing.T) {
	stores := map[string]func(t *testing.T) history.Store{
		"memStore": func(*testing.T) history.Store { return newMemStore() },
		"postgres.Lazy": func(t *testing.T) history.Store {
			return postgres.NewLazy(postgres.Options{DSN: isolatedPostgres(t)})
		},
	}
	for name, open := range stores {
		t.Run(name, func(t *testing.T) { ticketStoreContract(t, open(t)) })
	}
}

func ticketStoreContract(t *testing.T, s history.Store) {
	ctx := context.Background()
	jul := func(d int) time.Time { return time.Date(2026, 7, d, 9, 0, 0, 0, time.UTC) }
	at := func(t time.Time) *time.Time { return &t }
	upsert := func(tickets ...history.TrackerTicket) {
		t.Helper()
		if err := s.UpsertTickets(ctx, tickets); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	keys := func(since, until time.Time) []string {
		t.Helper()
		got, err := s.Tickets(ctx, since, until)
		if err != nil {
			t.Fatalf("tickets: %v", err)
		}
		var out []string
		for _, tk := range got {
			out = append(out, tk.Key)
		}
		sort.Strings(out)
		return out
	}
	byKey := func(key string) history.TrackerTicket {
		t.Helper()
		got, err := s.Tickets(ctx, time.Time{}, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("tickets: %v", err)
		}
		for _, tk := range got {
			if tk.Key == key {
				return tk
			}
		}
		t.Fatalf("%s not stored", key)
		return history.TrackerTicket{}
	}

	if idx, err := s.TicketsIndexed(ctx); err != nil || idx.Tickets != 0 {
		t.Fatalf("empty index = %+v (%v)", idx, err)
	}
	if err := s.UpsertTickets(ctx, nil); err != nil {
		t.Fatalf("an empty upsert is a no-op: %v", err)
	}

	opened := jul(1)
	upsert(
		history.TrackerTicket{Key: "DVOP-1", Project: "DVOP", ItemKey: "k1", ItemOpenedAt: &opened, CreatedAt: jul(2),
			StartedAt: at(jul(3)), StartedFrom: history.StartedFromChangelog, StatusCategory: "indeterminate", LastSeenAt: jul(3)},
		history.TrackerTicket{Key: "DVOP-2", Project: "DVOP", CreatedAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
			ResolvedAt: at(time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC)), StatusCategory: "done", LastSeenAt: jul(3)},
		history.TrackerTicket{Key: "DVOP-3", Project: "DVOP", CreatedAt: jul(4), StartedAt: at(jul(6)),
			StartedFrom: history.StartedFromStatusCategory, StatusCategory: "indeterminate", LastSeenAt: jul(3)},
		history.TrackerTicket{Key: "DVOP-4", Project: "DVOP", CreatedAt: time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC),
			ResolvedAt: at(jul(15)), StatusCategory: "done", LastSeenAt: jul(3)},
	)

	// DVOP-1: its item closed so nothing matched, and the history could not be read.
	upsert(history.TrackerTicket{Key: "DVOP-1", Project: "DVOP", CreatedAt: jul(2), StartedAt: at(jul(8)),
		StartedFrom: history.StartedFromStatusCategory, ResolvedAt: at(jul(10)), StatusCategory: "done", LastSeenAt: jul(11)})
	d1 := byKey("DVOP-1")
	if d1.ItemKey != "k1" || d1.ItemOpenedAt == nil || !d1.ItemOpenedAt.Equal(opened) {
		t.Errorf("an empty match forgot the earlier one: %q %v", d1.ItemKey, d1.ItemOpenedAt)
	}
	if d1.StartedAt == nil || !d1.StartedAt.Equal(jul(3)) || d1.StartedFrom != history.StartedFromChangelog {
		t.Errorf("the fallback replaced the changelog start: %v from %q", d1.StartedAt, d1.StartedFrom)
	}
	if d1.ResolvedAt == nil || !d1.ResolvedAt.Equal(jul(10)) || d1.StatusCategory != "done" {
		t.Errorf("tracker fields not rewritten: %+v", d1)
	}

	// DVOP-1 again, no start at all this time: the stored one stands.
	upsert(history.TrackerTicket{Key: "DVOP-1", Project: "DVOP", CreatedAt: jul(2), ResolvedAt: at(jul(10)),
		StatusCategory: "done", LastSeenAt: jul(11)})
	if d1 = byKey("DVOP-1"); d1.StartedAt == nil || !d1.StartedAt.Equal(jul(3)) || d1.StartedFrom != history.StartedFromChangelog {
		t.Errorf("a missing start erased the stored one: %v from %q", d1.StartedAt, d1.StartedFrom)
	}

	// DVOP-3: the changelog is read at last and replaces the fallback.
	upsert(history.TrackerTicket{Key: "DVOP-3", Project: "DVOP", CreatedAt: jul(4), StartedAt: at(jul(5)),
		StartedFrom: history.StartedFromChangelog, StatusCategory: "indeterminate", LastSeenAt: jul(11)})
	if d3 := byKey("DVOP-3"); d3.StartedAt == nil || !d3.StartedAt.Equal(jul(5)) || d3.StartedFrom != history.StartedFromChangelog {
		t.Errorf("the changelog start did not replace the fallback: %v from %q", d3.StartedAt, d3.StartedFrom)
	}

	// Created or resolved in the window, plus every matched close whatever its date.
	if got := fmt.Sprint(keys(jul(1), jul(31))); got != "[DVOP-1 DVOP-3 DVOP-4]" {
		t.Errorf("July = %s, want DVOP-1, DVOP-3 (created) and DVOP-4 (resolved)", got)
	}
	if got := fmt.Sprint(keys(jul(20), jul(31))); got != "[DVOP-1]" {
		t.Errorf("late July = %s, want the matched close DVOP-1 only", got)
	}
	// Half-open: a ticket resolved exactly at until is outside, exactly at since in.
	if got := fmt.Sprint(keys(jul(15), jul(16))); got != "[DVOP-1 DVOP-4]" {
		t.Errorf("[15th, 16th) = %s, want DVOP-4 resolved at its start", got)
	}
	if got := fmt.Sprint(keys(jul(14), jul(15))); got != "[DVOP-1]" {
		t.Errorf("[14th, 15th) = %s, want DVOP-4 excluded at its end", got)
	}

	idx, err := s.TicketsIndexed(ctx)
	if err != nil || idx.Tickets != 4 || !idx.FirstCreated.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)) || !idx.LastSynced.Equal(jul(11)) {
		t.Errorf("index = %+v (%v)", idx, err)
	}

	// Resolved before the cutoff goes; open tickets never do, however old.
	p, err := s.Prune(ctx, time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC))
	if err != nil || p.Tickets != 2 {
		t.Fatalf("prune = %+v (%v), want DVOP-1 and DVOP-2", p, err)
	}
	if got := fmt.Sprint(keys(time.Time{}, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))); got != "[DVOP-3 DVOP-4]" {
		t.Errorf("after prune = %s, want the open DVOP-3 and DVOP-4 resolved after the cutoff", got)
	}
}

// isolatedPostgres creates a database for this test alone and drops it afterwards.
func isolatedPostgres(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("PATCHWRIGHT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PATCHWRIGHT_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	name := fmt.Sprintf("patchwright_server_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(ctx)
	})
	return u.String()
}
