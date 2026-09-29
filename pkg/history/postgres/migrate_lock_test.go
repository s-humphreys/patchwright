package postgres

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// freshDatabase creates an empty database of its own, since the other tests here
// share one and truncate it, and this one needs a database no migration has touched.
func freshDatabase(t *testing.T) string {
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
	name := fmt.Sprintf("patchwright_migrate_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(ctx)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// A split deployment starts a worker and its web replicas against one database at
// once. Every one of them must come up with a store: without the migration lock the
// concurrent CREATE TABLEs collide and all but one are left without history until
// their next retry.
func TestConcurrentOpenOfAnEmptyDatabase(t *testing.T) {
	dsn := freshDatabase(t)
	const processes = 6
	var (
		wg     sync.WaitGroup
		start  = make(chan struct{})
		errs   = make([]error, processes)
		stores = make([]*Store, processes)
	)
	for i := range processes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			stores[i], errs[i] = Open(context.Background(), Options{DSN: dsn})
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("process %d could not open the store: %v", i, err)
			continue
		}
		defer stores[i].Close()
	}
	if t.Failed() {
		return
	}
	var applied, highest int
	if err := stores[0].pool.QueryRow(context.Background(),
		`SELECT COUNT(*), MAX(version) FROM schema_version`).Scan(&applied, &highest); err != nil {
		t.Fatal(err)
	}
	if applied != highest {
		t.Errorf("schema_version holds %d rows up to version %d: a migration was recorded twice or skipped", applied, highest)
	}
}
