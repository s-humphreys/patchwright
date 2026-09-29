package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/history"
)

// A request the store did not confirm in time may still commit, so it is neither
// reported as failed nor as queued; any other failure is a 503.
func TestWebRefreshIsHonestWhenTheStoreIsSlow(t *testing.T) {
	for name, tc := range map[string]struct {
		err      error
		code     int
		contains string
	}{
		"timeout":     {fmt.Errorf("history: request refresh: %w", context.DeadlineExceeded), http.StatusAccepted, "may still be queued"},
		"unreachable": {errors.New("history store unavailable: connection refused"), http.StatusServiceUnavailable, "could not pass"},
	} {
		t.Run(name, func(t *testing.T) {
			store := newMemStore()
			store.err = tc.err
			web := New(nil).WithRole(RoleWeb).WithHistory(store, 90*24*time.Hour)
			rec := post(web.Handler(), "/api/v1/assessments", "")
			if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.contains) {
				t.Errorf("POST /api/v1/assessments = %d %s, want %d containing %q", rec.Code, rec.Body, tc.code, tc.contains)
			}
		})
	}
}

// The refresh message promises a pick-up time only when there is a worker to keep it.
func TestWebRefreshMessageFollowsTheWorker(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		heartbeat time.Time
		want      string
	}{
		"alive":          {now.Add(-5 * time.Second), "picks requests up within"},
		"silent":         {now.Add(-2 * workerStale), "has not reported since 2026-09-29T11:58:00Z"},
		"never reported": {time.Time{}, "no assessment worker has reported yet"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := refreshMessage(history.WorkerState{Heartbeat: tc.heartbeat}, now); !strings.Contains(got, tc.want) {
				t.Errorf("message = %q, want it to contain %q", got, tc.want)
			}
		})
	}

	// And end to end, through the handler, with a worker gone quiet.
	store := newMemStore()
	_ = store.SaveWorkerState(context.Background(), history.WorkerState{Heartbeat: time.Now().Add(-2 * workerStale)})
	web := New(nil).WithRole(RoleWeb).WithHistory(store, 90*24*time.Hour)
	web.webTick(context.Background(), false)
	rec := post(web.Handler(), "/api/v1/assessments", "")
	var body struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusAccepted || strings.Contains(body.Message, "within") || !strings.Contains(body.Message, "queued") {
		t.Errorf("with a silent worker: %d %q", rec.Code, body.Message)
	}
}
