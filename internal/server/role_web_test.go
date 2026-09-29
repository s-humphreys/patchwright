package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A web replica given no Jira credentials says the plan is the worker's, rather than
// that ticketing is not configured, and still refuses to apply anything.
func TestWebWithoutJiraCredentialsSaysThePlanIsTheWorkers(t *testing.T) {
	store := newMemStore()
	New(stubAssessor{findings: estateFindings()}).WithRole(RoleWorker).WithHistory(store, 90*24*time.Hour).Refresh(context.Background())
	web := New(nil).WithRole(RoleWeb).WithHistory(store, 90*24*time.Hour).WithTicketPlanOnWorker()
	web.webTick(context.Background(), true)
	h := web.Handler()

	var body struct {
		Error string `json:"error"`
	}
	if code := getJSON(t, h, "/api/v1/tickets", &body); code != http.StatusServiceUnavailable ||
		!strings.Contains(body.Error, "made by the assessment worker") || strings.Contains(body.Error, "not configured") {
		t.Errorf("GET /api/v1/tickets = %d %q, want 503 naming the worker", code, body.Error)
	}
	if rec := post(h, "/api/v1/tickets", `{"confirm": true}`); rec.Code != http.StatusConflict {
		t.Errorf("POST /api/v1/tickets = %d, want 409 (%s)", rec.Code, rec.Body)
	}

	// Without the flag, no Jira at all is still "not configured".
	plain := New(nil).WithRole(RoleWeb).WithHistory(store, 90*24*time.Hour)
	plain.webTick(context.Background(), true)
	getJSON(t, plain.Handler(), "/api/v1/tickets", &body)
	if !strings.Contains(body.Error, "not configured") {
		t.Errorf("without Jira configured the plan says %q", body.Error)
	}
}
