package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The ticket plan is a page of its own, and the routing has to behave like one: a real
// path, gated the same way, and not the dashboard by another name.
func TestTheTicketPlanIsItsOwnPage(t *testing.T) {
	h := newTestServer(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tickets", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type = %q, want html", ct)
	}
	body := rec.Body.String()
	// Its own document, loading only its own entry point.
	if !strings.Contains(body, "/static/app/tickets.js") {
		t.Error("the page does not load the ticket plan module")
	}
	if strings.Contains(body, "/static/app/main.js") {
		t.Error("the ticket page pulls in the dashboard's entry point")
	}
	// The dashboard's furniture has no business here.
	for _, absent := range []string{`id="findings"`, `id="breakdown"`, `id="tiles"`} {
		if strings.Contains(body, absent) {
			t.Errorf("the ticket page carries the dashboard's %s", absent)
		}
	}
	// And every page mounts the shared header, or a separate page is a dead end.
	//
	// The links themselves used to be checked here, and are now rendered by the
	// header component - which is where they are tested (nav.test.js covers the
	// destinations and which one is marked current). What this can still prove is
	// that each document actually mounts it, and says which page it is.
	if !strings.Contains(body, `<pw-nav page="tickets">`) {
		t.Error("the ticket page does not mount the shared header")
	}
	if !strings.Contains(body, "/static/app/nav.js") {
		t.Error("the ticket page does not load the header component")
	}

	for path, page := range map[string]string{"/": "queue", "/analytics": "analytics"} {
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, path, nil))
		if want := `<pw-nav page="` + page + `">`; !strings.Contains(rec2.Body.String(), want) {
			t.Errorf("%s does not mount the header as %q", path, page)
		}
	}
}

func TestTheTicketPageNeedsTheSameCredentialAsEverythingElse(t *testing.T) {
	// It lists what is about to be written to a tracker, and names the tickets. It must
	// not be the one page that forgot to be gated.
	s := New(stubAssessor{}).WithAuth("s3cret")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tickets", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 without a token", rec.Code)
	}

	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tickets", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	s.Handler().ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Errorf("status = %d with a valid token, want 200", rec2.Code)
	}
}
