package ticket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A body cut at the cap used to surface as a JSON decode error, which sent the
// diagnosis towards the response's shape rather than its size.
func TestOversizedResponseIsReportedAsSuch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issues":[`))
		filler := []byte(strings.Repeat(" ", 1<<16))
		for written := 0; written <= maxResponseBytes; written += len(filler) {
			_, _ = w.Write(filler)
		}
		_, _ = w.Write([]byte(`]}`))
	}))
	defer srv.Close()

	j := &Jira{BaseURL: srv.URL, Client: srv.Client(), Email: "e", Token: "t"}
	var out any
	err := j.do(context.Background(), http.MethodGet, "/rest/api/3/search/jql", nil, &out)
	if err == nil || !strings.Contains(err.Error(), "response larger than") {
		t.Fatalf("err = %v, want the size cap named", err)
	}
	if strings.Contains(err.Error(), "decode") {
		t.Fatalf("err = %v: a cut body must not be reported as a decode failure", err)
	}
}

func TestResponseUnderTheCapDecodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	j := &Jira{BaseURL: srv.URL, Client: srv.Client(), Email: "e", Token: "t"}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := j.do(context.Background(), http.MethodGet, "/x", nil, &out); err != nil || !out.OK {
		t.Fatalf("err = %v, ok = %v", err, out.OK)
	}
}
