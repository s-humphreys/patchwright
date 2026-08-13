package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/sink"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

// stubTicketer plans a fixed set of drafts and records what gets applied.
type stubTicketer struct {
	updated   []string
	closed    []string
	autoClose bool
	drafts    []ticket.Draft
	open      map[string][]ticket.Existing
	planErr   error
	openErr   error
	created   []ticket.Draft
	comments  map[string][]string
	extended  map[string][]string
}

func newStubTicketer(drafts ...ticket.Draft) *stubTicketer {
	return &stubTicketer{
		drafts: drafts, open: map[string][]ticket.Existing{},
		comments: map[string][]string{}, extended: map[string][]string{},
	}
}

func (s *stubTicketer) Plan([]sink.FindingView) (*ticket.Plan, error) {
	if s.planErr != nil {
		return nil, s.planErr
	}
	return &ticket.Plan{Drafts: s.drafts}, nil
}

func (s *stubTicketer) OpenByImage(context.Context) (map[string][]ticket.Existing, error) {
	return s.open, s.openErr
}

func (s *stubTicketer) Create(_ context.Context, d ticket.Draft) (string, error) {
	s.created = append(s.created, d)
	return "PROJ-NEW", nil
}

func (s *stubTicketer) AddImages(_ context.Context, key string, images []string) error {
	s.extended[key] = append(s.extended[key], images...)
	return nil
}

func (s *stubTicketer) Config() config.JiraConfig {
	return config.JiraConfig{Project: "PROJ", AutoClose: s.autoClose}
}

func (s *stubTicketer) Close(_ context.Context, key, comment string) error {
	s.closed = append(s.closed, key)
	return nil
}

func (s *stubTicketer) Update(_ context.Context, key string, d ticket.Draft) error {
	s.updated = append(s.updated, key)
	return nil
}

func (s *stubTicketer) Comment(_ context.Context, key, body string) error {
	s.comments[key] = append(s.comments[key], body)
	return nil
}

func ticketServer(t *testing.T, st *stubTicketer, auto bool) *Server {
	t.Helper()
	s := New(stubAssessor{findings: []model.Finding{
		finding("acr.io/app:1", "platform", "team", true, false),
	}}).WithTicketing(st, auto)
	s.Refresh(context.Background())
	return s
}

func draft(summary string, images ...string) ticket.Draft {
	return ticket.Draft{Summary: summary, Images: images, Description: "body"}
}

// GET is the plan: it must never change anything.
func TestGetTicketsReturnsThePlanWithoutApplying(t *testing.T) {
	st := newStubTicketer(draft("Upgrade app to 2.0.0", "acme/app"))
	s := ticketServer(t, st, false)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tickets", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Applied bool `json:"applied"`
		Actions []struct {
			Kind    string `json:"kind"`
			Summary string `json:"summary"`
		} `json:"actions"`
	}
	decodeInto(t, rec, &body)

	if body.Applied {
		t.Error("a GET must not report having applied anything")
	}
	if len(body.Actions) != 1 || body.Actions[0].Kind != "create" {
		t.Fatalf("actions = %+v, want one create", body.Actions)
	}
	if len(st.created) != 0 {
		t.Errorf("a GET created %d ticket(s)", len(st.created))
	}
}

// A POST that creates Jira issues by omission is the wrong default.
func TestPostTicketsRefusesWithoutConfirm(t *testing.T) {
	st := newStubTicketer(draft("Upgrade app to 2.0.0", "acme/app"))
	s := ticketServer(t, st, false)

	for _, body := range []string{"", "{}", `{"confirm":false}`} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tickets", strings.NewReader(body))
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, rec.Code)
		}
		if len(st.created) != 0 {
			t.Fatalf("body %q created a ticket without confirmation", body)
		}
	}
}

func TestPostTicketsAppliesWithConfirm(t *testing.T) {
	st := newStubTicketer(draft("Upgrade app to 2.0.0", "acme/app"))
	s := ticketServer(t, st, false)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tickets", strings.NewReader(`{"confirm":true}`))
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Applied bool `json:"applied"`
		Actions []struct {
			Kind   string `json:"kind"`
			Ticket string `json:"ticket"`
		} `json:"actions"`
	}
	decodeInto(t, rec, &body)
	if !body.Applied || len(st.created) != 1 {
		t.Fatalf("applied=%v created=%d, want true/1", body.Applied, len(st.created))
	}
	if body.Actions[0].Ticket != "PROJ-NEW" {
		t.Errorf("the new key is not reported back: %+v", body.Actions[0])
	}
}

// Without a ticketer the endpoint says so, rather than reporting an empty plan that
// reads as "nothing to do".
func TestTicketEndpointsSayWhenTicketingIsNotConfigured(t *testing.T) {
	h := newTestServer(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tickets", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not configured") {
		t.Errorf("body does not explain why: %s", rec.Body.String())
	}
}

// Off by default: a deployment must not begin writing to Jira on its own.
func TestAutoTicketingIsOffByDefault(t *testing.T) {
	st := newStubTicketer(draft("Upgrade app to 2.0.0", "acme/app"))
	s := ticketServer(t, st, false)
	s.Refresh(context.Background())
	if len(st.created) != 0 {
		t.Errorf("a refresh created %d ticket(s) with auto-ticketing off", len(st.created))
	}
}

func TestAutoTicketingAppliesOnRefreshWhenEnabled(t *testing.T) {
	st := newStubTicketer(draft("Upgrade app to 2.0.0", "acme/app"))
	s := ticketServer(t, st, true) // the constructor refreshes once
	if len(st.created) != 1 {
		t.Fatalf("created %d, want 1 from the initial refresh", len(st.created))
	}
	// A second refresh with the ticket now open must not raise it again.
	st.open["acme/app"] = []ticket.Existing{{Key: "PROJ-NEW", Summary: "Upgrade app to 2.0.0"}}
	s.Refresh(context.Background())
	if len(st.created) != 1 {
		t.Errorf("created %d, want no duplicate on the second refresh", len(st.created))
	}
}

// A failed assessment must not trigger ticketing: it would act on stale cached data
// while reporting an error.
func TestAutoTicketingSkipsAFailedAssessment(t *testing.T) {
	st := newStubTicketer(draft("Upgrade app to 2.0.0", "acme/app"))
	s := New(stubAssessor{err: errors.New("provider unreachable")}).WithTicketing(st, true)
	s.Refresh(context.Background())
	if len(st.created) != 0 {
		t.Errorf("ticketing ran against a failed assessment (%d created)", len(st.created))
	}
}

// Losing a ticketing run must not cost the assessment.
func TestTicketingFailureDoesNotBreakTheAssessment(t *testing.T) {
	st := newStubTicketer(draft("Upgrade app to 2.0.0", "acme/app"))
	st.openErr = errors.New("jira unreachable")
	s := ticketServer(t, st, true)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("summary status = %d, want 200 despite Jira being down", rec.Code)
	}
	var raw map[string]json.RawMessage
	decodeInto(t, rec, &raw)
	if _, ok := raw["summary"]; !ok {
		t.Error("the assessment was lost because ticketing failed")
	}
}

// Pending work nobody can see is the same failure as absent data rendered as
// zero: the schedule has to plan and say so even when it will not apply.
func TestSchedulePlansAndLogsWhenAutoTicketingIsOff(t *testing.T) {
	var buf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(restore)

	st := newStubTicketer(ticket.Draft{Summary: "Upgrade app to 2.0", Images: []string{"acme/app"}})
	s := New(stubAssessor{findings: []model.Finding{assessedFinding("acr.io/app:1", "platform", "team", true)}}).
		WithTicketing(st, false) // auto-ticketing off
	s.Refresh(context.Background())

	out := buf.String()
	if !strings.Contains(out, "ticket plan") {
		t.Errorf("no plan was logged with auto-ticketing off:\n%s", out)
	}
	if !strings.Contains(out, "will not be applied") {
		t.Errorf("the log does not say the plan is not being applied:\n%s", out)
	}
	// Nothing may have been written.
	if len(st.created)+len(st.updated)+len(st.closed) != 0 {
		t.Errorf("writes happened with auto-ticketing off: created=%v updated=%v closed=%v",
			st.created, st.updated, st.closed)
	}
}

// A plan that is about to be applied must not read identically to one that is
// not, or the log cannot answer "did that happen?".
func TestAppliedPlansAreLoggedAsApplied(t *testing.T) {
	var buf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(restore)

	st := newStubTicketer(ticket.Draft{Summary: "Upgrade app to 2.0", Images: []string{"acme/app"}})
	s := New(stubAssessor{findings: []model.Finding{assessedFinding("acr.io/app:1", "platform", "team", true)}}).
		WithTicketing(st, true)
	s.Refresh(context.Background())

	out := buf.String()
	if !strings.Contains(out, "applied=true") {
		t.Errorf("an applied plan was not logged as applied:\n%s", out)
	}
	if strings.Contains(out, "will not be applied") {
		t.Errorf("an applied plan claimed it would not be applied:\n%s", out)
	}
	if len(st.created) == 0 {
		t.Error("auto-ticketing was on but nothing was created")
	}
}

// Every action kind must appear in both log lines. This exists because it did not:
// "update" was applied and counted, but the hand-written summary omitted it, so a
// run that rewrote a ticket reported nothing about it. A list written by hand
// cannot be trusted to grow with the type.
func TestEveryActionKindIsReported(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		applied       bool
	}{
		{"plan", "ticket plan", false},
		{"audit", "ticket reconciliation complete", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			restore := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
			defer slog.SetDefault(restore)

			actions := make([]ticket.Action, 0, len(ticket.ActionKinds()))
			for _, kind := range ticket.ActionKinds() {
				actions = append(actions, ticket.Action{Kind: kind, TicketKey: "PROJ-1"})
			}
			if tc.applied {
				results := make([]ticket.Result, 0, len(actions))
				for _, a := range actions {
					results = append(results, ticket.Result{Action: a, Key: a.TicketKey})
				}
				auditWrites(context.Background(), "test", results)
			} else {
				logPlan(context.Background(), "test", actions, false)
			}

			out := buf.String()
			if !strings.Contains(out, tc.message) {
				t.Fatalf("%q was not logged:\n%s", tc.message, out)
			}
			for _, kind := range ticket.ActionKinds() {
				if !strings.Contains(out, string(kind)+"=") {
					t.Errorf("kind %q is missing from the %s line:\n%s", kind, tc.name, out)
				}
			}
		})
	}
}
