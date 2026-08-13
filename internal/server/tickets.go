package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/s-humphreys/patchwright/pkg/sink"
	"github.com/s-humphreys/patchwright/pkg/ticket"
)

// Ticketing over the API.
//
// GET  /api/v1/tickets   what reconciliation would do against the cached assessment
// POST /api/v1/tickets   apply it, only with {"confirm": true}
//
// The plan is computed from the cached assessment, so the API answers "what would
// you raise from the data you are serving?" rather than from a file someone else
// produced. Two things are deliberate:
//
//   - Applying requires confirm: true in the body. A POST that creates Jira issues
//     by omission is the wrong default for an HTTP endpoint, and this one sits
//     behind a shared token rather than an identity.
//   - Auto-ticketing on the refresh schedule is opt-in and separate. A service that
//     starts raising tickets the moment it is deployed is not a good surprise.

// Ticketer plans and applies ticket work. *ticket.Planner plus *ticket.Jira satisfy
// this between them; tests provide a stub.
type Ticketer interface {
	Plan(findings []sink.FindingView) (*ticket.Plan, error)
	OpenByImage(ctx context.Context) (map[string][]ticket.Existing, error)
	ticket.Applier
}

// WithTicketing attaches ticket planning. autoApply raises and reconciles tickets
// on every scheduled refresh; without it the endpoints still work on request.
func (s *Server) WithTicketing(t Ticketer, autoApply bool) *Server {
	s.ticketer = t
	s.autoTicket = autoApply
	return s
}

// actionView is one reconciliation step as the API reports it.
type actionView struct {
	Kind    string `json:"kind"`
	Why     string `json:"why"`
	Ticket  string `json:"ticket,omitempty"`
	Summary string `json:"summary,omitempty"`
	// Route names the routing rule that chose this action's tracker, so a caller
	// reviewing a plan can see whose board each ticket lands on.
	Route   string   `json:"route,omitempty"`
	Images  []string `json:"images,omitempty"`
	Comment string   `json:"comment,omitempty"`
	// Error is set on an applied action that failed. Present so a caller sees
	// partial success rather than assuming all or nothing.
	Error string `json:"error,omitempty"`
}

func (s *Server) handleTicketPlan(w http.ResponseWriter, r *http.Request) {
	actions, err := s.planTickets(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Applied    bool           `json:"applied"`
		Actions    []actionView   `json:"actions"`
	}{s.meta(), false, viewActions(actions, nil)})
}

func (s *Server) handleTicketApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Confirm bool `json:"confirm"`
	}
	// An empty body is valid and means "not confirmed", so a decode failure on an
	// absent body must not be an error.
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}

	actions, err := s.planTickets(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if !body.Confirm {
		// Reject rather than silently returning a plan: the caller asked to change
		// something, and answering with a plan as though that were the same thing
		// invites a false sense of "it worked".
		writeJSON(w, http.StatusBadRequest, struct {
			Error   string       `json:"error"`
			Actions []actionView `json:"actions"`
		}{`refusing to apply without {"confirm": true}; GET this path for the plan`,
			viewActions(actions, nil)})
		return
	}

	results := ticket.Apply(r.Context(), s.ticketer, actions)
	auditWrites(r.Context(), "api", results)

	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Applied    bool           `json:"applied"`
		Actions    []actionView   `json:"actions"`
	}{s.meta(), true, viewActions(nil, results)})
}

// planTickets reconciles the cached assessment against Jira.
func (s *Server) planTickets(ctx context.Context) ([]ticket.Action, error) {
	if s.ticketer == nil {
		return nil, errTicketingNotConfigured
	}
	snap := s.snapshot()
	if snap == nil || snap.views == nil {
		return nil, errNoAssessment
	}
	plan, err := s.ticketer.Plan(snap.views)
	if err != nil {
		return nil, err
	}
	index, err := s.ticketer.OpenByImage(ctx)
	if err != nil {
		return nil, err
	}
	return ticket.Reconcile(ticket.ReconcileInput{
		Drafts: plan.Drafts, OpenByImage: index, Findings: snap.views,
	}), nil
}

// autoReconcile runs ticketing after a scheduled refresh, when enabled. Failures
// are logged and dropped: the assessment is the service's job, and losing a
// ticketing run must not cost it.
func (s *Server) autoReconcile(ctx context.Context) {
	if !s.autoTicket || s.ticketer == nil {
		return
	}
	actions, err := s.planTickets(ctx)
	if err != nil {
		slog.WarnContext(ctx, "auto-ticketing: could not plan", "error", err)
		return
	}
	results := ticket.Apply(ctx, s.ticketer, actions)
	auditWrites(ctx, "schedule", results)
}

// auditWrites records every change made to Jira and what triggered it.
//
// The shared token carries no identity, so a write cannot be attributed to a person.
// What can be recorded is whether it came from the refresh schedule or an API call,
// and exactly which tickets were touched: without the per-ticket lines the only trace
// of an automated change would be a count, which is not an audit trail.
func auditWrites(ctx context.Context, source string, results []ticket.Result) {
	counts := ticket.Summarize(results)
	failed := 0
	for _, r := range results {
		if r.Action.Kind == ticket.ActionSkip {
			continue // nothing changed, so there is nothing to record
		}
		if r.Err != nil {
			failed++
			slog.WarnContext(ctx, "jira write failed",
				"source", source, "action", r.Action.Kind, "ticket", r.Key, "error", r.Err)
			continue
		}
		slog.InfoContext(ctx, "jira write",
			"source", source, "action", r.Action.Kind, "ticket", r.Key,
			// Which tracker, now that a deployment can write to several: "created
			// PROJ-1" is not an audit trail if it cannot say whose board that was.
			"route", r.Action.Draft.Route,
			"images", r.Action.Images, "why", r.Action.Why)
	}
	slog.InfoContext(ctx, "ticket reconciliation complete",
		"source", source,
		"created", counts[ticket.ActionCreate], "extended", counts[ticket.ActionExtend],
		"commented", counts[ticket.ActionNoteStale]+counts[ticket.ActionNoteDone],
		"unchanged", counts[ticket.ActionSkip], "failed", failed)
}

func viewActions(actions []ticket.Action, results []ticket.Result) []actionView {
	if results != nil {
		out := make([]actionView, 0, len(results))
		for _, r := range results {
			v := viewAction(r.Action)
			if r.Key != "" {
				v.Ticket = r.Key
			}
			if r.Err != nil {
				v.Error = r.Err.Error()
			}
			out = append(out, v)
		}
		return out
	}
	out := make([]actionView, 0, len(actions))
	for _, a := range actions {
		out = append(out, viewAction(a))
	}
	return out
}

func viewAction(a ticket.Action) actionView {
	return actionView{
		Kind: string(a.Kind), Why: a.Why, Ticket: a.TicketKey,
		Summary: a.Draft.Summary, Route: a.Draft.Route,
		Images: actionImages(a), Comment: a.Message,
	}
}

// actionImages reports the images an action concerns: the draft's for a creation,
// the additions for an extension.
func actionImages(a ticket.Action) []string {
	if a.Kind == ticket.ActionCreate {
		return a.Draft.Images
	}
	return a.Images
}
