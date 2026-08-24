package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/config"
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
	// Config is the ticket configuration, so reconciliation can resolve per-project
	// decisions such as whether closing is allowed on that board. Asked rather than
	// assumed: the server must not enable a write the configuration did not.
	Config() config.JiraConfig
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
	Route string `json:"route,omitempty"`
	// URL links the existing ticket, so a plan is one click from the thing it
	// describes rather than a key to copy. Absent for a creation, which has no
	// ticket yet, and when the Jira base URL is unknown.
	URL     string   `json:"url,omitempty"`
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
	logPlan(r.Context(), "api", actions, false, s.autoTicket)
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Applied    bool           `json:"applied"`
		AutoApply  bool           `json:"auto_apply"`
		Actions    []actionView   `json:"actions"`
	}{s.meta(), false, s.autoTicket, s.viewActions(actions, nil)})
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
			s.viewActions(actions, nil)})
		return
	}

	logPlan(r.Context(), "api", actions, true, s.autoTicket)
	results := ticket.Apply(r.Context(), s.ticketer, actions)
	auditWrites(r.Context(), "api", results)

	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Applied    bool           `json:"applied"`
		Actions    []actionView   `json:"actions"`
	}{s.meta(), true, s.viewActions(nil, results)})
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
		Drafts: plan.Drafts, Skipped: plan.Skips, OpenByImage: index, Findings: snap.views,
		Config: s.ticketer.Config(),
	}), nil
}

// autoReconcile reconciles tickets after a scheduled refresh. Failures are logged
// and dropped: the assessment is the service's job, and losing a ticketing run
// must not cost it.
//
// It plans on every refresh even when applying is disabled, and logs what it
// would do. Previously it returned before planning, so a deployment without
// --auto-ticket gave no indication that work was piling up — the plan existed
// only for whoever thought to call the API. Pending work nobody can see is the
// same failure as absent data rendered as zero: the log has to say it.
func (s *Server) autoReconcile(ctx context.Context) {
	if s.ticketer == nil {
		return
	}
	actions, err := s.planTickets(ctx)
	if err != nil {
		slog.WarnContext(ctx, "ticket reconciliation: could not plan", "error", err)
		return
	}
	logPlan(ctx, "schedule", actions, s.autoTicket, s.autoTicket)
	if !s.autoTicket {
		return
	}
	results := ticket.Apply(ctx, s.ticketer, actions)
	auditWrites(ctx, "schedule", results)
}

// logPlan records what reconciliation intends to do, whether or not it will be
// applied. Skips are summarised rather than listed: "already correct" is worth
// counting and not worth a line each.
//
// applied says whether these actions are about to be written. Logging a plan that
// reads identically in both cases would be worse than not logging it, since the
// reader's next question is always "did that happen?".
func logPlan(ctx context.Context, source string, actions []ticket.Action, applied, autoApply bool) {
	counts := map[ticket.ActionKind]int{}
	for _, a := range actions {
		counts[a.Kind]++
	}
	// Neither skips nor holds are writes: one is already correct, the other is
	// waiting on data. Counting them as pending would overstate what is about to
	// happen.
	writes := len(actions) - counts[ticket.ActionSkip] - counts[ticket.ActionHold]
	attrs := []any{"source", source, "applied", applied}
	for _, kind := range ticket.ActionKinds() {
		attrs = append(attrs, string(kind), counts[kind])
	}
	slog.InfoContext(ctx, "ticket plan", attrs...)
	if writes == 0 {
		return
	}
	// Said once, not per action: the point is that something is waiting, and
	// repeating it on every line would bury the actions themselves.
	//
	// "This request applied nothing" and "nothing will apply it" are different
	// claims, and conflating them made the log assert auto-ticketing was off on a
	// deployment where it was on.
	switch {
	case applied:
		// Nothing to say: the writes are reported individually by the audit.
	case autoApply:
		slog.InfoContext(ctx, "ticket plan not applied by this request; the next scheduled "+
			"refresh will apply it (auto-ticketing is on)",
			"source", source, "pending_writes", writes)
	default:
		slog.InfoContext(ctx, "ticket plan will not be applied (auto-ticketing is off); "+
			"POST /api/v1/tickets with {\"confirm\": true} to apply it",
			"source", source, "pending_writes", writes)
	}
	for _, a := range actions {
		if a.Kind == ticket.ActionSkip {
			continue
		}
		if a.Kind == ticket.ActionHold {
			// Logged, because a ticket nobody can judge is worth seeing, but at debug:
			// on a broken credential this is every ticket at once.
			slog.DebugContext(ctx, "ticket plan hold",
				"source", source, "ticket", a.TicketKey, "why", a.Why)
			continue
		}
		slog.InfoContext(ctx, "ticket plan action",
			"source", source, "applied", applied, "action", a.Kind,
			"ticket", a.TicketKey, "route", a.Draft.Route,
			"summary", a.Draft.Summary, "why", a.Why)
	}
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
		if r.NoOp {
			// Not a write, so not part of the audit trail — but worth saying, or a
			// quiet run looks like a broken one.
			slog.DebugContext(ctx, "jira write skipped: already present",
				"source", source, "action", r.Action.Kind, "ticket", r.Key)
			continue
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
	attrs := []any{"source", source}
	// Every kind, by iteration: a hand-written list drops a new kind silently and
	// the run reads as though it did less than it did.
	for _, kind := range ticket.ActionKinds() {
		attrs = append(attrs, string(kind), counts[kind])
	}
	attrs = append(attrs, "already_present", ticket.NoOps(results), "failed", failed)
	slog.InfoContext(ctx, "ticket reconciliation complete", attrs...)
}

func (s *Server) viewActions(actions []ticket.Action, results []ticket.Result) []actionView {
	out := viewActions(actions, results)
	for i := range out {
		out[i].URL = s.ticketURL(out[i].Ticket)
	}
	return out
}

// ticketURL builds a browse link for a ticket key, or "" when the base URL is not
// known — a broken link is worse than none.
func (s *Server) ticketURL(key string) string {
	if key == "" || s.jiraBaseURL == "" {
		return ""
	}
	return strings.TrimSuffix(s.jiraBaseURL, "/") + "/browse/" + key
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
