package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// assessmentMeta tells clients how fresh the data is.
type assessmentMeta struct {
	GeneratedAt *time.Time `json:"generated_at"`
	Running     bool       `json:"running"`
	Error       string     `json:"error,omitempty"`
}

// Handler returns the HTTP handler for the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /api/v1/findings", s.handleFindings)
	mux.HandleFunc("GET /api/v1/finding", s.handleFinding)
	mux.HandleFunc("GET /api/v1/owners", s.handleOwners)
	mux.HandleFunc("GET /api/v1/summary", s.handleSummary)
	mux.HandleFunc("POST /api/v1/assessments", s.handleRefresh)
	return mux
}

func (s *Server) meta() assessmentMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := assessmentMeta{Running: s.running}
	if s.latest != nil {
		t := s.latest.generatedAt
		m.GeneratedAt = &t
		m.Error = s.latest.err
	}
	return m
}

func (s *Server) snapshot() *snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latest
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz reports ready once a first successful assessment is cached.
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	if snap == nil || snap.views == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "no assessment yet"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	snap := s.snapshot()
	views := []sink.FindingView{}
	if snap != nil {
		views = filterViews(snap.views, r)
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta     `json:"assessment"`
		Count      int                `json:"count"`
		Findings   []sink.FindingView `json:"findings"`
	}{s.meta(), len(views), views})
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	image := r.URL.Query().Get("image")
	if image == "" {
		writeError(w, http.StatusBadRequest, "query parameter 'image' is required")
		return
	}
	snap := s.snapshot()
	if snap == nil {
		writeError(w, http.StatusNotFound, "no assessment available")
		return
	}
	v, ok := snap.byImage[image]
	if !ok {
		writeError(w, http.StatusNotFound, "no finding for image "+image)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta   `json:"assessment"`
		Finding    sink.FindingView `json:"finding"`
	}{s.meta(), v})
}

func (s *Server) handleOwners(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	owners := []ownerStats{}
	if snap != nil {
		owners = snap.owners
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Owners     []ownerStats   `json:"owners"`
	}{s.meta(), owners})
}

func (s *Server) handleSummary(w http.ResponseWriter, _ *http.Request) {
	snap := s.snapshot()
	var sum summaryView
	if snap != nil {
		sum = snap.summary
	}
	writeJSON(w, http.StatusOK, struct {
		Assessment assessmentMeta `json:"assessment"`
		Summary    summaryView    `json:"summary"`
	}{s.meta(), sum})
}

// handleRefresh triggers an assessment in the background and returns 202.
func (s *Server) handleRefresh(w http.ResponseWriter, _ *http.Request) {
	go s.Refresh(context.Background())
	writeJSON(w, http.StatusAccepted, struct {
		Assessment assessmentMeta `json:"assessment"`
		Message    string         `json:"message"`
	}{s.meta(), "assessment triggered"})
}

// filterViews applies the query-parameter filters. By default suppressed
// findings are excluded unless ?suppressed=true.
func filterViews(views []sink.FindingView, r *http.Request) []sink.FindingView {
	q := r.URL.Query()
	ownerClass := q.Get("owner_class")
	team := q.Get("team")
	priority := q.Get("priority")
	actionable, hasActionable := boolParam(q.Get("actionable"))
	live, hasLive := boolParam(q.Get("live"))
	upgradable, hasUpgradable := boolParam(q.Get("upgradable"))
	knownExploited, hasKEV := boolParam(q.Get("known_exploited"))
	suppressed, hasSuppressed := boolParam(q.Get("suppressed"))

	out := make([]sink.FindingView, 0, len(views))
	for _, v := range views {
		if !hasSuppressed && v.Suppressed {
			continue // default: hide suppressed
		}
		if hasSuppressed && v.Suppressed != suppressed {
			continue
		}
		if ownerClass != "" && v.Owner.Class != ownerClass {
			continue
		}
		if team != "" && v.Owner.Team != team {
			continue
		}
		if priority != "" && v.Priority != priority {
			continue
		}
		if hasActionable && v.Actionable != actionable {
			continue
		}
		if hasKEV && v.KnownExploited != knownExploited {
			continue
		}
		if hasLive {
			isLive := v.Liveness != nil && v.Liveness.Live
			if isLive != live {
				continue
			}
		}
		if hasUpgradable {
			up := v.Upgrade != nil && v.Upgrade.Available && v.Upgrade.Actionable
			if up != upgradable {
				continue
			}
		}
		out = append(out, v)
	}
	return out
}

func boolParam(s string) (bool, bool) {
	if s == "" {
		return false, false
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false, false
	}
	return b, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
