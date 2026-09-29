package server

import (
	"context"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// failingAssessor reports enrichments and clusters it had to do without.
type failingAssessor struct {
	stubAssessor
	failures []model.SourceFailure
}

func (f failingAssessor) Failures() []model.SourceFailure { return f.failures }

// A cluster left out of the run reaches the page and the MCP tools by name, so
// "liveness there is unknown" is stated rather than inferred from quiet cells.
func TestAClusterLeftOutIsReportedWithTheAssessment(t *testing.T) {
	s := New(failingAssessor{
		stubAssessor: stubAssessor{findings: []model.Finding{finding("acr.io/a:1", "engineering", "a", true, false)}},
		failures:     []model.SourceFailure{{Stage: model.StageLive, Cluster: "remote", Error: "list cronjobs.batch: Unauthorized"}},
	})
	s.Refresh(context.Background())

	var body struct {
		Summary summaryView `json:"summary"`
	}
	getJSON(t, s.Handler(), "/api/v1/summary", &body)
	if got := body.Summary.SourceFailures; len(got) != 1 || got[0].Cluster != "remote" || got[0].Stage != model.StageLive {
		t.Errorf("summary source_failures = %+v", got)
	}
	if got := s.assessment().Failures; len(got) != 1 || got[0].Cluster != "remote" {
		t.Errorf("mcp assessment failures = %+v", got)
	}
}
