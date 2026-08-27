package policy

import (
	"testing"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

func newTestEvaluator(t *testing.T) *Evaluator {
	t.Helper()
	e, err := New(
		[]config.PolicyRule{
			{Name: "prod-critical", When: "counts['critical'] > 0 && dimensions['account'].exists(a, a.startsWith('Production'))", Priority: "high"},
			{Name: "any-critical", When: "counts['critical'] > 0", Priority: "low"},
		},
		[]config.PolicyRule{
			{Name: "cloud-managed", When: "owner['class'] == 'cloud-provider'"},
		},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func finding(class string, crit int, accounts ...string) model.Finding {
	return model.Finding{
		Image:      model.Image{Ref: "acr.io/x:1"},
		Counts:     model.Counts{model.SeverityCritical: crit},
		Owner:      model.Owner{Class: class},
		Dimensions: map[string][]string{"account": accounts},
	}
}

func TestSuppressionWinsOverActionable(t *testing.T) {
	e := newTestEvaluator(t)
	f := finding("cloud-provider", 5, "Production EU")
	if err := e.Evaluate(&f); err != nil {
		t.Fatal(err)
	}
	if !f.Suppressed || f.Actionable {
		t.Errorf("cloud-provider finding should be suppressed and not actionable, got suppressed=%v actionable=%v", f.Suppressed, f.Actionable)
	}
}

func TestProductionCriticalIsHigh(t *testing.T) {
	e := newTestEvaluator(t)
	f := finding("engineering", 3, "Development NA", "Production EU")
	if err := e.Evaluate(&f); err != nil {
		t.Fatal(err)
	}
	if !f.Actionable || f.Priority != "high" {
		t.Errorf("got actionable=%v priority=%q, want actionable=true priority=high", f.Actionable, f.Priority)
	}
}

func TestNonProductionCriticalFallsThroughToLow(t *testing.T) {
	e := newTestEvaluator(t)
	f := finding("engineering", 3, "Development NA")
	if err := e.Evaluate(&f); err != nil {
		t.Fatal(err)
	}
	if !f.Actionable || f.Priority != "low" {
		t.Errorf("got actionable=%v priority=%q, want actionable=true priority=low", f.Actionable, f.Priority)
	}
}

func TestNoCriticalIsNotActionable(t *testing.T) {
	e := newTestEvaluator(t)
	f := finding("engineering", 0, "Production EU")
	if err := e.Evaluate(&f); err != nil {
		t.Fatal(err)
	}
	if f.Actionable {
		t.Error("finding with no criticals should not be actionable")
	}
	if len(f.Reasons) == 0 {
		t.Error("expected an explanatory reason")
	}
}
