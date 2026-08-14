package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

func suppressRule(name, until string) config.PolicyRule {
	return config.PolicyRule{Name: name, When: "true", Until: until}
}

// A suppression with a date stops applying after it, which is the whole feature:
// accepted risk should expire rather than outlive the reason for it.
func TestExpiredSuppressionStopsApplying(t *testing.T) {
	yesterday := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	e, err := New(nil, []config.PolicyRule{suppressRule("lapsed", yesterday)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f := model.Finding{Image: model.Image{Ref: "acr.io/app:1"}}
	if err := e.Evaluate(&f); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if f.Suppressed {
		t.Error("a lapsed suppression still suppressed the finding")
	}
}

// A rule expiring today still applies today, in every timezone: the date is the last
// day it holds, not the first day it does not.
func TestSuppressionAppliesOnItsFinalDay(t *testing.T) {
	for _, until := range []string{
		time.Now().UTC().Format("2006-01-02"),
		time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02"),
	} {
		e, err := New(nil, []config.PolicyRule{suppressRule("current", until)})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		f := model.Finding{Image: model.Image{Ref: "acr.io/app:1"}}
		if err := e.Evaluate(&f); err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if !f.Suppressed {
			t.Errorf("until %q: the rule stopped applying early", until)
		}
	}
}

// No date means no expiry, so existing configuration is unchanged.
func TestSuppressionWithoutADateNeverExpires(t *testing.T) {
	e, err := New(nil, []config.PolicyRule{suppressRule("forever", "")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f := model.Finding{Image: model.Image{Ref: "acr.io/app:1"}}
	if err := e.Evaluate(&f); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !f.Suppressed {
		t.Error("a rule with no expiry stopped applying")
	}
	if got := e.Expired(time.Now()); len(got) != 0 {
		t.Errorf("a rule with no expiry was reported as lapsed: %+v", got)
	}
}

// Lapsed rules are reportable: work returning to the queue unexplained reads as the
// estate getting worse.
func TestExpiredReportsLapsedRules(t *testing.T) {
	old := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	future := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	e, err := New(nil, []config.PolicyRule{
		suppressRule("lapsed", old),
		suppressRule("current", future),
		suppressRule("permanent", ""),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := e.Expired(time.Now())
	if len(got) != 1 || got[0].Name != "lapsed" {
		t.Errorf("Expired() = %+v, want only the lapsed rule", got)
	}
}

// A mistyped date must fail at load. Accepting it and treating the rule as expired
// would silently un-suppress findings because of a typo; treating it as permanent
// would silently ignore the operator's intent.
func TestBadExpiryIsRejectedAtLoad(t *testing.T) {
	for _, until := range []string{"2026-13-01", "01/12/2026", "next tuesday", "2026-12-01T00:00:00Z"} {
		_, err := New(nil, []config.PolicyRule{suppressRule("bad", until)})
		if err == nil {
			t.Errorf("until %q was accepted", until)
			continue
		}
		if !strings.Contains(err.Error(), "YYYY-MM-DD") {
			t.Errorf("until %q: error does not say the expected form: %v", until, err)
		}
	}
}

// An expiry on an actionable rule is meaningless, so it is rejected rather than
// quietly ignored — the author clearly expected it to do something.
func TestExpiryOnAnActionableRuleIsRejected(t *testing.T) {
	_, err := New([]config.PolicyRule{
		{Name: "any-critical", When: "true", Priority: "low", Until: "2026-12-01"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "only applies to suppress") {
		t.Errorf("err = %v, want a rejection naming suppress rules", err)
	}
}
