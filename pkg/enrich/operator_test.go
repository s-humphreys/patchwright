package enrich_test

import (
	"context"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

func operatorChosenNATS() model.Upgrade {
	return model.Upgrade{
		Kind: "image", Name: "docker.io/nats", Current: "2.10.29", Resolved: true,
		Managed: "operator", Manager: "argo-events", OperatorChosen: true,
		OperatorImage: "quay.io/argoproj/argo-events:v1.9.11",
	}
}

func enrichOne(t *testing.T, ups map[string]model.Upgrade) *model.Upgrade {
	t.Helper()
	images := []model.AssessedImage{{Image: model.ParseImageRef("nats:2.10.29")}}
	if err := enrich.NewRemediationEnricher(fakeUpgradeSource{ups: ups}).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	return images[0].Upgrade
}

// A newer operator image that is not a chart is named, not proposed: its tags
// would be presented as the NATS image's own, which is the mistake being fixed.
func TestOperatorImageUpgradeIsNamedNotProposed(t *testing.T) {
	u := enrichOne(t, map[string]model.Upgrade{
		"docker.io/nats:2.10.29": operatorChosenNATS(),
		"quay.io/argoproj/argo-events:v1.9.11": {Kind: "image", Name: "quay.io/argoproj/argo-events",
			Current: "v1.9.11", Latest: "v1.9.12", Available: true, Actionable: true, Resolved: true},
	})
	if u.Available || u.Latest != "" {
		t.Errorf("proposed %+v", u)
	}
	want := "version chosen by the operator argo-events; upgrading it (quay.io/argoproj/argo-events v1.9.11 -> v1.9.12) is the only change that moves this image"
	if u.Reason != want {
		t.Errorf("reason = %q, want %q", u.Reason, want)
	}
}

func TestOperatorWithNoAnswerIsUnresolved(t *testing.T) {
	u := enrichOne(t, map[string]model.Upgrade{"docker.io/nats:2.10.29": operatorChosenNATS()})
	if u.Available {
		t.Errorf("proposed %+v", u)
	}
	if want := "version chosen by the operator argo-events; the operator's own upgrade could not be resolved"; u.Reason != want {
		t.Errorf("reason = %q, want %q", u.Reason, want)
	}
}
