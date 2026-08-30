package upgrade

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

type ageInspector struct {
	cfg map[string]ImageConfig
	err error
	// asked records what was read, so "we did not touch third-party images" is a
	// measurement rather than a hope. Guarded: images are read concurrently, and an
	// unsynchronised slice here is a race the detector only sometimes catches.
	mu    sync.Mutex
	asked []string
}

func (a *ageInspector) Config(_ context.Context, ref string) (ImageConfig, error) {
	a.mu.Lock()
	a.asked = append(a.asked, ref)
	a.mu.Unlock()
	if a.err != nil {
		return ImageConfig{}, a.err
	}
	return a.cfg[ref], nil
}

func (a *ageInspector) Digest(context.Context, string) (string, error) { return "", nil }

func ageCfg() config.RemediationConfig {
	return config.RemediationConfig{FirstPartyRegistries: []string{"acr.example.com"}}
}

func TestImageAgeRecordsWhenAFirstPartyImageWasBuilt(t *testing.T) {
	built := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	insp := &ageInspector{cfg: map[string]ImageConfig{
		"acr.example.com/api:1": {Built: built},
	}}
	images := []model.AssessedImage{{Image: model.ParseImageRef("acr.example.com/api:1")}}

	e := &ImageAgeEnricher{Cfg: ageCfg(), Inspector: insp}
	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if !images[0].ImageBuilt.Equal(built) {
		t.Errorf("ImageBuilt = %v, want %v", images[0].ImageBuilt, built)
	}
}

func TestThirdPartyImagesAreNotRead(t *testing.T) {
	// A vendor's build date is the vendor's business, and reading it would mean a
	// config blob per third-party image for a fact nobody here can act on.
	insp := &ageInspector{cfg: map[string]ImageConfig{}}
	images := []model.AssessedImage{
		{Image: model.ParseImageRef("docker.io/library/nginx:1")},
		{Image: model.ParseImageRef("acr.example.com/api:1")},
	}
	e := &ImageAgeEnricher{Cfg: ageCfg(), Inspector: insp}
	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if len(insp.asked) != 1 || insp.asked[0] != "acr.example.com/api:1" {
		t.Errorf("read %v, want only the first-party image", insp.asked)
	}
}

func TestAnImageWithNoBuildDateStaysZeroRatherThanEpoch(t *testing.T) {
	// Some builders omit it and some deliberately zero it for reproducibility.
	// Recording that as a date would put every one of them at the top of an
	// "oldest first" ordering.
	insp := &ageInspector{cfg: map[string]ImageConfig{"acr.example.com/api:1": {}}}
	images := []model.AssessedImage{{Image: model.ParseImageRef("acr.example.com/api:1")}}
	e := &ImageAgeEnricher{Cfg: ageCfg(), Inspector: insp}
	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if !images[0].ImageBuilt.IsZero() {
		t.Errorf("ImageBuilt = %v, want zero", images[0].ImageBuilt)
	}
}

func TestAnUnreadableImageLosesOnlyItsDate(t *testing.T) {
	// The build date explains a finding rather than deciding it, so losing it must
	// not cost the assessment.
	insp := &ageInspector{err: errors.New("unauthorized")}
	images := []model.AssessedImage{{Image: model.ParseImageRef("acr.example.com/api:1")}}
	e := &ImageAgeEnricher{Cfg: ageCfg(), Inspector: insp}
	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Errorf("an unreadable image must not fail the run: %v", err)
	}
	if !images[0].ImageBuilt.IsZero() {
		t.Error("a failed read must not invent a date")
	}
}
