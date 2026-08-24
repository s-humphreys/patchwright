package upgrade

import (
	"context"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

type stubPRs struct {
	prs []PullRequest
	err error
}

func (s stubPRs) Name() string { return "stub" }
func (s stubPRs) Open(context.Context) ([]PullRequest, error) {
	return s.prs, s.err
}

type stubInspector struct {
	labels map[string]map[string]string
}

func (s stubInspector) Labels(_ context.Context, ref string) (map[string]string, error) {
	return s.labels[ref], nil
}
func (s stubInspector) Digest(context.Context, string) (string, error) { return "", nil }

const repoLabel = "com.example.build.repository"

func enricher(prs []PullRequest, labels map[string]map[string]string, cfg config.InFlightConfig) *InFlightEnricher {
	return &InFlightEnricher{
		Cfg: config.RemediationConfig{
			// "reg" is first-party in these tests: a missing build label is only a gap
			// worth reporting where we own the build.
			FirstPartyRegistries: []string{"reg"},
			Base:                 config.BaseImageConfig{RepoLabels: []string{repoLabel}},
			InFlight:             cfg,
		},
		Source:    stubPRs{prs: prs},
		Inspector: stubInspector{labels: labels},
	}
}

func image(ref, name, latest string) model.AssessedImage {
	return model.AssessedImage{
		Image:   model.Image{Ref: ref, Registry: "reg"},
		Upgrade: &model.Upgrade{Kind: "base", Name: name, Latest: latest, Available: true},
	}
}

func TestMatchRequiresTheRepositoryThatBuildsTheImage(t *testing.T) {
	// The pull request bumps exactly the right base to exactly the right version,
	// but in the repository that builds the base rather than the application. The
	// application still has to be rebuilt, so this is not remediation for it.
	prs := []PullRequest{{
		Repository: "base-images",
		Title:      "chore(deps): Update example.io/dotnet/aspnet Docker tag to v10.0.11",
		Created:    time.Now().Add(-72 * time.Hour),
	}}
	labels := map[string]map[string]string{
		"reg/app:v1": {repoLabel: "app-service"},
	}
	images := []model.AssessedImage{image("reg/app:v1", "example.io/dotnet/aspnet", "10.0.11")}

	if err := enricher(prs, labels, config.InFlightConfig{}).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].InFlight != nil {
		t.Fatalf("matched a pull request in another repository: %+v", images[0].InFlight)
	}
}

func TestMatchIsExactOnDependencyAndVersion(t *testing.T) {
	labels := map[string]map[string]string{"reg/app:v1": {repoLabel: "app-service"}}
	cases := []struct {
		name       string
		title      string
		dep, want  string
		matched    bool
		exactMatch bool
	}{
		{
			name:       "exact dependency and version",
			title:      "chore(deps): Update example.io/dotnet/aspnet Docker tag to v10.0.11",
			dep:        "example.io/dotnet/aspnet",
			want:       "10.0.11",
			matched:    true,
			exactMatch: true,
		},
		{
			// "dotnet/aspnet" is a prefix of "dotnet/aspnet/10". A substring check
			// matches here and is wrong: these are different repositories.
			name:    "prefix of another dependency path is not a match",
			title:   "chore(deps): Update example.io/dotnet/aspnet/10 Docker tag to v1.1.1",
			dep:     "example.io/dotnet/aspnet",
			want:    "10.0.11",
			matched: false,
		},
		{
			name:       "right dependency, different version is not exact",
			title:      "chore(deps): Update example.io/dotnet/aspnet Docker tag to v10.0.9",
			dep:        "example.io/dotnet/aspnet",
			want:       "10.0.11",
			matched:    true,
			exactMatch: false,
		},
		{
			name:       "registry omitted in the title still matches the path",
			title:      "chore(deps): Update dotnet/aspnet Docker tag to 10.0.11",
			dep:        "example.io/dotnet/aspnet",
			want:       "10.0.11",
			matched:    true,
			exactMatch: true,
		},
		{
			name:    "unparseable title never matches",
			title:   "bump some things",
			dep:     "example.io/dotnet/aspnet",
			want:    "10.0.11",
			matched: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prs := []PullRequest{{Repository: "app-service", Title: tc.title, Created: time.Now()}}
			images := []model.AssessedImage{image("reg/app:v1", tc.dep, tc.want)}
			if err := enricher(prs, labels, config.InFlightConfig{}).EnrichImages(context.Background(), images); err != nil {
				t.Fatal(err)
			}
			got := images[0].InFlight
			if tc.matched != (got != nil) {
				t.Fatalf("matched = %v, want %v (%+v)", got != nil, tc.matched, got)
			}
			if got != nil && got.Exact != tc.exactMatch {
				t.Fatalf("exact = %v, want %v", got.Exact, tc.exactMatch)
			}
		})
	}
}

func TestAuthorAndBranchFiltersApply(t *testing.T) {
	labels := map[string]map[string]string{"reg/app:v1": {repoLabel: "app-service"}}
	pr := PullRequest{
		Repository: "app-service",
		Title:      "chore(deps): Update dotnet/aspnet Docker tag to v10.0.11",
		Branch:     "refs/heads/renovate/dotnet-aspnet",
		Author:     "bot.automations",
		Created:    time.Now(),
	}
	cfg := config.InFlightConfig{Authors: []string{"bot.automations"}, BranchPrefixes: []string{"renovate/"}}

	images := []model.AssessedImage{image("reg/app:v1", "example.io/dotnet/aspnet", "10.0.11")}
	if err := enricher([]PullRequest{pr}, labels, cfg).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].InFlight == nil {
		t.Fatal("configured author and branch prefix should match")
	}

	other := pr
	other.Author = "someone.else"
	images = []model.AssessedImage{image("reg/app:v1", "example.io/dotnet/aspnet", "10.0.11")}
	if err := enricher([]PullRequest{other}, labels, cfg).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].InFlight != nil {
		t.Fatal("an author outside the configured list must not match")
	}
}

func TestNoBuildRepoLabelMeansNoMatch(t *testing.T) {
	// An image that does not record which repository built it cannot be tied to a
	// pull request. It must come back unmatched rather than matched by name.
	prs := []PullRequest{{
		Repository: "app-service",
		Title:      "chore(deps): Update dotnet/aspnet Docker tag to v10.0.11",
		Created:    time.Now(),
	}}
	images := []model.AssessedImage{image("reg/app:v1", "example.io/dotnet/aspnet", "10.0.11")}
	if err := enricher(prs, map[string]map[string]string{}, config.InFlightConfig{}).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].InFlight != nil {
		t.Fatal("matched without knowing which repository builds the image")
	}
	// And it must say so, rather than looking like an image nobody has started work
	// on: this one can never be matched, and the fix is a label in its build.
	if images[0].InFlightReason == "" {
		t.Fatal("an unmatchable image must carry the reason it cannot be matched")
	}
}

func TestAMatchedImageCarriesNoUnmatchableReason(t *testing.T) {
	prs := []PullRequest{{
		Repository: "app-service",
		Title:      "chore(deps): Update dotnet/aspnet Docker tag to v10.0.11",
		Created:    time.Now(),
	}}
	labels := map[string]map[string]string{"reg/app:v1": {repoLabel: "app-service"}}
	images := []model.AssessedImage{image("reg/app:v1", "example.io/dotnet/aspnet", "10.0.11")}
	if err := enricher(prs, labels, config.InFlightConfig{}).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].InFlightReason != "" {
		t.Fatalf("a matched image must carry no unmatchable reason: %q", images[0].InFlightReason)
	}
}

func TestImagesWithoutAnAvailableUpgradeAreNotMatched(t *testing.T) {
	prs := []PullRequest{{
		Repository: "app-service",
		Title:      "chore(deps): Update dotnet/aspnet Docker tag to v10.0.11",
		Created:    time.Now(),
	}}
	labels := map[string]map[string]string{"reg/app:v1": {repoLabel: "app-service"}}
	img := image("reg/app:v1", "example.io/dotnet/aspnet", "10.0.11")
	img.Upgrade.Available = false
	images := []model.AssessedImage{img}
	if err := enricher(prs, labels, config.InFlightConfig{}).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].InFlight != nil {
		t.Fatal("an image with no upgrade available has nothing to be in flight")
	}
}

func TestBuildRepoLabelToleratesACloneURL(t *testing.T) {
	prs := []PullRequest{{
		Repository: "app-service",
		Title:      "chore(deps): Update dotnet/aspnet Docker tag to v10.0.11",
		Created:    time.Now(),
	}}
	labels := map[string]map[string]string{
		"reg/app:v1": {repoLabel: "https://example.visualstudio.com/Apps/_git/app-service"},
	}
	images := []model.AssessedImage{image("reg/app:v1", "example.io/dotnet/aspnet", "10.0.11")}
	if err := enricher(prs, labels, config.InFlightConfig{}).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].InFlight == nil {
		t.Fatal("a label holding a clone URL should resolve to the repository name")
	}
}

func TestDigestUpgradesMatchOnShortDigest(t *testing.T) {
	prs := []PullRequest{{
		Repository: "app-service",
		Title:      "chore(deps): Update dotnet/aspnet digest to c4b29bf36800aa",
		Created:    time.Now(),
	}}
	labels := map[string]map[string]string{"reg/app:v1": {repoLabel: "app-service"}}
	images := []model.AssessedImage{image("reg/app:v1", "example.io/dotnet/aspnet", "c4b29bf36800")}
	if err := enricher(prs, labels, config.InFlightConfig{}).EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	got := images[0].InFlight
	if got == nil || !got.Exact {
		t.Fatalf("short digest should match the same digest given longer: %+v", got)
	}
}

func TestStaleAfterDays(t *testing.T) {
	cfg := config.InFlightConfig{StaleAfterDays: 14}
	if cfg.Stale(13 * 24 * time.Hour) {
		t.Fatal("13 days is not stale at a 14 day threshold")
	}
	if !cfg.Stale(15 * 24 * time.Hour) {
		t.Fatal("15 days is stale at a 14 day threshold")
	}
	if (config.InFlightConfig{}).Stale(365 * 24 * time.Hour) {
		t.Fatal("no threshold configured means nothing is stale")
	}
}

func TestAThirdPartyImageIsNotReportedAsAPipelineGap(t *testing.T) {
	// Someone else's image records no repository of ours because we do not build it.
	// Reporting that as a missing label invites the team to go and label images they
	// have no control over.
	e := &InFlightEnricher{
		Cfg: config.RemediationConfig{
			FirstPartyRegistries: []string{"reg"},
			Base:                 config.BaseImageConfig{RepoLabels: []string{repoLabel}},
		},
		Source:    stubPRs{},
		Inspector: stubInspector{labels: map[string]map[string]string{}},
	}
	images := []model.AssessedImage{{
		Image:   model.Image{Ref: "quay.io/vendor/app:1", Registry: "quay.io"},
		Upgrade: &model.Upgrade{Kind: "image", Name: "quay.io/vendor/app", Latest: "2", Available: true},
	}}
	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if images[0].InFlightReason != "" {
		t.Fatalf("third-party image reported as a build pipeline gap: %q", images[0].InFlightReason)
	}
}
