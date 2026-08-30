package upgrade

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// PullRequest is an open pull request as reported by a provider.
type PullRequest struct {
	// Repository is the repository the pull request targets, bare name (no
	// project or organisation prefix).
	Repository string
	Title      string
	Branch     string
	URL        string
	Author     string
	Created    time.Time
}

// PullRequestSource lists the open pull requests to consider. Implemented per
// host: Azure DevOps today, GitHub to follow.
type PullRequestSource interface {
	// Name identifies the provider, for logs.
	Name() string
	// Open returns every open pull request the source can see. Filtering by
	// author and branch is the matcher's job, so the config that decides what
	// counts lives in one place.
	Open(ctx context.Context) ([]PullRequest, error)
}

// InFlightEnricher annotates images whose upgrade already has an open pull
// request.
//
// It answers a narrow question deliberately: does a pull request exist, in the
// repository that builds this image, bumping this dependency to this version.
// All three parts are required. A pull request in another repository that bumps
// the same base image does not remediate this image — the image still has to be
// rebuilt — and treating it as remediation would silence the finding that asks
// for exactly that rebuild.
type InFlightEnricher struct {
	Cfg    config.RemediationConfig
	Source PullRequestSource
	// Inspector reads image labels, to find which repository builds an image.
	Inspector ImageInspector
	// Concurrency bounds registry calls in flight. Zero means the default.
	Concurrency int
}

func (e *InFlightEnricher) concurrency() int {
	if e.Concurrency > 0 {
		return e.Concurrency
	}
	return defaultConcurrency
}

// EnrichImages implements the image enrichment stage. It never fails the run:
// a provider that cannot be reached leaves images unannotated, which reads as
// "not known to be in flight" rather than as "no pull request exists".
func (e *InFlightEnricher) EnrichImages(ctx context.Context, images []model.AssessedImage) error {
	prs, err := e.Source.Open(ctx)
	if err != nil {
		return fmt.Errorf("list open pull requests (%s): %w", e.Source.Name(), err)
	}
	prs = e.eligible(prs)
	byRepo := map[string][]PullRequest{}
	for _, pr := range prs {
		key := strings.ToLower(pr.Repository)
		byRepo[key] = append(byRepo[key], pr)
	}

	// Label reads are registry round trips, one per image. Serially that is half an
	// hour on an estate of this size, which makes the whole stage unusable; bounded
	// concurrency keeps it to minutes without hammering the registry.
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.concurrency())
	repos := make(map[string]string, len(images))

	matched, unmatchedRepo := 0, 0
	for i := range images {
		img := &images[i]
		img.InFlightChecked = true
		if img.Upgrade == nil || !img.Upgrade.Available {
			continue // nothing to be in flight for
		}
		wg.Add(1)
		go func(ref string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			repo, err := e.buildRepo(ctx, ref)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || repo == "" {
				return
			}
			repos[ref] = repo
		}(img.Image.Ref)
	}
	wg.Wait()

	for i := range images {
		img := &images[i]
		if img.Upgrade == nil || !img.Upgrade.Available {
			continue
		}
		repo, ok := repos[img.Image.Ref]
		if !ok {
			unmatchedRepo++
			// Say why, but only where the missing label is something anybody here can
			// fix. Someone else's image records no repository of ours because we do not
			// build it, which is not a gap in our pipeline and must not be reported as
			// one: the first run of this counted 21 such images and invited the team to
			// go and label Kiali's.
			if e.Cfg.IsFirstParty(img.Image.Registry) {
				img.InFlightReason = e.unmatchableReason()
			}
			continue
		}
		fl, matchedOne := match(byRepo[strings.ToLower(repo)], *img.Upgrade, e.Cfg.InFlight)
		if !matchedOne {
			continue
		}
		img.InFlight = &fl
		matched++
	}
	slog.InfoContext(ctx, "in-flight remediation checked",
		"provider", e.Source.Name(), "open_pull_requests", len(prs),
		"matched", matched, "no_build_repo", unmatchedRepo)
	return nil
}

// unmatchableReason names why an image could not be tied to a repository, so the
// report can distinguish it from an image with no pull request.
func (e *InFlightEnricher) unmatchableReason() string {
	if len(e.Cfg.Base.RepoLabels) == 0 {
		return "no remediation.base.repoLabels configured, so no image can be matched to a repository"
	}
	return "image records no build repository label, so no pull request can be tied to it"
}

// eligible filters to the pull requests the config says may count.
func (e *InFlightEnricher) eligible(prs []PullRequest) []PullRequest {
	cfg := e.Cfg.InFlight
	out := make([]PullRequest, 0, len(prs))
	for _, pr := range prs {
		if len(cfg.Authors) > 0 && !containsFold(cfg.Authors, pr.Author) {
			continue
		}
		if len(cfg.BranchPrefixes) > 0 && !hasPrefixFold(cfg.BranchPrefixes, strings.TrimPrefix(pr.Branch, "refs/heads/")) {
			continue
		}
		out = append(out, pr)
	}
	return out
}

// buildRepo reads the repository that built an image from its labels. Empty
// (with no error) means the image records no such label, so it cannot be matched.
func (e *InFlightEnricher) buildRepo(ctx context.Context, ref string) (string, error) {
	keys := e.Cfg.Base.RepoLabels
	if len(keys) == 0 {
		return "", nil
	}
	cfg, err := e.Inspector.Config(ctx, ref)
	labels := cfg.Labels
	if err != nil {
		return "", err
	}
	for _, k := range keys {
		if v := strings.TrimSpace(labels[k]); v != "" {
			return lastPathSegment(v), nil
		}
	}
	return "", nil
}

// lastPathSegment reduces a repository identifier to its bare name, so a label
// holding a clone URL ("https://host/org/proj/_git/api") and one holding a bare
// name ("api") compare equal.
func lastPathSegment(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".git")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// titlePatterns extract the dependency and target version from a pull request
// title. Matching the structured title rather than searching it for substrings
// is deliberate: "dotnet/aspnet" is a substring of "dotnet/aspnet/10", so a
// contains-check reports the wrong dependency with full confidence.
var titlePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)update\s+(?:dependency\s+)?(\S+)\s+docker\s+tag\s+to\s+(\S+)`),
	regexp.MustCompile(`(?i)update\s+helm\s+release\s+(\S+)\s+to\s+(\S+)`),
	regexp.MustCompile(`(?i)update\s+(?:dependency\s+)?(\S+)\s+(?:docker\s+)?digest\s+to\s+(\S+)`),
	regexp.MustCompile(`(?i)update\s+(?:dependency\s+)?(\S+)\s+to\s+(\S+)`),
}

// parseTitle returns the dependency and target version a title claims to bump.
func parseTitle(title string) (dep, version string, ok bool) {
	for _, re := range titlePatterns {
		if m := re.FindStringSubmatch(title); m != nil {
			return strings.Trim(m[1], "`'\""), strings.Trim(m[2], "`'\""), true
		}
	}
	return "", "", false
}

// match returns the pull request in this repository that bumps this upgrade's
// dependency, preferring an exact version match. A dependency match with a
// different target version is returned with Exact false: something is being
// worked on, but it is not necessarily this.
func match(prs []PullRequest, up model.Upgrade, cfg config.InFlightConfig) (model.InFlight, bool) {
	var partial *PullRequest
	for i := range prs {
		pr := prs[i]
		dep, version, ok := parseTitle(pr.Title)
		if !ok || !sameDependency(dep, up.Name) {
			continue
		}
		if sameVersion(version, up.Latest) {
			return inFlight(pr, true, cfg), true
		}
		if partial == nil {
			p := pr
			partial = &p
		}
	}
	if partial != nil {
		return inFlight(*partial, false, cfg), true
	}
	return model.InFlight{}, false
}

// inFlight converts a matched pull request into the model type carried on a
// finding.
func inFlight(pr PullRequest, exact bool, cfg config.InFlightConfig) model.InFlight {
	fl := model.InFlight{
		Repository: pr.Repository, Title: pr.Title, URL: pr.URL,
		Author: pr.Author, Opened: pr.Created, Exact: exact,
	}
	if !pr.Created.IsZero() {
		fl.Stale = cfg.Stale(time.Since(pr.Created))
	}
	return fl
}

// sameDependency compares two image references for equality, tolerating only a
// missing registry on the pull request side (a Dockerfile may name a Docker Hub
// image with no host). Every path segment must match: a shared prefix is not a
// match.
func sameDependency(prDep, upgradeName string) bool {
	prDep, upgradeName = normaliseRef(prDep), normaliseRef(upgradeName)
	if prDep == "" || upgradeName == "" {
		return false
	}
	if prDep == upgradeName {
		return true
	}
	// The upgrade name is registry-qualified; the title may not be. Compare the
	// path only when the remainder is a full segment boundary.
	if i := strings.Index(upgradeName, "/"); i > 0 && strings.Contains(upgradeName[:i], ".") {
		return prDep == upgradeName[i+1:]
	}
	return false
}

// normaliseRef strips a tag/digest and lowercases, leaving registry and path.
func normaliseRef(ref string) string {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	// A colon after the last slash is a tag; one before it is a registry port.
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return strings.Trim(ref, "/")
}

// sameVersion compares target versions, tolerating a "v" prefix on either side
// and a digest given in short form.
func sameVersion(prVersion, latest string) bool {
	a := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(prVersion), "v"))
	b := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(latest), "v"))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	a, b = strings.TrimPrefix(a, "sha256:"), strings.TrimPrefix(b, "sha256:")
	if len(a) >= 12 && len(b) >= 12 && (strings.HasPrefix(a, b) || strings.HasPrefix(b, a)) {
		return true
	}
	return false
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

func hasPrefixFold(prefixes []string, v string) bool {
	v = strings.ToLower(v)
	for _, p := range prefixes {
		if strings.HasPrefix(v, strings.ToLower(strings.TrimSpace(p))) {
			return true
		}
	}
	return false
}
