package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
)

// AzureDevOpsPATEnv is the environment variable holding the personal access
// token used to list pull requests. Read from the environment rather than
// config so a config file can be committed and a chart can ship without a
// credential in a values file.
const AzureDevOpsPATEnv = "AZURE_DEVOPS_PAT"

// AzureDevOps lists open pull requests across the configured projects.
//
// Code read scope is enough: this source only reads.
type AzureDevOps struct {
	Organisation string
	Projects     []string
	Token        string
	// BaseURL defaults to the public service. Overridable for a self-hosted
	// server and for tests.
	BaseURL string
	Client  *http.Client
}

// NewAzureDevOps builds a source from config, taking the token from the
// environment. It fails rather than degrading when the token is missing: an
// unauthenticated run would report zero pull requests, which is indistinguishable
// from "no remediation in flight" and would be wrong about every image.
func NewAzureDevOps(cfg config.InFlightConfig) (*AzureDevOps, error) {
	token := strings.TrimSpace(os.Getenv(AzureDevOpsPATEnv))
	if token == "" {
		return nil, fmt.Errorf("%s is not set: in-flight detection needs a token with code read access", AzureDevOpsPATEnv)
	}
	return &AzureDevOps{
		Organisation: cfg.Organisation,
		Projects:     cfg.Projects,
		Token:        token,
		BaseURL:      "https://dev.azure.com",
		Client:       &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Name implements PullRequestSource.
func (a *AzureDevOps) Name() string { return "azuredevops" }

// Open implements PullRequestSource, listing active pull requests one project at
// a time. A project that cannot be read fails the call: a partial listing would
// silently mean "no pull request" for every image built in that project.
func (a *AzureDevOps) Open(ctx context.Context) ([]PullRequest, error) {
	var all []PullRequest
	for _, project := range a.Projects {
		prs, err := a.project(ctx, project)
		if err != nil {
			return nil, fmt.Errorf("project %s: %w", project, err)
		}
		all = append(all, prs...)
	}
	return all, nil
}

// adoPullRequests is the subset of the API response this source uses.
type adoPullRequests struct {
	Value []struct {
		PullRequestID int    `json:"pullRequestId"`
		Title         string `json:"title"`
		SourceRefName string `json:"sourceRefName"`
		CreationDate  string `json:"creationDate"`
		CreatedBy     struct {
			UniqueName  string `json:"uniqueName"`
			DisplayName string `json:"displayName"`
		} `json:"createdBy"`
		Repository struct {
			Name string `json:"name"`
		} `json:"repository"`
	} `json:"value"`
}

func (a *AzureDevOps) project(ctx context.Context, project string) ([]PullRequest, error) {
	endpoint := fmt.Sprintf("%s/%s/%s/_apis/git/pullrequests",
		strings.TrimRight(a.BaseURL, "/"), url.PathEscape(a.Organisation), url.PathEscape(project))
	q := url.Values{}
	q.Set("searchCriteria.status", "active")
	q.Set("$top", "1000")
	q.Set("api-version", "7.1")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth("", a.Token) // Azure DevOps takes the PAT as the basic-auth password
	req.Header.Set("Accept", "application/json")

	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A PAT that has expired or lacks scope answers 203 with an HTML sign-in
		// page rather than 401, so anything other than 200 is treated as a failure
		// with its status named.
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	var body adoPullRequests
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	out := make([]PullRequest, 0, len(body.Value))
	for _, v := range body.Value {
		author := v.CreatedBy.UniqueName
		if author == "" {
			author = v.CreatedBy.DisplayName
		}
		created, _ := time.Parse(time.RFC3339, v.CreationDate)
		out = append(out, PullRequest{
			Repository: v.Repository.Name,
			Title:      v.Title,
			Branch:     strings.TrimPrefix(v.SourceRefName, "refs/heads/"),
			Author:     author,
			Created:    created,
			URL: fmt.Sprintf("%s/%s/%s/_git/%s/pullrequest/%d",
				strings.TrimRight(a.BaseURL, "/"), a.Organisation, project, v.Repository.Name, v.PullRequestID),
		})
	}
	return out, nil
}
