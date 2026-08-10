package ticket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
)

// Jira is the minimal client this tool needs: find existing tickets for an
// image, and create one. Nothing else, because nothing else should be
// automated against a ticket system without a human in the loop.
type Jira struct {
	BaseURL string
	Email   string
	Token   string
	Client  *http.Client
	cfg     config.JiraConfig
}

// Credential environment variables. Kept out of config files: a config file is
// committed, and an API token must not be.
const (
	EnvBaseURL = "JIRA_BASE_URL"
	EnvEmail   = "JIRA_EMAIL"
	EnvToken   = "JIRA_API_TOKEN"
)

// NewJira builds a client from the environment. It returns a clear error naming
// what is missing rather than failing later with a 401.
func NewJira(cfg config.JiraConfig) (*Jira, error) {
	base, email, token := os.Getenv(EnvBaseURL), os.Getenv(EnvEmail), os.Getenv(EnvToken)
	var missing []string
	if base == "" {
		missing = append(missing, EnvBaseURL+" (e.g. https://your-site.atlassian.net)")
	}
	if email == "" {
		missing = append(missing, EnvEmail)
	}
	if token == "" {
		missing = append(missing, EnvToken)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing Jira credentials in the environment: %s", strings.Join(missing, ", "))
	}
	return &Jira{
		BaseURL: strings.TrimSuffix(base, "/"),
		Email:   email,
		Token:   token,
		Client:  &http.Client{Timeout: 30 * time.Second},
		cfg:     cfg,
	}, nil
}

// Existing is a ticket already covering an image.
type Existing struct {
	Key    string
	Status string
	// Done reports whether the ticket is in a completed status category. A
	// recurrence after a completed upgrade is genuinely new work, so only open
	// tickets suppress a new one.
	Done bool
}

// FindOpen returns open (not Done) tickets already covering the image. This is
// the idempotency check, and it queries Jira rather than any local state:
// a state file would drift the moment someone closed a ticket by hand.
func (j *Jira) FindOpen(ctx context.Context, image string) ([]Existing, error) {
	jql := fmt.Sprintf(`project = %q AND issuetype = %q AND %s AND statusCategory != Done`,
		j.cfg.Project, j.cfg.EffectiveIssueType(), j.imageClause(image))

	var resp struct {
		Issues []struct {
			Key    string `json:"key"`
			Fields struct {
				Status struct {
					Name           string `json:"name"`
					StatusCategory struct {
						Key string `json:"key"`
					} `json:"statusCategory"`
				} `json:"status"`
			} `json:"fields"`
		} `json:"issues"`
	}
	q := url.Values{}
	q.Set("jql", jql)
	q.Set("fields", "status")
	q.Set("maxResults", "50")
	if err := j.do(ctx, http.MethodGet, "/rest/api/3/search/jql?"+q.Encode(), nil, &resp); err != nil {
		return nil, fmt.Errorf("search for existing tickets (jql: %s): %w", jql, err)
	}

	out := make([]Existing, 0, len(resp.Issues))
	for _, i := range resp.Issues {
		out = append(out, Existing{
			Key:    i.Key,
			Status: i.Fields.Status.Name,
			Done:   i.Fields.Status.StatusCategory.Key == "done",
		})
	}
	return out, nil
}

// imageClause builds the JQL predicate matching a ticket to an image, from
// whichever mechanism is configured. Custom-field JQL (cf[NNNNN]) is not
// supported uniformly on team-managed projects, which is why the label form
// exists as a fallback.
func (j *Jira) imageClause(image string) string {
	if j.cfg.ImageLabel {
		return fmt.Sprintf("labels = %q", ImageLabel(image))
	}
	id := strings.TrimPrefix(j.cfg.ImageField, "customfield_")
	return fmt.Sprintf("cf[%s] ~ %q", id, image)
}

// ImageLabel converts an image repository into a Jira-safe label. Jira labels
// cannot contain spaces; slashes are replaced so the label stays one token and
// remains reversible enough to read.
func ImageLabel(image string) string {
	safe := strings.NewReplacer("/", "_", " ", "_", ":", "_").Replace(image)
	return "patchwright-" + safe
}

// Create raises a ticket and returns its key.
func (j *Jira) Create(ctx context.Context, d Draft) (string, error) {
	fields := map[string]any{
		"project":     map[string]string{"key": j.cfg.Project},
		"summary":     d.Summary,
		"issuetype":   map[string]string{"name": j.cfg.EffectiveIssueType()},
		"description": ADFDocument(d.Description),
	}
	if j.cfg.Epic != "" {
		fields["parent"] = map[string]string{"key": j.cfg.Epic}
	}
	if j.cfg.Priority != "" {
		fields["priority"] = map[string]string{"name": j.cfg.Priority}
	}

	labels := append([]string{}, j.cfg.Labels...)
	if j.cfg.ImageLabel {
		for _, img := range d.Images {
			labels = append(labels, ImageLabel(img))
		}
	} else {
		fields[j.cfg.ImageField] = d.Images
	}
	if len(labels) > 0 {
		fields["labels"] = labels
	}

	var resp struct {
		Key string `json:"key"`
	}
	if err := j.do(ctx, http.MethodPost, "/rest/api/3/issue", map[string]any{"fields": fields}, &resp); err != nil {
		return "", fmt.Errorf("create ticket %q: %w", d.Summary, err)
	}
	return resp.Key, nil
}

func (j *Jira) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, j.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.SetBasicAuth(j.Email, j.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := j.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // response body close, nothing to do on failure

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Include the body: Jira's field-level validation errors are the useful
		// part (an unknown custom field, a missing required field on a screen).
		return fmt.Errorf("jira %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode jira response: %w", err)
	}
	slog.DebugContext(ctx, "jira request ok", "method", method, "path", path, "status", resp.StatusCode)
	return nil
}
