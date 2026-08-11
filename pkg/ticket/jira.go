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
	Key     string
	Status  string
	Summary string
	// Done reports whether the ticket is in a completed status category. A
	// recurrence after a completed upgrade is genuinely new work, so only open
	// tickets suppress a new one.
	Done bool
}

// FindOpen returns open (not Done) tickets already covering any of the images.
// This is the idempotency check, and it queries Jira rather than any local state:
// a state file would drift the moment someone closed a ticket by hand.
//
// All of a ticket's images go in one query. An open ticket on any single image
// suppresses the whole group, so asking per image would be extra round trips for
// the same answer.
func (j *Jira) FindOpen(ctx context.Context, images []string) ([]Existing, error) {
	if len(images) == 0 {
		return nil, nil
	}
	jql := fmt.Sprintf(`project = %q AND issuetype = %q AND %s AND statusCategory != Done`,
		j.cfg.Project, j.cfg.EffectiveIssueType(), j.imageClause(images))

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

// OpenByImage returns every open ticket in the project, indexed by each image it
// covers.
//
// One query for the whole project, rather than one per image: a ticket carries its
// images in the configured field, so reading them back builds the whole index in a
// single round trip. That is what makes showing "is someone already on this?" next
// to every finding cheap enough to do on each assessment.
func (j *Jira) OpenByImage(ctx context.Context) (map[string][]Existing, error) {
	jql := fmt.Sprintf(`project = %q AND issuetype = %q AND statusCategory != Done`,
		j.cfg.Project, j.cfg.EffectiveIssueType())

	out := map[string][]Existing{}
	token := ""
	for {
		var resp struct {
			Issues []struct {
				Key    string `json:"key"`
				Fields struct {
					Summary string `json:"summary"`
					Status  struct {
						Name           string `json:"name"`
						StatusCategory struct {
							Key string `json:"key"`
						} `json:"statusCategory"`
					} `json:"status"`
				} `json:"fields"`
				// The image field is configurable, so it cannot be a named struct
				// field; decode the raw fields separately below.
				RawFields map[string]json.RawMessage `json:"-"`
			} `json:"issues"`
			NextPageToken string `json:"nextPageToken"`
			IsLast        bool   `json:"isLast"`
		}
		// Decode twice: once into the typed shape, once loosely for the
		// configurable image field.
		var loose struct {
			Issues []struct {
				Key    string                     `json:"key"`
				Fields map[string]json.RawMessage `json:"fields"`
			} `json:"issues"`
		}

		q := url.Values{}
		q.Set("jql", jql)
		q.Set("fields", "status,summary,"+j.imageFieldName())
		q.Set("maxResults", "100")
		if token != "" {
			q.Set("nextPageToken", token)
		}
		body, err := j.raw(ctx, http.MethodGet, "/rest/api/3/search/jql?"+q.Encode())
		if err != nil {
			return nil, fmt.Errorf("list open tickets (jql: %s): %w", jql, err)
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode open tickets: %w", err)
		}
		if err := json.Unmarshal(body, &loose); err != nil {
			return nil, fmt.Errorf("decode open ticket fields: %w", err)
		}

		for i, issue := range resp.Issues {
			e := Existing{
				Key:     issue.Key,
				Status:  issue.Fields.Status.Name,
				Summary: issue.Fields.Summary,
				Done:    issue.Fields.Status.StatusCategory.Key == "done",
			}
			for _, img := range j.imagesOf(loose.Issues[i].Fields) {
				out[img] = append(out[img], e)
			}
		}

		if resp.IsLast || resp.NextPageToken == "" {
			return out, nil
		}
		token = resp.NextPageToken
	}
}

// imageFieldName is the field to request and read images from.
func (j *Jira) imageFieldName() string {
	if j.cfg.ImageLabel {
		return "labels"
	}
	return j.cfg.ImageField
}

// imagesOf extracts the image repositories a ticket covers. Labels are converted
// back from their sanitised form so they match a finding's repository again.
func (j *Jira) imagesOf(fields map[string]json.RawMessage) []string {
	raw, ok := fields[j.imageFieldName()]
	if !ok {
		return nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil
	}
	if !j.cfg.ImageLabel {
		return values
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if repo, ok := repoFromLabel(v); ok {
			out = append(out, repo)
		}
	}
	return out
}

// imageClause builds the JQL predicate matching a ticket to any of its images.
//
// Uses IN, i.e. exact equality, NOT the "~" contains operator: a multi-value
// custom field (and a label) is matched by equality, and "~" silently returns
// nothing against one. Silently, which is the dangerous part — a duplicate check
// that always finds nothing reports "would create" for a ticket that already
// exists, and a batch run then raises the lot again.
func (j *Jira) imageClause(images []string) string {
	values := make([]string, 0, len(images))
	for _, img := range images {
		v := img
		if j.cfg.ImageLabel {
			v = ImageLabel(v)
		}
		values = append(values, quoteJQL(v))
	}
	list := strings.Join(values, ", ")
	if j.cfg.ImageLabel {
		return "labels IN (" + list + ")"
	}
	id := strings.TrimPrefix(j.cfg.ImageField, "customfield_")
	return "cf[" + id + "] IN (" + list + ")"
}

// quoteJQL renders a JQL string literal, escaping backslashes and quotes so an
// unusual image name cannot break the query or alter its meaning.
func quoteJQL(s string) string {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
	return `"` + esc + `"`
}

// repoFromLabel reverses ImageLabel. It is lossy in principle (a repository
// containing "_" is indistinguishable from one containing "/"), so it is only used
// to display a ticket against a finding, never to decide whether to create one.
func repoFromLabel(label string) (string, bool) {
	const prefix = "patchwright-"
	if !strings.HasPrefix(label, prefix) {
		return "", false
	}
	return strings.ReplaceAll(strings.TrimPrefix(label, prefix), "_", "/"), true
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

// raw performs a request and returns the response body, for callers that must
// decode it more than once (the image field's name is configuration, so it cannot
// be a named struct field).
func (j *Jira) raw(ctx context.Context, method, path string) ([]byte, error) {
	var out json.RawMessage
	if err := j.do(ctx, method, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
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
