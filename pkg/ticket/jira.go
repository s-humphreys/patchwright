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
	"sort"
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
	// byRoute is the resolved configuration per route name, so a write uses the
	// project, issue type, image field and priority scheme of the tracker the
	// planner chose. Always contains the default.
	byRoute map[string]config.JiraConfig
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
	byRoute := map[string]config.JiraConfig{routeName: cfg}
	for _, r := range cfg.Routes {
		byRoute[r.Name] = cfg.Resolve(r)
	}
	return &Jira{
		byRoute: byRoute,
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
	// Category is Jira's status category key ("new", "indeterminate", "done").
	// Status names are per-project and unpredictable ("NEEDS REFINEMENT"), so the
	// category is the only portable way to tell raised-but-untouched from
	// actively-being-worked.
	Category string
	// Done reports whether the ticket is in a completed status category. A
	// recurrence after a completed upgrade is genuinely new work, so only open
	// tickets suppress a new one.
	Done bool
	// Assigned reports whether anyone has picked the ticket up. Together with
	// Category it decides whether a stale ticket can be rewritten or should only
	// be commented on: nobody's work is disrupted by editing a ticket that is
	// untouched and unassigned, whereas rewriting one under the person working it
	// changes the task they are halfway through.
	Assigned bool
}

// Untouched reports whether a ticket can be rewritten rather than commented on.
//
// Both conditions are needed. An unassigned ticket already in progress is being
// worked by someone who has not claimed it — common on boards that assign at
// standup rather than on pickup — and an assigned ticket still in "To Do" has an
// owner who has read it and knows what it says. Editing either would change the
// task after someone engaged with it, so the comment is the honest move there.
func (e Existing) Untouched() bool {
	return !e.Assigned && e.Category == "new"
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
	// Every configured tracker, for the same reason OpenByImage searches them all:
	// an existing ticket in another team's project still means the work is in
	// flight, and an idempotency check that cannot see it is not one.
	var out []Existing
	seen := map[string]bool{}
	for _, cfg := range j.searchConfigs() {
		found, err := j.findOpenIn(ctx, cfg, images)
		if err != nil {
			return nil, err
		}
		for _, e := range found {
			if !seen[e.Key] {
				seen[e.Key] = true
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func (j *Jira) findOpenIn(ctx context.Context, cfg config.JiraConfig, images []string) ([]Existing, error) {
	jql := fmt.Sprintf(`project = %q AND issuetype = %q AND %s AND statusCategory != Done`,
		cfg.Project, cfg.EffectiveIssueType(), imageClauseFor(cfg, images))

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
			Key:      i.Key,
			Status:   i.Fields.Status.Name,
			Category: i.Fields.Status.StatusCategory.Key,
			Done:     i.Fields.Status.StatusCategory.Key == "done",
		})
	}
	return out, nil
}

// OpenByImage indexes the open tickets of every tracker this configuration can
// write to, not just the default one.
//
// Searching only the base project would be silently wrong once routes exist: a
// finding routed to another team's project would find no ticket there, and every
// run would raise a fresh duplicate. Distinct searches are deduplicated first,
// since several routes commonly share a project.
func (j *Jira) OpenByImage(ctx context.Context) (map[string][]Existing, error) {
	out := map[string][]Existing{}
	seenSearch := map[string]bool{}
	seenTicket := map[string]map[string]bool{} // image -> ticket keys already indexed
	for _, cfg := range j.searchConfigs() {
		key := cfg.Project + "\x00" + cfg.EffectiveIssueType() + "\x00" + jiraImageFieldName(cfg)
		if seenSearch[key] {
			continue
		}
		seenSearch[key] = true
		found, err := j.openByImageIn(ctx, cfg)
		if err != nil {
			return nil, err
		}
		for image, tickets := range found {
			if seenTicket[image] == nil {
				seenTicket[image] = map[string]bool{}
			}
			for _, t := range tickets {
				// The same ticket can surface twice when two searches overlap;
				// counting it twice would make reconciliation think an image is
				// covered by more tickets than exist.
				if seenTicket[image][t.Key] {
					continue
				}
				seenTicket[image][t.Key] = true
				out[image] = append(out[image], t)
			}
		}
	}
	return out, nil
}

// searchConfigs is every tracker to search: the default plus each route's.
func (j *Jira) searchConfigs() []config.JiraConfig {
	out := []config.JiraConfig{j.cfg}
	for _, r := range j.cfg.Routes {
		out = append(out, j.cfg.Resolve(r))
	}
	return out
}

func (j *Jira) openByImageIn(ctx context.Context, cfg config.JiraConfig) (map[string][]Existing, error) {
	jql := fmt.Sprintf(`project = %q AND issuetype = %q AND statusCategory != Done`,
		cfg.Project, cfg.EffectiveIssueType())

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
					// A pointer, because Jira sends null for unassigned and the
					// difference between null and an object is the whole signal.
					Assignee *struct {
						AccountID string `json:"accountId"`
					} `json:"assignee"`
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
		q.Set("fields", "status,summary,assignee,"+jiraImageFieldName(cfg))
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
				Key:      issue.Key,
				Status:   issue.Fields.Status.Name,
				Summary:  issue.Fields.Summary,
				Category: issue.Fields.Status.StatusCategory.Key,
				Done:     issue.Fields.Status.StatusCategory.Key == "done",
				Assigned: issue.Fields.Assignee != nil,
			}
			for _, img := range imagesOfFields(cfg, loose.Issues[i].Fields) {
				out[img] = append(out[img], e)
			}
		}

		if resp.IsLast || resp.NextPageToken == "" {
			return out, nil
		}
		token = resp.NextPageToken
	}
}

// imageFieldName is the field to request and read images from, for the default
// tracker. Per-tracker callers use jiraImageFieldName directly.
func (j *Jira) imageFieldName() string { return jiraImageFieldName(j.cfg) }

func jiraImageFieldName(cfg config.JiraConfig) string {
	if cfg.ImageLabel {
		return "labels"
	}
	return cfg.ImageField
}

// cfgForRoute returns the configuration for a route name, falling back to the
// default. A draft naming an unknown route is a bug rather than a user error, and
// writing it to the default tracker is the recoverable outcome.
func (j *Jira) cfgForRoute(name string) config.JiraConfig {
	if cfg, ok := j.byRoute[name]; ok {
		return cfg
	}
	return j.cfg
}

// cfgForKey resolves the tracker an existing ticket belongs to from its key.
//
// A Jira issue key is "<PROJECT>-<n>", so the prefix identifies the project
// without another API call. This matters for writes to existing tickets: the
// image field differs per tracker, and writing our images into the wrong field
// would leave a ticket that no future run can find.
func (j *Jira) cfgForKey(key string) config.JiraConfig {
	project, _, ok := strings.Cut(key, "-")
	if !ok {
		return j.cfg
	}
	for _, cfg := range j.searchConfigs() {
		if cfg.Project == project {
			return cfg
		}
	}
	return j.cfg
}

// imagesOf extracts the image repositories a ticket covers. Labels are converted
// back from their sanitised form so they match a finding's repository again.
func (j *Jira) imagesOf(fields map[string]json.RawMessage) []string {
	return imagesOfFields(j.cfg, fields)
}

// imagesOfFields reads the images a ticket covers out of whichever field the
// given tracker stores them in.
func imagesOfFields(cfg config.JiraConfig, fields map[string]json.RawMessage) []string {
	raw, ok := fields[jiraImageFieldName(cfg)]
	if !ok {
		return nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil
	}
	if !cfg.ImageLabel {
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
func (j *Jira) imageClause(images []string) string { return imageClauseFor(j.cfg, images) }

func imageClauseFor(cfg config.JiraConfig, images []string) string {
	values := make([]string, 0, len(images))
	for _, img := range images {
		v := img
		if cfg.ImageLabel {
			v = ImageLabel(v)
		}
		values = append(values, quoteJQL(v))
	}
	list := strings.Join(values, ", ")
	if cfg.ImageLabel {
		return "labels IN (" + list + ")"
	}
	id := strings.TrimPrefix(cfg.ImageField, "customfield_")
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
	// The tracker comes from the draft's route: the planner already decided whose
	// board this belongs on, and re-deciding it here would let the two disagree.
	cfg := j.cfgForRoute(d.Route)
	fields := map[string]any{
		"project":     map[string]string{"key": cfg.Project},
		"summary":     d.Summary,
		"issuetype":   map[string]string{"name": cfg.EffectiveIssueType()},
		"description": ADFDocument(d.Description),
	}
	if cfg.Epic != "" {
		fields["parent"] = map[string]string{"key": cfg.Epic}
	}
	// The assessment already decided how urgent this is; carrying that into Jira is
	// what stops the queue flattening to one priority.
	if p := cfg.JiraPriority(d.Priority); p != "" {
		fields["priority"] = map[string]string{"name": p}
	}

	labels := append([]string{}, cfg.Labels...)
	if cfg.ImageLabel {
		for _, img := range d.Images {
			labels = append(labels, ImageLabel(img))
		}
	} else {
		fields[cfg.ImageField] = d.Images
	}
	if len(labels) > 0 {
		fields["labels"] = labels
	}

	var resp struct {
		Key string `json:"key"`
	}
	if err := j.do(ctx, http.MethodPost, "/rest/api/3/issue", map[string]any{"fields": fields}, &resp); err != nil {
		return "", fmt.Errorf("create ticket %q in project %s: %w", d.Summary, cfg.Project, err)
	}
	return resp.Key, nil
}

// Update rewrites a ticket's summary and description to match a fresh draft.
//
// Only the wording is replaced. The images stay as they are, because the draft
// that produced this update covers the same group by definition, and priority
// stays because a human may have deliberately changed it — silently reverting
// someone's triage decision would be a worse bug than a stale summary.
//
// No comment is posted alongside. Jira records field edits in the issue history,
// which is a better audit trail than a comment claiming an edit happened, and
// patchwright logs the write with its own reason.
func (j *Jira) Update(ctx context.Context, key string, d Draft) error {
	body := map[string]any{"fields": map[string]any{
		"summary":     d.Summary,
		"description": ADFDocument(d.Description),
	}}
	if err := j.do(ctx, http.MethodPut, "/rest/api/3/issue/"+url.PathEscape(key), body, nil); err != nil {
		return fmt.Errorf("update %s: %w", key, err)
	}
	return nil
}

// Close transitions a ticket into a done status, commenting with the reason in
// the same request so the explanation cannot arrive without the transition.
//
// The transition is looked up rather than assumed: transition ids are per-workflow,
// and a hardcoded one silently moves tickets to the wrong status on any board that
// does not share the workflow it was written against.
func (j *Jira) Close(ctx context.Context, key, comment string) error {
	cfg := j.cfgForKey(key)
	id, name, err := j.doneTransition(ctx, key, cfg.CloseTransition)
	if err != nil {
		return err
	}
	body := map[string]any{
		"transition": map[string]string{"id": id},
	}
	if comment != "" {
		body["update"] = map[string]any{
			"comment": []any{map[string]any{"add": map[string]any{"body": ADFDocument(comment)}}},
		}
	}
	if err := j.do(ctx, http.MethodPost,
		"/rest/api/3/issue/"+url.PathEscape(key)+"/transitions", body, nil); err != nil {
		return fmt.Errorf("close %s via %q: %w", key, name, err)
	}
	return nil
}

// doneTransition finds the transition to close a ticket with.
//
// A configured name wins, matched case-insensitively against both the transition
// and its target status, because boards label these inconsistently ("Done", "Close
// Issue", "Resolve"). Without a name, the only unambiguous choice is a transition
// into the done status category, and more than one means the workflow offers
// several ways to finish — patchwright refuses rather than picking, since "Won't
// Do" and "Done" say very different things about the same work.
func (j *Jira) doneTransition(ctx context.Context, key, want string) (id, name string, err error) {
	body, err := j.raw(ctx, http.MethodGet,
		"/rest/api/3/issue/"+url.PathEscape(key)+"/transitions")
	if err != nil {
		return "", "", fmt.Errorf("list transitions for %s: %w", key, err)
	}
	var resp struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				Name           string `json:"name"`
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"to"`
		} `json:"transitions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", "", fmt.Errorf("decode transitions for %s: %w", key, err)
	}

	var available []string
	var done []int
	for i, t := range resp.Transitions {
		available = append(available, fmt.Sprintf("%s -> %s", t.Name, t.To.Name))
		if want != "" && (strings.EqualFold(t.Name, want) || strings.EqualFold(t.To.Name, want)) {
			return t.ID, t.Name, nil
		}
		if t.To.StatusCategory.Key == "done" {
			done = append(done, i)
		}
	}
	if want != "" {
		return "", "", fmt.Errorf("no transition named %q available on %s (available: %s)",
			want, key, strings.Join(available, ", "))
	}
	switch len(done) {
	case 0:
		return "", "", fmt.Errorf("no transition into a done status available on %s (available: %s)",
			key, strings.Join(available, ", "))
	case 1:
		t := resp.Transitions[done[0]]
		return t.ID, t.Name, nil
	default:
		names := make([]string, 0, len(done))
		for _, i := range done {
			names = append(names, resp.Transitions[i].Name)
		}
		return "", "", fmt.Errorf("%s has %d ways to finish (%s); set jira.closeTransition "+
			"so the choice is yours rather than ours", key, len(done), strings.Join(names, ", "))
	}
}

// AddImages adds image repositories to an existing ticket's image field or labels,
// preserving what is already there. Jira replaces a field wholesale on update, so
// the current value is read first: a blind write would silently drop the images the
// ticket was raised for.
func (j *Jira) AddImages(ctx context.Context, key string, images []string) error {
	// Resolved from the ticket's own key, not the default: the image field differs
	// per tracker, and writing into the wrong one leaves a ticket no later run can
	// find, which is how duplicates get raised for work already in flight.
	cfg := j.cfgForKey(key)
	existing, err := j.imagesOn(ctx, key)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, img := range existing {
		have[img] = true
	}
	merged := append([]string{}, existing...)
	for _, img := range images {
		if !have[img] {
			have[img] = true
			merged = append(merged, img)
		}
	}
	if len(merged) == len(existing) {
		return nil // already covered; nothing to write
	}
	sort.Strings(merged)

	values := merged
	if cfg.ImageLabel {
		values = make([]string, 0, len(merged))
		for _, img := range merged {
			values = append(values, ImageLabel(img))
		}
	}
	body := map[string]any{"fields": map[string]any{jiraImageFieldName(cfg): values}}
	if err := j.do(ctx, http.MethodPut, "/rest/api/3/issue/"+url.PathEscape(key), body, nil); err != nil {
		return fmt.Errorf("add images to %s: %w", key, err)
	}
	return nil
}

// imagesOn reads the images currently recorded on a ticket.
func (j *Jira) imagesOn(ctx context.Context, key string) ([]string, error) {
	cfg := j.cfgForKey(key)
	q := url.Values{}
	q.Set("fields", jiraImageFieldName(cfg))
	body, err := j.raw(ctx, http.MethodGet,
		"/rest/api/3/issue/"+url.PathEscape(key)+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	var resp struct {
		Fields map[string]json.RawMessage `json:"fields"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode %s: %w", key, err)
	}
	return imagesOfFields(cfg, resp.Fields), nil
}

// Comment adds a comment. Used rather than editing a ticket in place so the
// reasoning is visible in the history and a human can disagree with it.
func (j *Jira) Comment(ctx context.Context, key, body string) error {
	doc := map[string]any{"body": ADFDocument(body)}
	if err := j.do(ctx, http.MethodPost,
		"/rest/api/3/issue/"+url.PathEscape(key)+"/comment", doc, nil); err != nil {
		return fmt.Errorf("comment on %s: %w", key, err)
	}
	return nil
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
