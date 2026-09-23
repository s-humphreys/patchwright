package ticket

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/pkg/config"
)

// Dated is a ticket as the tracker dates it: when it was raised, first picked up
// and resolved, whatever its status now. The open index ignores anything done,
// because its job is to avoid duplicates; measuring cycle time needs the opposite.
type Dated struct {
	Key     string
	Project string
	// Summary is the issue's title.
	Summary string
	// Images are what the ticket covers, read from the route's image field.
	Images   []string
	Status   string
	Category string
	Created  time.Time
	// Started is the first move into the "indeterminate" status category. Nil when
	// the ticket never went through one, which is not the same as instantly.
	Started *time.Time
	// StartedFrom says how Started was found: StartedFromChangelog, or
	// StartedFromStatusCategory when the change history could not be read and the
	// ticket is in progress now.
	StartedFrom string
	// Resolved is Jira's resolution date, or the status category change date for a
	// done ticket whose workflow never sets a resolution. Nil unless the ticket is
	// in the done category now.
	Resolved *time.Time
	Due      *time.Time
	// Fields is the issue's fields as Jira sent them, kept so a question about a
	// field nobody parsed yet can still be answered from the stored row.
	Fields json.RawMessage
}

const (
	StartedFromChangelog      = "changelog"
	StartedFromStatusCategory = "status-category"
)

// jiraTime is the timestamp shape Jira's REST API writes.
const jiraTime = "2006-01-02T15:04:05.000-0700"

// DatedTickets lists every ticket of every configured tracker with the tracker's
// dates, closed ones included. within limits it to tickets updated in that window
// (the incremental path); zero lists everything, which is the backfill.
//
// First In Progress comes from the change history, expanded in the search. The
// status id a history entry moves to is mapped to its category with one call per
// sync; if that call fails, a ticket in progress now falls back to its status
// category change date and the rest go undated rather than guessed.
func (j *Jira) DatedTickets(ctx context.Context, within time.Duration) ([]Dated, error) {
	categories, err := j.statusCategories(ctx)
	if err != nil {
		slog.WarnContext(ctx, "jira: could not map statuses to categories; first In Progress falls back to the status category change date of tickets in progress now", "error", err)
		categories = nil
	}
	var out []Dated
	seenSearch := map[string]bool{}
	seenTicket := map[string]bool{}
	for _, cfg := range j.searchConfigs() {
		key := cfg.Project + "\x00" + cfg.EffectiveIssueType() + "\x00" + jiraImageFieldName(cfg)
		if seenSearch[key] {
			continue
		}
		seenSearch[key] = true
		found, err := j.datedIn(ctx, cfg, within, categories)
		if err != nil {
			return nil, err
		}
		for _, d := range found {
			if !seenTicket[d.Key] {
				seenTicket[d.Key] = true
				out = append(out, d)
			}
		}
	}
	return out, nil
}

// statusCategories maps every status id on the site to its category key.
func (j *Jira) statusCategories(ctx context.Context) (map[string]string, error) {
	var statuses []struct {
		ID             string `json:"id"`
		StatusCategory struct {
			Key string `json:"key"`
		} `json:"statusCategory"`
	}
	if err := j.do(ctx, http.MethodGet, "/rest/api/3/status", nil, &statuses); err != nil {
		return nil, fmt.Errorf("list statuses: %w", err)
	}
	out := make(map[string]string, len(statuses))
	for _, s := range statuses {
		out[s.ID] = s.StatusCategory.Key
	}
	return out, nil
}

type changeHistory struct {
	Created string `json:"created"`
	Items   []struct {
		// fieldId is the stable identifier; field is the display name, which a
		// site can translate. Older entries may carry only the name.
		FieldID string `json:"fieldId"`
		Field   string `json:"field"`
		To      string `json:"to"`
	} `json:"items"`
}

func (h changeHistory) statusTargets() []string {
	var out []string
	for _, it := range h.Items {
		if it.FieldID == "status" || (it.FieldID == "" && it.Field == "status") {
			out = append(out, it.To)
		}
	}
	return out
}

func (j *Jira) datedIn(ctx context.Context, cfg config.JiraConfig, within time.Duration, categories map[string]string) ([]Dated, error) {
	jql := fmt.Sprintf(`project = %q AND issuetype = %q`, cfg.Project, cfg.EffectiveIssueType())
	if within > 0 {
		jql += fmt.Sprintf(` AND updated >= -%dm`, int(math.Ceil(within.Minutes())))
	}
	var out []Dated
	token := ""
	for {
		var resp struct {
			Issues []struct {
				Key    string          `json:"key"`
				Fields json.RawMessage `json:"fields"`
				// The search expands at most a page of history, newest first; total
				// says whether the first move into progress may be past the end.
				Changelog *struct {
					Total     int             `json:"total"`
					Histories []changeHistory `json:"histories"`
				} `json:"changelog"`
			} `json:"issues"`
			NextPageToken string `json:"nextPageToken"`
			IsLast        bool   `json:"isLast"`
		}
		q := url.Values{}
		q.Set("jql", jql)
		q.Set("fields", "summary,created,resolutiondate,duedate,status,statuscategorychangedate,"+jiraImageFieldName(cfg))
		// Half the usual page: each issue carries its change history, and a
		// project with long-lived tickets makes a hundred of them a large body.
		q.Set("maxResults", "50")
		if categories != nil {
			q.Set("expand", "changelog")
		}
		if token != "" {
			q.Set("nextPageToken", token)
		}
		body, err := j.raw(ctx, http.MethodGet, "/rest/api/3/search/jql?"+q.Encode())
		if err != nil {
			return nil, fmt.Errorf("list dated tickets (jql: %s): %w", jql, err)
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode dated tickets: %w", err)
		}
		for _, issue := range resp.Issues {
			d, err := parseDated(cfg, issue.Key, issue.Fields)
			if err != nil {
				return nil, err
			}
			if categories != nil && issue.Changelog != nil {
				// The expanded page is the newest history, so on a truncated one its
				// earliest move into progress need not be the first: a reopened
				// ticket has a recent re-entry there and its real start past the end.
				if issue.Changelog.Total > len(issue.Changelog.Histories) {
					if d.Started, err = j.firstStartedPaged(ctx, issue.Key, categories); err != nil {
						return nil, err
					}
				} else {
					d.Started = firstStarted(issue.Changelog.Histories, categories)
				}
				if d.Started != nil {
					d.StartedFrom = StartedFromChangelog
				}
			}
			if d.Started == nil && categories == nil && d.Category == "indeterminate" {
				if t := statusCategoryChanged(issue.Fields); t != nil {
					d.Started, d.StartedFrom = t, StartedFromStatusCategory
				}
			}
			out = append(out, d)
		}
		if resp.IsLast || resp.NextPageToken == "" {
			return out, nil
		}
		token = resp.NextPageToken
	}
}

func parseDated(cfg config.JiraConfig, key string, raw json.RawMessage) (Dated, error) {
	var f struct {
		Summary        string  `json:"summary"`
		Created        string  `json:"created"`
		ResolutionDate *string `json:"resolutiondate"`
		DueDate        *string `json:"duedate"`
		Status         struct {
			Name           string `json:"name"`
			StatusCategory struct {
				Key string `json:"key"`
			} `json:"statusCategory"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return Dated{}, fmt.Errorf("decode %s fields: %w", key, err)
	}
	created, err := time.Parse(jiraTime, f.Created)
	if err != nil {
		return Dated{}, fmt.Errorf("%s: created %q: %w", key, f.Created, err)
	}
	project, _, _ := strings.Cut(key, "-")
	d := Dated{
		Key: key, Project: project, Summary: f.Summary, Created: created,
		Status: f.Status.Name, Category: f.Status.StatusCategory.Key, Fields: raw,
	}
	var loose map[string]json.RawMessage
	if err := json.Unmarshal(raw, &loose); err == nil {
		d.Images = imagesOfFields(cfg, loose)
	}
	// Resolved only while done: some workflows reopen a ticket without clearing its
	// resolution, and a stale date on open work would count it as closed. Workflows
	// that close without setting a resolution leave the date empty on a done ticket,
	// and the move into done is the same moment.
	if d.Category == "done" {
		if f.ResolutionDate != nil {
			if t, err := time.Parse(jiraTime, *f.ResolutionDate); err == nil {
				d.Resolved = &t
			}
		}
		if d.Resolved == nil {
			d.Resolved = statusCategoryChanged(raw)
		}
	}
	if f.DueDate != nil {
		if t, err := time.Parse(time.DateOnly, *f.DueDate); err == nil {
			d.Due = &t
		}
	}
	return d, nil
}

func statusCategoryChanged(raw json.RawMessage) *time.Time {
	var f struct {
		Changed string `json:"statuscategorychangedate"`
	}
	if json.Unmarshal(raw, &f) != nil || f.Changed == "" {
		return nil
	}
	t, err := time.Parse(jiraTime, f.Changed)
	if err != nil {
		return nil
	}
	return &t
}

// firstStarted is the earliest history entry that moved the ticket into a status
// in the indeterminate category. Histories arrive in either order depending on the
// endpoint, so the minimum is taken rather than the first seen.
func firstStarted(histories []changeHistory, categories map[string]string) *time.Time {
	var first *time.Time
	for _, h := range histories {
		for _, to := range h.statusTargets() {
			if categories[to] != "indeterminate" {
				continue
			}
			t, err := time.Parse(jiraTime, h.Created)
			if err != nil {
				continue
			}
			if first == nil || t.Before(*first) {
				first = &t
			}
		}
	}
	return first
}

// firstStartedPaged reads a ticket's full change history, oldest first, for the
// rare ticket whose history is longer than the search expands.
func (j *Jira) firstStartedPaged(ctx context.Context, key string, categories map[string]string) (*time.Time, error) {
	start := 0
	for {
		var page struct {
			Total  int             `json:"total"`
			IsLast bool            `json:"isLast"`
			Values []changeHistory `json:"values"`
		}
		path := fmt.Sprintf("/rest/api/3/issue/%s/changelog?startAt=%d&maxResults=100", url.PathEscape(key), start)
		if err := j.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, fmt.Errorf("read %s change history: %w", key, err)
		}
		if t := firstStarted(page.Values, categories); t != nil {
			return t, nil
		}
		start += len(page.Values)
		if page.IsLast || len(page.Values) == 0 || start >= page.Total {
			return nil, nil
		}
	}
}
