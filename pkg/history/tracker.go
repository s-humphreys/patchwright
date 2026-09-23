package history

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"
)

// TrackerTicket is one ticket as the tracker dates it. The event log knows when
// patchwright raised a ticket or saw it close; the tracker knows when it was raised
// whoever raised it, when somebody first picked it up, and when it was resolved,
// including for tickets older than the record.
type TrackerTicket struct {
	Key     string `json:"key"`
	Project string `json:"project"`
	// ItemKey is the work item the ticket was matched to by image, best effort, and
	// ItemOpenedAt when that item's current span opened. Empty for a ticket whose
	// images match nothing open, which is every ticket on an item that closed before
	// the tracker was first read.
	ItemKey      string     `json:"item_key,omitempty"`
	ItemOpenedAt *time.Time `json:"item_opened_at,omitempty"`
	// Images are what the ticket covers. Used to match it and not stored apart from
	// the raw fields.
	Images    []string  `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	// StartedAt is the first move into an in-progress status, and StartedFrom how it
	// was found ("changelog", or "status-category" when only the current status's
	// change date was available).
	StartedAt   *time.Time `json:"started_at,omitempty"`
	StartedFrom string     `json:"started_from,omitempty"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
	DueAt       *time.Time `json:"due_at,omitempty"`
	Status      string     `json:"status,omitempty"`
	// StatusCategory is the tracker's portable category: new, indeterminate, done.
	StatusCategory string          `json:"status_category,omitempty"`
	LastSeenAt     time.Time       `json:"last_seen_at"`
	Raw            json.RawMessage `json:"-"`
}

// How a ticket's first In Progress was found.
const (
	StartedFromChangelog      = "changelog"
	StartedFromStatusCategory = "status-category"
)

// TicketIndexState is what the store holds of the tracker.
type TicketIndexState struct {
	Tickets      int
	FirstCreated time.Time
	LastSynced   time.Time
}

// TicketFetcher reads the tracker: tickets updated within the window, or every
// ticket when within is zero.
type TicketFetcher func(ctx context.Context, within time.Duration) ([]TrackerTicket, error)

// TicketSync is what one sync did.
type TicketSync struct {
	Full    bool          `json:"full"`
	Window  time.Duration `json:"window,omitempty"`
	Fetched int           `json:"fetched"`
	Matched int           `json:"matched"`
}

// minTicketWindow is the shortest incremental window. Longer than the refresh
// interval by a wide margin, so a run that failed or a clock that drifted does not
// leave a ticket unread; the upsert makes re-reading free.
const minTicketWindow = 48 * time.Hour

// SyncTickets reads the tracker into the store: everything when full is set or the
// index is empty, otherwise what changed since the last sync or in the last two
// days, whichever is longer. Tickets are matched to the open items first, so a
// close can later be dated against the item it left open.
func SyncTickets(ctx context.Context, store Store, fetch TicketFetcher, full bool, now time.Time) (TicketSync, error) {
	idx, err := store.TicketsIndexed(ctx)
	if err != nil {
		return TicketSync{}, err
	}
	out := TicketSync{Full: full || idx.Tickets == 0}
	if !out.Full {
		out.Window = minTicketWindow
		if since := now.Sub(idx.LastSynced) + time.Hour; since > out.Window {
			out.Window = since
		}
	}
	tickets, err := fetch(ctx, out.Window)
	if err != nil {
		return out, fmt.Errorf("read the tracker: %w", err)
	}
	open, err := store.Open(ctx)
	if err != nil {
		return out, err
	}
	tickets = MatchTickets(tickets, open)
	for i := range tickets {
		tickets[i].LastSeenAt = now
		if tickets[i].ItemKey != "" {
			out.Matched++
		}
	}
	out.Fetched = len(tickets)
	if err := store.UpsertTickets(ctx, tickets); err != nil {
		return out, err
	}
	return out, nil
}

// MatchTickets attributes each ticket to an open work item whose repository is one
// of the ticket's images, the way reconciliation matches a ticket to findings.
// Where several items share a repository, the one whose snapshot already lists the
// ticket wins, then the one opened first. A ticket that matches nothing keeps
// whatever an earlier sync matched it to.
func MatchTickets(tickets []TrackerTicket, open []State) []TrackerTicket {
	byRepo := map[string][]State{}
	for _, st := range sortedStates(open) {
		byRepo[st.Current.Repository] = append(byRepo[st.Current.Repository], st)
	}
	out := make([]TrackerTicket, len(tickets))
	for i, t := range tickets {
		var best *State
		bestListed := false
		for _, img := range t.Images {
			for j := range byRepo[img] {
				st := &byRepo[img][j]
				listed := listsTicket(st.Current, t.Key)
				if best == nil || (listed && !bestListed) || (listed == bestListed && st.OpenedAt.Before(best.OpenedAt)) {
					best, bestListed = st, listed
				}
			}
		}
		if best != nil {
			opened := best.OpenedAt
			t.ItemKey, t.ItemOpenedAt = best.Current.Key, &opened
		}
		out[i] = t
	}
	return out
}

func listsTicket(s Snapshot, key string) bool {
	for _, k := range s.Tickets {
		if k == key {
			return true
		}
	}
	return false
}

// TrackerSummary marks the figures read from the tracker rather than from the
// record: tickets, whoever raised them, with no rule or signal attached.
type TrackerSummary struct {
	// Source is always "tracker", so a consumer reading one period's fields can
	// tell which of them came from where.
	Source string `json:"source"`
	// Tickets is how many tickets the index holds.
	Tickets int `json:"tickets"`
	// FirstCreated is the oldest ticket indexed: roughly when ticketing began, less
	// whatever retention has pruned.
	FirstCreated *time.Time `json:"first_created,omitempty"`
	LastSynced   time.Time  `json:"last_synced"`
	// StartedFromStatusCategory counts the tickets behind this report's cycle times
	// whose first In Progress is the status category change date rather than the
	// change history.
	StartedFromStatusCategory int `json:"started_from_status_category,omitempty"`
}

// AddTracker adds the tracker's figures to a report: per period, tickets raised and
// closed by the tracker's own dates and the three cycle-time medians over tickets
// resolved in the period; on the open summary, how long ago the ticket closed on
// each item still open. first is when the record began, which bounds what "the
// finding opened" can mean.
func (r *Report) AddTracker(tickets []TrackerTicket, idx TicketIndexState, open []State, first, now time.Time) {
	if idx.Tickets == 0 {
		return
	}
	sum := &TrackerSummary{Source: "tracker", Tickets: idx.Tickets, LastSynced: idx.LastSynced}
	if !idx.FirstCreated.IsZero() {
		f := idx.FirstCreated
		sum.FirstCreated = &f
	}
	r.Tracker = sum

	periodOf := func(t time.Time) int {
		for i, m := range r.Movement {
			if !t.Before(m.Start) && t.Before(m.End) {
				return i
			}
		}
		return -1
	}
	// Periods that end before the first ticket are before ticketing began, not
	// periods in which nothing was raised.
	for i := range r.Movement {
		if idx.FirstCreated.IsZero() || r.Movement[i].End.After(idx.FirstCreated) {
			r.Movement[i].TrackerTicketsRaised, r.Movement[i].TrackerTicketsClosed = new(int), new(int)
		}
	}
	told, toStart, worked := map[int][]float64{}, map[int][]float64{}, map[int][]float64{}
	for _, t := range tickets {
		if i := periodOf(t.CreatedAt); i >= 0 && r.Movement[i].TrackerTicketsRaised != nil {
			*r.Movement[i].TrackerTicketsRaised++
		}
		if t.ResolvedAt == nil {
			continue
		}
		i := periodOf(*t.ResolvedAt)
		if i < 0 {
			continue
		}
		if r.Movement[i].TrackerTicketsClosed != nil {
			*r.Movement[i].TrackerTicketsClosed++
		}
		// The finding's opening is only known for items the record saw open, not for
		// the baseline, whose opened_at is when the watching started.
		if t.ItemOpenedAt != nil && !t.CreatedAt.Before(*t.ItemOpenedAt) &&
			(first.IsZero() || t.ItemOpenedAt.After(first.Add(time.Minute))) {
			told[i] = append(told[i], days(t.CreatedAt.Sub(*t.ItemOpenedAt)))
		}
		if t.StartedAt == nil {
			continue
		}
		if t.StartedFrom == StartedFromStatusCategory {
			sum.StartedFromStatusCategory++
		}
		if !t.StartedAt.Before(t.CreatedAt) {
			toStart[i] = append(toStart[i], days(t.StartedAt.Sub(t.CreatedAt)))
		}
		if !t.ResolvedAt.Before(*t.StartedAt) {
			worked[i] = append(worked[i], days(t.ResolvedAt.Sub(*t.StartedAt)))
		}
	}
	for i := range r.Movement {
		m := &r.Movement[i]
		m.MedianDaysTold, m.MedianDaysToldN = medianOf(told[i])
		m.MedianDaysToStart, m.MedianDaysToStartN = medianOf(toStart[i])
		m.MedianDaysWorked, m.MedianDaysWorkedN = medianOf(worked[i])
	}
	r.Open.addClosedTickets(tickets, open, now)
}

// addClosedTickets dates the "ticket closed, finding open" bucket: open items whose
// latest matched ticket the tracker resolved during the item's current span, with
// no ticket covering the item now. An item somebody has ticketed again is being
// worked, whatever happened to the first ticket.
func (o *OpenSummary) addClosedTickets(tickets []TrackerTicket, open []State, now time.Time) {
	openAt := map[string]State{}
	for _, st := range open {
		openAt[st.Current.Key] = st
	}
	latest := map[string]time.Time{}
	for _, t := range tickets {
		st, ok := openAt[t.ItemKey]
		if t.ResolvedAt == nil || !ok || st.Current.Ticketed() || t.ResolvedAt.Before(st.OpenedAt) || t.ResolvedAt.After(now) {
			continue
		}
		if t.ResolvedAt.After(latest[t.ItemKey]) {
			latest[t.ItemKey] = *t.ResolvedAt
		}
	}
	n := len(latest)
	o.ClosedTicketFindingOpen = &n
	if n == 0 {
		return
	}
	o.ClosedTicketAgeDays = map[string]int{}
	for _, closed := range latest {
		o.ClosedTicketAgeDays[ageBucket(int(now.Sub(closed).Hours()/24))]++
	}
}

func days(d time.Duration) float64 { return d.Hours() / 24 }

// medianOf is the median in days to one decimal place and how many values it rests
// on; nil and zero for none.
func medianOf(xs []float64) (*float64, int) {
	if len(xs) == 0 {
		return nil, 0
	}
	sort.Float64s(xs)
	m := math.Round(median(xs)*10) / 10
	return &m, len(xs)
}
