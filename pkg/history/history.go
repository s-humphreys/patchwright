// Package history records how work items move between assessments, so the tool
// can say whether things are getting better rather than only what is wrong today.
//
// Every assessment is a snapshot. This package turns consecutive snapshots into an
// append-only log of transitions, keyed on the work item a queue row and a ticket
// already share, and aggregates that log into a report by period. The design,
// including why resolution demands evidence and why a resolution is classified by
// what the item looked like when it opened, is in docs/design/history.md.
//
// Nothing here touches a database. The store interface is in store.go and its only
// implementation is the postgres subpackage, so the diff and the report can be
// tested as plain functions.
package history

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

// SchemaVersion is the shape of the API response and of stored payloads. Bumped
// whenever a consumer would read old data wrongly, so a report never states a shape
// it does not carry.
const SchemaVersion = 1

// EPSSHigh is the exploitation probability above which a finding carries the
// epss-high signal. It is the threshold the policy rules and the analytics already
// use; having it in three places with three values would be worse than in two.
const EPSSHigh = 0.5

// Signals this package derives, beside the ones the assessment reports on a finding.
// They exist because the report classifies resolutions by signal, and "a fixable
// critical" or "EPSS above the threshold" are the rules' vocabulary without being
// signals the queue shows.
const (
	SignalEPSSHigh        = "epss-high"
	SignalFixableCritical = "fixable-critical"
)

// retiredSignals were recorded by earlier versions and are no longer derived.
// Snapshots already stored keep them, so they are ignored wherever a stored snapshot
// is compared with a new one or counted as open now; otherwise the first run after
// an upgrade would record every item that carried one as having changed.
var retiredSignals = map[string]bool{"exposed": true}

func withoutRetired(signals []string) []string {
	out := make([]string, 0, len(signals))
	for _, s := range signals {
		if !retiredSignals[s] {
			out = append(out, s)
		}
	}
	return out
}

// Kind is the type of a transition.
type Kind string

const (
	// KindOpened is the first assessment in which a key carried an actionable finding.
	KindOpened Kind = "opened"
	// KindResolved is the item leaving the queue WITH evidence that its work is done.
	KindResolved Kind = "resolved"
	// KindLapsed is the item leaving the queue without that evidence: no longer
	// reported, the workload gone, or the data to judge it missing.
	KindLapsed Kind = "lapsed"
	// KindChanged is the rule, priority, signals or target moving while open.
	KindChanged Kind = "changed"
	// KindReassigned is the owner changing while the service and target did not.
	KindReassigned Kind = "reassigned"
	// KindTicketRaised is reconciliation creating or extending a ticket for the item.
	KindTicketRaised Kind = "ticket_raised"
	// KindTicketClosed is a ticket that covered the item no longer being open.
	KindTicketClosed Kind = "ticket_closed"
)

// Kinds lists every kind, in lifecycle order, for consumers that render a legend.
func Kinds() []Kind {
	return []Kind{KindOpened, KindChanged, KindReassigned, KindTicketRaised, KindTicketClosed, KindResolved, KindLapsed}
}

// Snapshot is one work item as one assessment saw it.
type Snapshot struct {
	// Key identifies the item across runs: owner class, team, repository and the
	// NAME of what it upgrades to. Deliberately not the version. The queue's own key
	// includes the target version so that two different moves are two rows, but a
	// history keyed that way would close and reopen an item every time upstream cut
	// a release, and report each as a lapse.
	Key        string `json:"key"`
	Repository string `json:"repository"`
	Class      string `json:"class"`
	Team       string `json:"team"`
	// Target is the upgrade's name (a chart, a base image), empty when nothing is
	// known to move to.
	Target        string `json:"target,omitempty"`
	TargetVersion string `json:"target_version,omitempty"`
	// Kind is the upgrade's kind (base, helm, ...), so rebuilds and version bumps
	// can be told apart in a report.
	Kind string `json:"kind,omitempty"`

	Rule     string   `json:"rule,omitempty"`
	Priority string   `json:"priority,omitempty"`
	Signals  []string `json:"signals,omitempty"`
	// Accounts and Namespaces are where the item runs, kept raw so a report can
	// classify production against the rest by whatever names the estate uses,
	// without depending on a rule name that will be renamed.
	Accounts   []string `json:"accounts,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	// Risk is the highest representative risk score across the item's deployments.
	Risk     float64 `json:"risk"`
	Critical int     `json:"critical"`
	High     int     `json:"high"`
	// Counts is the worst count per severity across the item's deployments.
	Counts map[string]int `json:"counts,omitempty"`
	// CVEs is every distinct CVE across the item's deployments, with what was known
	// about each. It is what makes "which CVEs did we fix" answerable, and is bounded
	// by the images rather than by time.
	CVEs []CVE `json:"cves,omitempty"`
	// OldestCVE is the earliest first-seen date across the item's CVEs, when any is
	// dated. It is the age source for time-to-remediate.
	OldestCVE *time.Time `json:"oldest_cve,omitempty"`
	Images    []string   `json:"images"`
	// Tickets are the open tickets covering any of the item's images at this
	// assessment, so a resolution can be classified as ticketed or not.
	Tickets []string `json:"tickets,omitempty"`
}

// CVE is one vulnerability as an item carried it.
type CVE struct {
	ID           string     `json:"id"`
	Severity     string     `json:"severity,omitempty"`
	CVSS         float64    `json:"cvss,omitempty"`
	EPSS         float64    `json:"epss,omitempty"`
	KEV          bool       `json:"kev,omitempty"`
	FixAvailable bool       `json:"fix_available,omitempty"`
	FirstSeen    *time.Time `json:"first_seen,omitempty"`
}

// Ticketed reports whether any open ticket covered the item.
func (s Snapshot) Ticketed() bool { return len(s.Tickets) > 0 }

// CVEIDs lists the item's CVE identifiers, sorted.
func (s Snapshot) CVEIDs() []string {
	out := make([]string, 0, len(s.CVEs))
	for _, c := range s.CVEs {
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}

// Has reports whether the snapshot carries a signal.
func (s Snapshot) Has(signal string) bool {
	for _, x := range s.Signals {
		if x == signal {
			return true
		}
	}
	return false
}

// Key builds the identity of a work item. Exported so a store or a test can compute
// it without a FindingView.
func Key(class, team, repository, target string) string {
	return strings.Join([]string{class, team, repository, target}, "|")
}

// State is an open item as the store holds it: its latest snapshot and when it
// opened.
type State struct {
	ID       int64     `json:"id"`
	OpenedAt time.Time `json:"opened_at"`
	// Opened is how the item looked when it opened, which is what a resolution is
	// classified by.
	Opened Snapshot `json:"opened"`
	// Current is the latest snapshot recorded for it.
	Current Snapshot `json:"current"`
	// Missing is how many consecutive assessments the item has been absent from
	// without evidence of resolution, and MissingSince when that began. An item
	// lapses only once Missing reaches the grace period; a provider that drops a
	// repository from one hourly response and returns it in the next has not told
	// us anything about the work.
	Missing      int        `json:"missing,omitempty"`
	MissingSince *time.Time `json:"missing_since,omitempty"`
	// TicketDue is the due date each ticket covering the item was raised with, by
	// issue key, so a close can be measured against it. Held on the item rather than
	// read back from the tracker: the date is set once at creation and never moved,
	// so the one patchwright recorded is the one that counts.
	TicketDue map[string]time.Time `json:"ticket_due,omitempty"`
}

// Mark is a change to an open item's missing counter, recorded alongside the
// events of the same run. Zero Missing clears it: the item is back.
type Mark struct {
	ItemID       int64
	Missing      int
	MissingSince *time.Time
}

// DefaultLapseAfter is the grace period when none is configured: the number of
// consecutive assessments an item must be absent from before it lapses. Three
// hourly runs absorbs the jitter a scan provider's responses carry between calls,
// and still lapses a genuinely removed image within the working morning.
const DefaultLapseAfter = 3

// Event is one transition.
type Event struct {
	ID int64 `json:"id,omitempty"`
	// ItemID is the store's identity for the item. Zero for an opened event, where
	// the store assigns one.
	ItemID  int64     `json:"-"`
	Key     string    `json:"key"`
	Kind    Kind      `json:"kind"`
	At      time.Time `json:"at"`
	Payload Payload   `json:"payload"`
}

// Payload carries what a kind needs. One struct rather than one per kind so it can
// be a single jsonb column and be decoded without a type switch; fields a kind does
// not use are omitted.
type Payload struct {
	// Snapshot is the item's state after this event: the opening state for opened,
	// the new state for changed and reassigned.
	Snapshot *Snapshot `json:"snapshot,omitempty"`
	// Opened is how the item looked when it opened, repeated on resolved and lapsed
	// so a report classifies a resolution without a join, and so the classification
	// survives the item row being pruned.
	Opened   *Snapshot  `json:"opened,omitempty"`
	OpenedAt *time.Time `json:"opened_at,omitempty"`
	// Closed is the item's last recorded state before it resolved or lapsed, so
	// what was actually fixed (its CVEs, its versions) is on the closing event.
	Closed *Snapshot `json:"closed,omitempty"`
	// DaysOpen is the age at resolution or lapse.
	DaysOpen *int `json:"days_open,omitempty"`
	// MissingSince and MissedRuns say, on a lapse, how long the item had been absent
	// before the grace period ran out.
	MissingSince *time.Time `json:"missing_since,omitempty"`
	MissedRuns   int        `json:"missed_runs,omitempty"`
	// Ticketed is whether an open ticket covered the item when it resolved or lapsed.
	Ticketed bool `json:"ticketed,omitempty"`
	// Evidence is the observed state that justified a resolution.
	Evidence string `json:"evidence,omitempty"`
	// Reason is why a lapse could not be called a resolution. On a ticket_closed
	// event it is instead why patchwright itself closed the ticket (upgrade-landed,
	// not-running, no-longer-actionable), and empty when a person closed it: a
	// ticket closed because the image was switched off is not a ticket closed
	// because the work was done.
	Reason string `json:"reason,omitempty"`

	// Changes describe a changed event in words; SignalsAdded and SignalsRemoved are
	// the same movement in a shape a report can count.
	Changes        []string `json:"changes,omitempty"`
	SignalsAdded   []string `json:"signals_added,omitempty"`
	SignalsRemoved []string `json:"signals_removed,omitempty"`
	CVEsAdded      []string `json:"cves_added,omitempty"`
	CVEsRemoved    []string `json:"cves_removed,omitempty"`

	// From and To are the owners either side of a reassignment.
	From *Owner `json:"from,omitempty"`
	To   *Owner `json:"to,omitempty"`

	// Ticket is the issue key for ticket events, Action how it was touched
	// (create, extend), and EvidenceAtClose whether patchwright had evidence the
	// work was done when the ticket closed. A ticket closed without it is a human
	// closing a ticket on an image that still runs.
	Ticket          string `json:"ticket,omitempty"`
	Action          string `json:"action,omitempty"`
	EvidenceAtClose *bool  `json:"evidence_at_close,omitempty"`

	// DueDate is the ticket's due date: on ticket_raised for a create that set one,
	// and repeated on ticket_closed so the close carries its own deadline. DaysToDue
	// is the due date less the close date in whole UTC days, negative when overdue,
	// and Overdue says the same as a flag. All absent when no due date was recorded,
	// which is not the same as on time.
	DueDate   *time.Time `json:"due_date,omitempty"`
	DaysToDue *int       `json:"days_to_due,omitempty"`
	Overdue   *bool      `json:"overdue,omitempty"`
}

// Owner is a class and team pair.
type Owner struct {
	Class string `json:"class"`
	Team  string `json:"team"`
}

// Snapshots collapses an assessment's findings into work items. The population is
// actionable, unsuppressed findings: the queue. tickets maps a repository to the
// open ticket keys covering it, as the server's snapshot already holds them.
func Snapshots(views []sink.FindingView, tickets map[string][]string) []Snapshot {
	order := []string{}
	members := map[string][]sink.FindingView{}
	for _, f := range views {
		if !f.Actionable || f.Suppressed {
			continue
		}
		k := keyOf(f)
		if _, seen := members[k]; !seen {
			order = append(order, k)
		}
		members[k] = append(members[k], f)
	}
	out := make([]Snapshot, 0, len(order))
	for _, k := range order {
		out = append(out, snapshot(k, members[k], tickets))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func keyOf(f sink.FindingView) string {
	target := ""
	if f.Upgrade != nil {
		target = f.Upgrade.Name
	}
	return Key(f.Owner.Class, f.Owner.Team, f.Repository, target)
}

var priorityRank = map[string]int{"urgent": 4, "high": 3, "medium": 2, "low": 1}

func snapshot(key string, members []sink.FindingView, tickets map[string][]string) Snapshot {
	lead := members[0]
	for _, f := range members {
		if priorityRank[f.Priority] > priorityRank[lead.Priority] {
			lead = f
		}
	}
	s := Snapshot{
		Key: key, Repository: lead.Repository, Class: lead.Owner.Class, Team: lead.Owner.Team,
		Rule: lead.Rule, Priority: lead.Priority,
	}
	if lead.Upgrade != nil {
		s.Target, s.TargetVersion, s.Kind = lead.Upgrade.Name, lead.Upgrade.Latest, lead.Upgrade.Kind
	}
	signals := map[string]bool{}
	ticketed := map[string]bool{}
	accounts, namespaces := map[string]bool{}, map[string]bool{}
	cves := map[string]CVE{}
	for _, f := range members {
		s.Images = append(s.Images, f.Image)
		if f.Risk > s.Risk {
			s.Risk = f.Risk
		}
		for sev, n := range f.Counts {
			if n > s.Counts[sev] {
				if s.Counts == nil {
					s.Counts = map[string]int{}
				}
				s.Counts[sev] = n
			}
		}
		s.Critical, s.High = s.Counts["critical"], s.Counts["high"]
		for _, a := range f.Dimensions["account"] {
			accounts[a] = true
		}
		for _, n := range f.Dimensions["namespace"] {
			namespaces[n] = true
		}
		for _, v := range f.Vulns {
			c, seen := cves[v.ID]
			if !seen {
				c = CVE{ID: v.ID, Severity: v.Severity, CVSS: v.CVSS, FirstSeen: v.FirstSeen}
			}
			// The worst reading across deployments: a CVE is exploited if any
			// scan says so, and fixable if any deployment has a fix.
			c.KEV = c.KEV || v.KEV
			c.FixAvailable = c.FixAvailable || v.FixAvailable
			if v.EPSS > c.EPSS {
				c.EPSS = v.EPSS
			}
			if v.CVSS > c.CVSS {
				c.CVSS = v.CVSS
			}
			cves[v.ID] = c
		}
		if f.OldestCVESeen != nil && (s.OldestCVE == nil || f.OldestCVESeen.Before(*s.OldestCVE)) {
			t := *f.OldestCVESeen
			s.OldestCVE = &t
		}
		for _, sig := range f.Signals {
			signals[sig] = true
		}
		if f.TopEPSS > EPSSHigh {
			signals[SignalEPSSHigh] = true
		}
		if f.FixableCritical > 0 {
			signals[SignalFixableCritical] = true
		}
		for _, k := range tickets[f.Repository] {
			ticketed[k] = true
		}
	}
	// The queue's transient signals describe this run rather than the item, and a
	// changed event for every pull request opening and closing would be noise in a
	// record meant to show remediation.
	delete(signals, "in-flight")
	delete(signals, "stale-fix")
	delete(signals, "fallback-scan")
	delete(signals, "unassessed")
	s.Signals = sortedKeys(signals)
	s.Tickets = sortedKeys(ticketed)
	s.Accounts, s.Namespaces = sortedKeys(accounts), sortedKeys(namespaces)
	for _, id := range sortedKeys(boolKeys(cves)) {
		s.CVEs = append(s.CVEs, cves[id])
	}
	sort.Strings(s.Images)
	return s
}

func boolKeys(m map[string]CVE) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Input is what one assessment contributes to the diff.
type Input struct {
	// Open is every item the store holds as open.
	Open []State
	// Current is the work items in this assessment.
	Current []Snapshot
	// Views is every finding in this assessment, suppressed included, because the
	// evidence that an item's work is done is read from findings that are no longer
	// actionable.
	Views []sink.FindingView
	// OpenTickets maps a repository to the tickets still open for it, so a ticket
	// that closed alongside an item leaving the queue is recorded with it.
	OpenTickets map[string][]string
	// ClosedReasons are the tickets patchwright closed since the last run, by key,
	// with why. A ticket gone from the open index without an entry here was closed
	// by a person.
	ClosedReasons map[string]string
	// LapseAfter is the grace period in consecutive absent assessments. Zero means
	// DefaultLapseAfter. Resolution with evidence is never delayed by it.
	LapseAfter int
	Now        time.Time
}

// Diff compares the open items against the current assessment and returns the
// transitions, in a stable order, and the missing-counter marks to apply. Events
// for existing items carry their ItemID; opened events carry none.
func Diff(in Input) ([]Event, []Mark) {
	lapseAfter := in.LapseAfter
	if lapseAfter <= 0 {
		lapseAfter = DefaultLapseAfter
	}
	current := map[string]Snapshot{}
	for _, s := range in.Current {
		current[s.Key] = s
	}
	open := map[string]State{}
	for _, st := range in.Open {
		open[st.Current.Key] = st
	}
	byRepo := map[string][]sink.FindingView{}
	for _, v := range in.Views {
		byRepo[v.Repository] = append(byRepo[v.Repository], v)
	}

	var events []Event
	var marks []Mark
	claimed := map[string]bool{} // current keys explained by a reassignment

	// Items that left the queue. Checked before openings so a reassignment can claim
	// the new key it moved to.
	for _, st := range sortedStates(in.Open) {
		if _, still := current[st.Current.Key]; still {
			continue
		}
		if to, ok := reassignedTo(st.Current, in.Current, open); ok && !claimed[to.Key] {
			claimed[to.Key] = true
			events = append(events, reassigned(st, to, in.Now))
			continue
		}
		ev := closed(st, byRepo, in.Now)
		if ev.Kind == KindLapsed && st.Missing+1 < lapseAfter {
			// Absent, but not for long enough to mean anything. Count it and wait;
			// no event, because a provider hiccup is not movement.
			since := st.MissingSince
			if since == nil {
				t := in.Now
				since = &t
			}
			marks = append(marks, Mark{ItemID: st.ID, Missing: st.Missing + 1, MissingSince: since})
			continue
		}
		if ev.Kind == KindLapsed && st.MissingSince != nil {
			ev.Payload.MissingSince = st.MissingSince
			ev.Payload.MissedRuns = st.Missing + 1
		}
		events = append(events, ev)
		events = append(events, ticketsClosed(st, ticketsFor(st.Current, in.OpenTickets), ev.Kind == KindResolved, in.ClosedReasons, in.Now)...)
	}

	for _, s := range in.Current {
		if claimed[s.Key] {
			continue
		}
		st, exists := open[s.Key]
		if !exists {
			snap := s
			events = append(events, Event{Key: s.Key, Kind: KindOpened, At: in.Now, Payload: Payload{Snapshot: &snap}})
			continue
		}
		if st.Missing > 0 {
			// Back within the grace period: nothing happened, as far as the record
			// is concerned.
			marks = append(marks, Mark{ItemID: st.ID})
		}
		if ev, changed := changed(st, s, in.Now); changed {
			events = append(events, ev)
		}
		events = append(events, ticketsClosed(st, s.Tickets, false, in.ClosedReasons, in.Now)...)
	}
	return events, marks
}

// ticketsFor lists the tickets still open for an item's repository.
func ticketsFor(item Snapshot, open map[string][]string) []string {
	seen := map[string]bool{}
	for _, k := range open[item.Repository] {
		seen[k] = true
	}
	return sortedKeys(seen)
}

func sortedStates(states []State) []State {
	out := append([]State(nil), states...)
	sort.Slice(out, func(i, j int) bool { return out[i].Current.Key < out[j].Current.Key })
	return out
}

// reassignedTo finds a current item that is the same service and target under a
// different owner, and is not itself already an open item.
func reassignedTo(prev Snapshot, current []Snapshot, open map[string]State) (Snapshot, bool) {
	for _, s := range current {
		if s.Repository != prev.Repository || s.Target != prev.Target {
			continue
		}
		if s.Class == prev.Class && s.Team == prev.Team {
			continue
		}
		if _, alreadyOpen := open[s.Key]; alreadyOpen {
			continue
		}
		return s, true
	}
	return Snapshot{}, false
}

func reassigned(st State, to Snapshot, now time.Time) Event {
	snap := to
	return Event{
		ItemID: st.ID, Key: st.Current.Key, Kind: KindReassigned, At: now,
		Payload: Payload{
			Snapshot: &snap,
			From:     &Owner{Class: st.Current.Class, Team: st.Current.Team},
			To:       &Owner{Class: to.Class, Team: to.Team},
		},
	}
}

// closed decides whether an item that left the queue was resolved or lapsed, and
// records any tickets that closed with it.
func closed(st State, byRepo map[string][]sink.FindingView, now time.Time) Event {
	opened, closedState := st.Opened, st.Current
	openedAt := st.OpenedAt
	days := int(now.Sub(openedAt).Hours() / 24)
	p := Payload{Opened: &opened, Closed: &closedState, OpenedAt: &openedAt, DaysOpen: &days, Ticketed: st.Current.Ticketed()}
	evidence, reason := Evidence(st.Current, byRepo)
	kind := KindLapsed
	if reason == "" {
		kind = KindResolved
		p.Evidence = evidence
	} else {
		p.Reason = reason
	}
	return Event{ItemID: st.ID, Key: st.Current.Key, Kind: kind, At: now, Payload: p}
}

// Evidence applies the test ticket auto-closing uses to an item that has left the
// queue. It returns the observed state as evidence when the work is provably done,
// or the first reason it cannot be called done. The reasons are distinct on purpose:
// "no longer reported" is coverage loss, "upgrade still available" is the work not
// having happened, and a report that merged them would improve fastest when the
// scanner broke.
//
// Judged per repository, as the assessment names it: an item's images all share its
// repository, and the same key is what the ticket index and the queue use.
func Evidence(item Snapshot, byRepo map[string][]sink.FindingView) (evidence, reason string) {
	var observed []string
	for _, repo := range []string{item.Repository} {
		found := byRepo[repo]
		if len(found) == 0 {
			return "", fmt.Sprintf("%s is no longer reported", repo)
		}
		versions := map[string]bool{}
		for _, f := range found {
			switch {
			case f.Liveness != nil && !f.Liveness.Live:
				return "", fmt.Sprintf("%s is no longer running", repo)
			case !f.RemediationChecked:
				return "", fmt.Sprintf("%s was not checked for a newer version", repo)
			case f.Upgrade == nil || !f.Upgrade.Resolved:
				return "", fmt.Sprintf("%s: versions could not be resolved", repo)
			case f.Upgrade.Available:
				return "", fmt.Sprintf("%s still has %s available", repo, f.Upgrade.Latest)
			case f.Liveness == nil:
				return "", fmt.Sprintf("%s: liveness was not reconciled", repo)
			}
			if f.Upgrade.Current != "" {
				versions[f.Upgrade.Current] = true
			}
		}
		if len(versions) == 0 {
			observed = append(observed, repo+" is on the latest version")
		} else {
			observed = append(observed, fmt.Sprintf("%s is on %s", repo, strings.Join(sortedKeys(versions), ", ")))
		}
	}
	return strings.Join(observed, "; ") + ".", ""
}

// changed reports the item's movement while open, when there was any. Risk moves on
// most scans and is carried in the snapshot without being an event of its own.
func changed(st State, now Snapshot, at time.Time) (Event, bool) {
	prev := st.Current
	var changes []string
	if prev.Rule != now.Rule {
		changes = append(changes, "rule: "+orNone(prev.Rule)+" -> "+orNone(now.Rule))
	}
	if prev.Priority != now.Priority {
		changes = append(changes, "priority: "+orNone(prev.Priority)+" -> "+orNone(now.Priority))
	}
	if prev.TargetVersion != now.TargetVersion {
		changes = append(changes, "target: "+orNone(prev.TargetVersion)+" -> "+orNone(now.TargetVersion))
	}
	added, removed := diffStrings(withoutRetired(prev.Signals), now.Signals)
	for _, s := range added {
		changes = append(changes, "+"+s)
	}
	for _, s := range removed {
		changes = append(changes, "-"+s)
	}
	// CVEs arriving or leaving while the item stays open is movement worth
	// recording: a partial fix, or a newly published CVE against a running image.
	cvesAdded, cvesRemoved := diffStrings(prev.CVEIDs(), now.CVEIDs())
	if len(cvesAdded) > 0 {
		changes = append(changes, fmt.Sprintf("+%d CVEs", len(cvesAdded)))
	}
	if len(cvesRemoved) > 0 {
		changes = append(changes, fmt.Sprintf("-%d CVEs", len(cvesRemoved)))
	}
	if len(changes) == 0 {
		return Event{}, false
	}
	snap := now
	return Event{
		ItemID: st.ID, Key: st.Current.Key, Kind: KindChanged, At: at,
		Payload: Payload{
			Snapshot: &snap, Changes: changes, SignalsAdded: added, SignalsRemoved: removed,
			CVEsAdded: cvesAdded, CVEsRemoved: cvesRemoved,
		},
	}, true
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func diffStrings(prev, now []string) (added, removed []string) {
	p, n := map[string]bool{}, map[string]bool{}
	for _, s := range prev {
		p[s] = true
	}
	for _, s := range now {
		n[s] = true
		if !p[s] {
			added = append(added, s)
		}
	}
	for _, s := range prev {
		if !n[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// ticketsClosed records tickets that covered the item last time and no longer do.
// Only open tickets are indexed, so a key that has gone from the index has closed or
// moved to a done status; phase three of the design reads the date from the tracker.
func ticketsClosed(st State, nowTickets []string, evidence bool, reasons map[string]string, at time.Time) []Event {
	_, gone := diffStrings(st.Current.Tickets, nowTickets)
	out := make([]Event, 0, len(gone))
	for _, key := range gone {
		e := evidence
		p := Payload{Ticket: key, EvidenceAtClose: &e, Reason: reasons[key]}
		if due, ok := st.TicketDue[key]; ok {
			d := due
			days := DaysToDue(due, at)
			overdue := days < 0
			p.DueDate, p.DaysToDue, p.Overdue = &d, &days, &overdue
		}
		out = append(out, Event{
			ItemID: st.ID, Key: st.Current.Key, Kind: KindTicketClosed, At: at, Payload: p,
		})
	}
	return out
}

// DaysToDue is whole calendar days from at until due, in UTC, negative once the
// due date has passed. A due date is a day rather than an instant, so a ticket
// closed at any time on its due day is on time (zero), not a fraction late.
func DaysToDue(due, at time.Time) int {
	day := func(t time.Time) time.Time {
		t = t.UTC()
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	}
	return int(day(due).Sub(day(at)).Hours() / 24)
}

// TicketWrite is one successful create or extend from ticket reconciliation, in the
// shape this package needs: which images the ticket now covers.
type TicketWrite struct {
	Key    string
	Action string
	Images []string
	// DueDate is set only on a create that gave the ticket one. An extend leaves
	// it nil: adding images to a ticket does not move its deadline.
	DueDate *time.Time
}

// TicketEvents attributes ticket writes to the open items whose images they cover.
// Called after reconciliation, which runs after the lifecycle diff, so the items
// here are the ones the store holds open for this assessment.
//
// A write names its images the way the ticket does, as bare repositories, which is
// also how a work item is keyed. The full references an item lists are matched too,
// for a caller that has them; matching on those alone recorded no ticket_raised
// event at all in production, because a draft never carries a tag or registry.
func TicketEvents(open []State, writes []TicketWrite, at time.Time) []Event {
	var out []Event
	for _, st := range sortedStates(open) {
		covered := map[string]bool{}
		for _, img := range st.Current.Images {
			covered[img] = true
		}
		if st.Current.Repository != "" {
			covered[st.Current.Repository] = true
		}
		for _, w := range writes {
			for _, img := range w.Images {
				if covered[img] {
					out = append(out, Event{
						ItemID: st.ID, Key: st.Current.Key, Kind: KindTicketRaised, At: at,
						Payload: Payload{Ticket: w.Key, Action: w.Action, DueDate: w.DueDate},
					})
					break
				}
			}
		}
	}
	return out
}

// Assessment is what one run contributes to the assessments table: enough to draw
// the estate's direction without a finding-level row.
type Assessment struct {
	ID         int64     `json:"id,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Findings   int       `json:"findings"`
	Actionable int       `json:"actionable"`
	ItemCount  int       `json:"item_count"`
	Risk       RiskStats `json:"risk"`
	// ByClass and ByTeam split the risk the same way the owners page does.
	ByClass map[string]RiskStats `json:"by_class,omitempty"`
	ByTeam  map[string]RiskStats `json:"by_team,omitempty"`

	// Counts are severity totals summed over every unsuppressed finding, and
	// ActionableCounts over the actionable ones: "total criticals across the
	// estate" month on month. Distinct CVE tallies sit beside them because a CVE on
	// sixty images is one vulnerability and sixty findings.
	Counts           map[string]int `json:"counts,omitempty"`
	ActionableCounts map[string]int `json:"actionable_counts,omitempty"`
	DistinctCVEs     int            `json:"distinct_cves"`
	DistinctKEV      int            `json:"distinct_kev"`
	DistinctEPSSHigh int            `json:"distinct_epss_high"`

	// Summary is the server's headline summary for the run, stored as given so any
	// aggregate the status page shows today can be asked about historically.
	Summary any `json:"summary,omitempty"`
	// Items is the full work-item list for the run. Not returned by Assessments,
	// which would be heavy; it is stored so a question nobody has asked yet can be
	// answered by re-deriving from the items rather than from the events.
	Items []Snapshot `json:"items,omitempty"`
}

// RiskStats summarise the risk scores of a set of work items. Sum is the estate
// number; the percentiles stop one enormous image from standing in for everything.
type RiskStats struct {
	Items int     `json:"items"`
	Sum   float64 `json:"sum"`
	P50   float64 `json:"p50"`
	P90   float64 `json:"p90"`
	Max   float64 `json:"max"`
	// Urgent and KnownExploited are how much of the set is at the sharp end.
	Urgent         int `json:"urgent"`
	KnownExploited int `json:"known_exploited"`
}

// Risk computes RiskStats over snapshots.
func Risk(items []Snapshot) RiskStats {
	out := RiskStats{Items: len(items)}
	if len(items) == 0 {
		return out
	}
	scores := make([]float64, 0, len(items))
	for _, s := range items {
		scores = append(scores, s.Risk)
		out.Sum += s.Risk
		if s.Risk > out.Max {
			out.Max = s.Risk
		}
		if s.Priority == "urgent" {
			out.Urgent++
		}
		if s.Has("kev") {
			out.KnownExploited++
		}
	}
	sort.Float64s(scores)
	out.P50 = percentile(scores, 0.5)
	out.P90 = percentile(scores, 0.9)
	return out
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

// Summarise builds an Assessment row from an assessment's findings and items.
// summary is the server's headline view, stored as given.
func Summarise(started, finished time.Time, views []sink.FindingView, items []Snapshot, summary any) Assessment {
	a := Assessment{
		StartedAt: started, FinishedAt: finished,
		Risk: Risk(items), ByClass: map[string]RiskStats{}, ByTeam: map[string]RiskStats{},
		Counts: map[string]int{}, ActionableCounts: map[string]int{},
		Summary: summary, Items: items,
	}
	cves, kev, epss := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, v := range views {
		if v.Suppressed {
			continue
		}
		a.Findings++
		for sev, n := range v.Counts {
			a.Counts[sev] += n
		}
		if v.Actionable {
			a.Actionable++
			for sev, n := range v.Counts {
				a.ActionableCounts[sev] += n
			}
		}
		for _, c := range v.Vulns {
			cves[c.ID] = true
			if c.KEV {
				kev[c.ID] = true
			}
			if c.EPSS > EPSSHigh {
				epss[c.ID] = true
			}
		}
	}
	a.DistinctCVEs, a.DistinctKEV, a.DistinctEPSSHigh = len(cves), len(kev), len(epss)
	a.ItemCount = len(items)
	byClass, byTeam := map[string][]Snapshot{}, map[string][]Snapshot{}
	for _, s := range items {
		byClass[s.Class] = append(byClass[s.Class], s)
		byTeam[s.Team] = append(byTeam[s.Team], s)
	}
	for c, ss := range byClass {
		a.ByClass[c] = Risk(ss)
	}
	for t, ss := range byTeam {
		a.ByTeam[t] = Risk(ss)
	}
	return a
}
