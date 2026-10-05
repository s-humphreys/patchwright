# History

Every assessment is a snapshot. History is the record of how the queue moved between
them, so the tool can answer "is this getting better", "what did we resolve last
month" and "how much of that was ticketed work" from the status page and the API,
without a metrics stack in between. The reasoning is in
[design/history.md](design/history.md); this page is how to run it and how to read it.

Off by default. Without it the tool behaves exactly as before: nothing at rest, no
database.

## Enabling it

History needs a PostgreSQL database and two settings.

```sh
export PATCHWRIGHT_HISTORY_DSN=postgres://patchwright@db.example.internal:5432/patchwright
```

```yaml
history:
  retention: 400d      # required: how long events and closed items are kept
  auth: azure          # optional: mint an Entra token per connection; default password
  lapseAfter: 3        # optional: absent assessments before an item lapses; default 3
  decommissionAfter: 7d # optional: how long a removed item stays gone before it counts as remediated; default 7d
  decommissionMaxLapses: 20 # optional: more not-running lapses than this in one run are never credited; default 20
```

The connection string is the credential, so it comes from the environment and its
presence is what switches history on. Where the password is kept apart from the
connection details, set `PATCHWRIGHT_HISTORY_PASSWORD` as well: it replaces whatever
the DSN carries, so the DSN can be plain configuration and only the password a
secret, with nothing URL-escaped into anything. Retention is required and deliberately not
defaulted: the record is a history of which services carried exploitable
vulnerabilities and for how long, and how long to keep that is a decision for
whoever owns the organisation's security records, not for a config file to inherit.
`serve` refuses to start with a DSN and no retention.

`auth: azure` is for Azure Database for PostgreSQL with Entra authentication. The
DSN names a user and no password; a token is minted before each connection using the
same identity chain registry authentication uses (workload identity in the cluster,
the CLI's login on a laptop). Nothing is stored.

The schema is created and migrated at startup. Migrations are numbered SQL files
embedded in the binary. The database user needs `CREATE` on the schema it connects
to, which on PostgreSQL 15 and later means granting it explicitly; see
[deploying.md](deploying.md#history).

If the database is unreachable the assessment still runs and the page still serves.
History reports itself unavailable, the log says why, and the next refresh tries
again. An outage of the record is not an outage of the queue.

## Restarts serve the last assessment

With a store configured, every successful assessment is also stored whole, as the
page, the API and the MCP tools serve it, and a starting process serves the newest
stored one while its own first run is in flight. A restart (an eviction, a config
reload, a rollout) no longer means twenty minutes of 503s: the pod is ready as soon as
it has read the store.

What it serves is labelled as what it is. `assessment.generated_at` stays the time the
stored assessment was made, so the page's "assessed N ago" is its real age, and
`assessment.loaded_from_store` is `true` until the first run in the new process
replaces it; the page adds "kept from before a restart". Nothing acts on it: tickets
are reconciled, and the history record written, only from an assessment the process
ran itself, and `POST /api/v1/tickets` answers 409 until one has. Reconciling Jira
against data from before a restart could close a ticket on the strength of a fix that
has since been rolled back.

The payload is gzipped JSON in `served_assessments`, and only the newest three are
kept. A real estate's findings are tens of megabytes of JSON and a few once
compressed. Each row records the build that wrote it and a payload schema version; a
row this build cannot read (another schema, or corrupt) is ignored with a warning in
the log, and the process starts the way it did before, waiting for its first run. So
does an unreachable database: the store is never a reason not to start.

Metrics are not restored. The gauges describe runs in this process, and stay absent
until the first one completes, as before.

The same stored assessment is what a split deployment's web replicas serve: with
`serve --role=worker` and `--role=web` (the chart's `split.enabled`), the worker stores
every assessment and the web replicas read the newest, and a `worker_state` row carries
the worker's heartbeat, whether it is running, and requests for a fresh run. See
[deploying.md](deploying.md#splitting-the-worker-from-the-page).

## What is recorded

The unit is the **work item**: an owner, a service, and what it upgrades to. It is
the same unit the queue page and a ticket use, so a queue row, a ticket and a history
entry are one thing. Deliberately, the version of the target is not part of the key:
a history that reopened an item every time upstream cut a release would report each
one as a lapse.

| Event | When |
|---|---|
| `opened` | The item first carried an actionable finding |
| `changed` | Its rule, priority, signals, target or CVEs moved while open. CVEs that left with evidence of remediation are recorded as cleared on it |
| `reassigned` | Its owner changed but the service and target did not. Not a close and an open |
| `ticket_raised` | Reconciliation created or extended a ticket covering it |
| `ticket_closed` | A ticket that covered it is no longer open, with whether patchwright had evidence the work was done at the time, and the reason when patchwright closed it itself (`upgrade-landed`, `not-running`, `no-longer-actionable`, `upgrade-clears-nothing`, `decommissioned`) |
| `resolved` | It left the queue **with evidence**: every image still reported, checked for a newer version, on the latest, with liveness reconciled. The test auto-close uses |
| `lapsed` | It left the queue without that evidence: no longer reported, no longer running, or the data to judge it missing |
| `decommissioned` | A lapsed item whose workloads were removed and stayed gone: see [remediated by decommissioning](#remediated-by-decommissioning). Dated when they disappeared |

A reader sees these two as **fixed (confirmed)** and **left without a fix**: the page,
the report caveats and the `trend_report` sentences use those words, while the event
kinds and JSON fields keep `resolved` and `lapsed`. The unit is the work item, one
service and the one upgrade that would fix it. Fixed (confirmed) and left without a
fix are never summed. A time-to-remediate that counted coverage loss as remediation
would improve fastest when the scanner broke.

### A ticket closes once

Each run keeps an open item's stored ticket list in step with the open-ticket index,
additions included, without recording a `changed` event. A ticket that leaves the
index is therefore recorded as `ticket_closed` once per item, not again on every run
it stays gone; one raised again and closed again is recorded again. When the index
cannot be read (a Jira error), the run records no ticket closes at all and leaves the
stored lists alone, and a warning is logged: an empty answer is not every ticket
closing. Earlier versions did repeat the close on every run; reports count at most one
close per item and ticket in the range, and the rows can be removed with the
[clean-up below](#removing-repeated-ticket-closes).

### CVEs cleared from items still open

An upgrade often clears the CVEs that mattered without clearing every CVE, so the item
stays in the queue, perhaps at a lower priority, and is never resolved. Its `changed`
event carries `cves_removed`, every CVE that left, and `cves_cleared`, the ones
credited as remediated, with `evidence`, `ticketed` and `tickets`: the tickets that
covered the item at the previous assessment, which is when the work was being done.

A CVE is credited only on evidence, the same standard a resolution holds, adapted to
an item that is still open. Between two consecutive assessments:

- the item was in both, and the run read every source (no cluster left out, no
  enrichment failed);
- every image was fully scanned in both, by the same source (the provider in both, or
  the same fallback in both; a vuln source in both or neither), so the absence is the
  scanner's answer about a new image rather than a different feed's;
- every image's liveness was reconciled as running in both, and it runs in no fewer
  accounts or namespaces than before, so nothing disappeared by being switched off;
- the running image was replaced: a digest or, without one, a reference the previous
  run did not have, in place of one this run does not.

Anything else is recorded with the CVEs in `cves_removed` and a `reason`, and counted
nowhere. A CVE that stays on the image but drops off KEV, or whose EPSS falls below
0.5, never leaves the item at all, so it is never cleared; the second is
`epss_decayed`, as before. The KEV and EPSS readings of a cleared CVE are those of
the image that was replaced.

Each movement period carries `cves_cleared`, `kev_cves_cleared` and
`epss_high_cves_cleared`: distinct CVEs cleared that period, **counting resolved items'
CVEs as well as those cleared from items still open**, so they are the figures to
quote for "KEVs resolved this month". `cleared_ticketed` and `cleared_unticketed` split
them by whether a ticket covered the item; a CVE cleared on both kinds of item that
period is ticketed, so the two sum to the total. `items_partly_cleared` is the items
that cleared CVEs while staying open. An item's CVE counts once, and again only after
it came back and cleared again, so a resolved item's final CVEs and its earlier partial
clears never count the same CVE twice. `cves_resolved` and `kev_cves_resolved` keep
their meaning, the CVEs of resolved items only, so nothing published before changes.

Periods are distinct within themselves; a CVE cleared from one item in March and from
another in April counts in both months. The report's `totals` counts each CVE once
across the whole range, and the page and `trend_report` read their range figures from
there rather than adding up periods.

Partial clears are recorded from the release that added them onward; there is no
backfill. The first assessment after upgrading stores each open item's scan state, so
the earliest credit comes from the second.

### Remediated by decommissioning

Switching a service off removes its risk as surely as upgrading it, so an item whose
workloads were removed is credited as remediated, once that removal has proved real.
An item that lapsed as **no longer running** (still reported, liveness reconciled, no
workload anywhere) becomes `decommissioned` when all of these hold:

- it has been gone for `decommissionAfter` (default 7 days), counted from the first
  assessment it was absent from;
- every assessment in that time recorded no source failure, the same test partial
  clears use, because a cluster nobody read looks exactly like one where nothing runs.
  A workload kind the live source is forbidden to list inside a cluster is not a
  failure, but it leaves every image not seen running unreconciled, which never lapses
  as not running;
- the live source was configured with the same clusters in the run the item was last
  seen in, in every run since, and in the judging run. Taking a cluster out of the
  source is no failure, yet every image on it stops running;
- it has not come back: not reopened under its own key, and its repository not in the
  queue under any other item since;
- nothing in the estate runs its repository now, under any owner, namespace or
  cluster, nor an image with one of the digests it last ran, and no such finding has
  unknown liveness. The same repository live elsewhere is a move, and the same digest
  under another repository a rename; neither is a removal.

One assessment lapsing more than `decommissionMaxLapses` items (default 20) as not
running marks every one of those lapses `not_creditable`, and none is ever credited.
Services are switched off a few at a time; that many at once is far likelier a change
in what liveness can see, such as a workload kind no longer counted as running or a
cluster's grants changing. Neither guard catches a change that affects one service at
a time, such as one namespace's workloads moving out of the source's reach, or a
rename that also rebuilt the image: those still look like a removal.

An item that lapsed because the provider stopped reporting it is never a candidate:
that is coverage lost while the workload may still run. Each lapse is judged once, by
the first assessment at or after its deadline, so the verdict cannot flip on a later
run. A run that cannot read the record it judges from records itself as unjudged and
the next run judges instead. A lapse no run judges within twice the window and a day
of disappearing (a worker stopped for longer than that) stays left without a fix.

Assessments recorded before this check existed have no live scope, so a lapse whose
window began before the upgrade is not credited; the first credits come a window
after it.

The `decommissioned` event is dated when the workloads disappeared and recorded only
once the window has passed, so it is credited to the period of the disappearance and
a period's figure can still rise for a week after it ends. It carries the item's
last-known snapshot (`closed`), so its CVEs are the ones that were switched off. Each
movement period has `decommissioned` with `items`, `items_ticketed`, `cves`, `kev` and
`epss_high`, split into `ticketed` and `unticketed` CVE tallies, and `remediated`,
which is `resolved` plus decommissioned items. An item's CVE that was already cleared
(a partial clear) is not counted again. `totals` counts each CVE once across the range
and adds `remediated_items` and `remediated_cves`, the distinct CVEs cleared or
decommissioned.

`lapsed` keeps its meaning: a decommissioned item was also counted as left without a
fix when it left the queue, and still is. Decommissioning is a later verdict on a
subset of those lapses, not a reclassification.

There is no backfill. Lapse events record their reason and last snapshot, and stored
assessments record whether they were partial, but nothing stored says whether the
image ran elsewhere, outside the queue, during a past window, so a past lapse cannot be
judged to the same standard. Lapses whose window ends after the upgrade are judged;
earlier ones stay left without a fix.

Ticket reconciliation reads the same credit: an open ticket whose every image was
decommissioned within the last two windows, and none of which is seen running now, is
closed as `decommissioned` through `closeTransitionNoLongerActionable` when nobody has
picked it up and the board sets that transition, and otherwise gets a single comment
saying so instead of the "coverage is missing" note.

### Absence is counted before it is believed

A scan provider's hourly responses are not identical: a handful of repositories
drop out of one and return in the next, and once in a while a whole slice goes
missing for a single call. Recording each as a lapse and a reopening would turn
provider jitter into movement, and the first day of the record did exactly that.

So an item that disappears **without evidence** is marked missing and counted, not
lapsed. It lapses only after `lapseAfter` consecutive absent assessments (default
three), and the lapse says how long it had been missing. An item that returns inside
that window writes nothing: as far as the record is concerned nothing happened.
Resolution with evidence is never delayed, because evidence is positive data rather
than absence. The open summary reports how many items are currently in that limbo
as `missing`.

Ticket reconciliation reads the same state: a ticket whose image left the queue
inside the grace period, whether absent, no longer running or no longer matching a
rule, is held rather than closed or commented on. The close follows on the run the
item lapses.

Each item's snapshot carries what a later question is likely to need: its rule,
priority and signals; its risk score and worst counts per severity; where it runs
(accounts and namespaces, kept raw so production can be told apart by whatever names
the estate uses); the upgrade's kind and target; the open tickets
covering it; and every distinct CVE it carries with severity, CVSS, EPSS, KEV and
fix availability. The `resolved` and `lapsed` events carry both the opening and the
closing snapshot, so "which CVEs did we fix" is on the event itself. CVEs arriving or
leaving while an item stays open are a `changed` event.

Each assessment also records the estate: severity totals over all unsuppressed
findings and over the actionable ones, distinct CVE, KEV and high-EPSS counts, the
risk score sum, median, p90 and maximum of the work items (and the same per class and
per team), the status page's headline summary as it stood, and the full work-item
list. The last two are deliberately more than the report reads today. Storage is
cheap and the record cannot be backfilled, so anything the page can say now can be
asked about historically, and a question nobody has thought of yet can be answered by
re-deriving from the items rather than from the events.

### Classified by the opening state

"KEVs resolved this month" and "EPSS above 0.5 resolved" classify each resolution by
what the item looked like **when the record first saw it**, not by its last state and
not by the current configuration:

- EPSS scores move daily. An item whose score fell from 0.6 to 0.4 has left the EPSS
  bucket with no patch applied. It is reported as `epss_decayed`, and when it later
  resolves it still counts as an EPSS resolution, because that is what it was when we
  found it.
- CVEs join KEV after the fact. That is a `changed` event and is counted as
  `became_known_exploited`.
- Both count once per transition, not once per `changed` event. An item's CVEs, and
  the KEV flags and EPSS scores on them, come and go with what a run could see: a run
  whose vuln source could not answer for an image records the item without that
  image's CVEs, and one whose exploit lookup failed keeps the CVEs without their flags
  and scores. Counting those events read every lapse in coverage as the item leaving
  KEV and the next complete run as a fresh entry, and `became_known_exploited` once
  stood at several times the number of KEV items. So leaving takes the evidence a
  cleared CVE takes: the CVEs that carried the signal count as gone only when the image
  they were last seen on was replaced, both runs scanned by the same source and
  running. Gone any other way, or in a run that missed a source, the item keeps its
  standing. A CVE still there with its KEV flag removed has left KEV, and one still
  there with a lower score has decayed, unless the item carries no EPSS score at all,
  which is the exploit feed not answering. A CVE fixed takes its signals with it, which
  is not a decay. An item counts again only after it really left and came back. This
  is read from the stored events, so past periods are corrected too: events recorded
  before snapshots carried their scan state cannot show a CVE was remediated, so a CVE
  leaving them never ends an item's standing. An item first seen in the range by a
  `changed` event is judged by that event's own signal moves.
- Rules are first-match-wins and get renamed. Signals (`kev`, `epss-high`,
  `fixable-critical`, `end-of-life`) are what rules are made of and do not depend on
  order, so the per-signal split is the one to compare month on month. The per-rule
  split is there for the sign-off report, which is keyed on rule names by design.
- Snapshots recorded before internet exposure was removed still carry an `exposure`
  field and an `exposed` signal. They are read as they are, so past periods keep the
  `exposed` row they had; no new item gains it, and losing it is not recorded as a
  `changed` event or counted among the items open now.

KEV is the headline exploited figure and EPSS sits beside it with that weight: one is
a fact that only grows, the other a forecast.

### Open work items by signal

Each risk point (the last assessment of a period) carries `open_by_signal`: the work
items open at that assessment, read from its stored work-item list, by signal. An item
carrying several signals would be counted several times by a plain tally, so each is
counted once, under the first of `kev`, `epss-high`, `fixable-critical` and
`end-of-life` that it carries. The four values therefore sum to the open items carrying
any of them and can be stacked; items with none, and the retired `exposed` signal, are
in no key. Every key is present, zero included, when the list was read; the field is
absent for a period whose last assessment has no stored list (recorded before lists
were kept, or unreadable, which the caveats then say). Unlike the movement splits this
is the item's state at the end of the period, not when it was first seen, so an item
whose EPSS decayed moves out of that band; `epss_decayed` and `became_known_exploited`
count those moves. Added without a schema version bump, like the tracker fields.

### Leaving a route's tickets out of the counts

A route set `countInAnalytics: false` (see [routing](ticketing.md#routing)) keeps
raising, reconciling and closing tickets as any route does, but its tickets are left
out of every ticket count the record serves: `tickets_raised` and `tickets_closed`,
the tracker's `tracker_tickets_raised` and `tracker_tickets_closed`, the cycle-time
medians, the closed-ticket ages and `/api/v1/history/tickets`. It is for a test or
sandbox epic whose tickets are not remediation work. Tickets are told apart by project
and the epic they are filed under, which the tracker read stores; the first sync after
upgrading reads the tracker in full once to learn the epic of tickets already held.

The report's `tickets_excluded` names the routes and says how many tickets it left out
and what each count would otherwise have included, the caveats say the same, and the
analytics page and `trend_report` state it beside the figures. A ticket on such a
route is not remediation work, so it does not make an item ticketed either:
`resolved_ticketed`, `cleared_ticketed` and `decommissioned.items_ticketed` count an
item as ticketed only when a ticket on a counted route covered it, so the ticketed
share cannot exceed the tickets the counts keep. Before the tracker has been read
nothing can be told apart, `tickets_excluded` is absent and the caveat says none was
left out.

### Total remediation against ticketed work

Four buckets, and a report shows all four:

| Bucket | Field | Meaning |
|---|---|---|
| Fixed (confirmed), never ticketed | `resolved_unticketed` | Landed by another route: an update bot, a Flux automation, a rebuild done in passing |
| Fixed (confirmed), ticketed | `resolved_ticketed` | Ticketed work completed. A **subset** of fixed, never a separate total |
| Ticket closed, finding open | `tickets_closed_finding_open` | A human closed the ticket and the old image still runs |
| Left without a fix | `lapsed` | Coverage loss or the workload went away. Excluded from every remediation figure, except the subset later credited as decommissioned |

`resolved_unticketed + resolved_ticketed` is total upgrades and patches. Remediation
by decommissioning is reported beside it, never inside it: `remediated` is the two
added together.

### Deadlines

When [`dueDays`](ticketing.md#configuration) gives tickets a due date, the date a
create set is recorded on its `ticket_raised` event and held on the item. When the
ticket closes, `ticket_closed` repeats `due_date` and adds `days_to_due` (the due date
less the close date in whole UTC days, negative when late) and `overdue`. A ticket
closed at any time on its due day is on time.

| Field | Where | Meaning |
|---|---|---|
| `tickets_closed_on_time` | per period | Closed on or before the recorded due date |
| `tickets_closed_overdue` | per period | Closed after it |
| `mean_days_to_due_at_close` | per period | Mean of `days_to_due` over those closes; negative is late. Absent when none had a due date |
| `tickets_overdue_open` | `open` | Distinct open tickets past their due date now, counted per ticket rather than per item |

Only the due date patchwright set is measured. A ticket raised before `dueDays` was
configured, or for a priority with no window, has none and is in neither on-time nor
overdue, so the two need not add up to `tickets_closed`. The date is never moved, so a
due date somebody edits in Jira afterwards is not what this measures against. An
extend does not carry a due date either: an item a ticket only came to cover later has
no deadline recorded against it.

### Tracker dates

The record knows when patchwright raised a ticket and when it saw one close. It does
not know when a person picked one up, and before the record began it knows nothing at
all. With ticketing configured, each run therefore also reads the tracker's own dates
for every ticket on the configured projects, closed ones included, into a `tickets`
table (see [ticketing.md](ticketing.md#dates-read-back-from-the-tracker) for exactly
what is read and when). A resolved ticket is pruned with the rest of the record once
its resolution is older than `retention`; an open one is kept.

Three things come of it, all marked as coming from the tracker by a `tracker` block
on the report (`source: "tracker"`):

| Field | Where | Meaning |
|---|---|---|
| `median_days_told` | per period | Work item opened, as the record first saw it, to ticket raised. Long means nobody was told |
| `median_days_to_start` | per period | Ticket raised to its first In Progress status. Long means told, not prioritised |
| `median_days_worked` | per period | First In Progress to resolved. Long means being worked, slowly |
| `tracker_tickets_raised`, `tracker_tickets_closed` | per period | Tickets created and resolved, by the tracker's dates |
| `closed_ticket_finding_open`, `closed_ticket_age_days` | `open` | Open items whose latest ticket closed while they stayed open and that have no ticket now, bucketed by days since the close |

Each median is over the tickets **resolved** in the period whose two endpoints are
known, with `_n` saying how many that is. The three are kept apart because each one
blames something different, and one number would flatter whichever part a team is good
at. `told` needs the ticket matched to a work item the record saw open: an item that
was already open when the record began has no known opening, so its tickets have no
`told` interval. A ticket that never passed through In Progress has neither of the
other two.

`tracker_tickets_raised` and `tracker_tickets_closed` are the backfill. Jira holds
created and resolution dates for every ticket since ticketing was switched on, so
these reach back before the record did. They count **tickets, not resolutions**: every
ticket of the configured issue type on the routes' epics, raised by patchwright or by
hand, with no rule or signal attached, because none can be attached with any
confidence. A route with no epic files at the project root, so its project is read
whole. The first production read had no epic scope and returned every Task three
projects had ever raised, which made the cycle time the backlog's; the scope is what
keeps these numbers about vulnerability work.
They sit beside `tickets_raised` and `tickets_closed`, which are events on work items
the record watched, and the two are not the same number. A period that ended before
the oldest ticket the tracker holds carries neither field, since that is before
ticketing, not a period in which nothing was raised.

`closed_ticket_finding_open` dates the third bucket of the delineation from the
tracker's resolution date. An item that has been ticketed again since is left out:
somebody is on it, whatever happened to the first ticket.

`GET /api/v1/history/tickets?since=90d` lists the same tickets by the day they were
created: every UTC calendar day of the range, a day with none included, each with the
tickets raised that day, their title, current status, the work item they matched and
a link to the tracker. It is always per day, whatever bucket the report uses, and the
first day is counted whole. The title is read with the dates; tickets last read before
it was stay untitled until the tracker is read in full, so run
`patchwright history backfill-tickets` once after upgrading.

## Reading it

The **Analytics** page opens with the report, so the page tells a story: how things
are moving, then what to do next. It shows the caveats first, the risk direction by
period, opened against fixed (confirmed) against left without a fix, with the unit
defined under the heading, the four-bucket delineation, a stacked bar per period of the
open work items by signal (each item under its most severe signal) with the EPSS decay
and newly known-exploited counts under it, and the queue as the record holds it now.
The movement panel carries a CVE line beside the fixed items: CVEs, known-exploited
CVEs and EPSS-above-0.5 CVEs cleared, including from items still open, ticketed and
otherwise, each counted once across the range.
The per-rule and per-team splits stay in the API and the MCP tool but are not drawn.
Once the tracker has been read, the ticketed panel adds a cycle-time table and the
tracker's own ticket counts, each only for the periods that have them, and a chart of
tickets created per day whatever the bucket: click a day, or pick it from the buttons
under the chart, for the tickets behind it.
A lookback and a bucket selector carry in the URL, so a view can be linked. With two
or more periods the direction, movement and signal panels draw interactive charts
(hover for each period's values) using a vendored copy of uPlot; with one period a
chart would be a single block, so the numbers stand alone. The
`trend_report` [MCP tool](mcp.md) answers the same questions in words.

`GET /api/v1/history?since=90d&bucket=month` returns the report; `since` takes a
number of days or an RFC 3339 timestamp, `until` defaults to now, `bucket` is `month`
or `week`. `GET /api/v1/history/item?key=…` returns one work item's every event. Both
are in the [API reference](api.md) and carry a `schema_version`, because the shape
will move and a consumer should be told rather than find out. Fields are added without a bump, as the tracker fields were; the version moves
when a field a consumer already reads would change meaning.

Every report leads with its caveats. The one to read first: **the record begins when
history was switched on.** Periods before that are empty because nothing was watching,
not because nothing happened. Three months after go-live there are three months.

## What it changes

**Data at rest.** With history enabled, [SECURITY.md](../SECURITY.md)'s statement that
no database is used stops being true. The record holds image references, CVE
identifiers, team names, versions and ticket keys: a history of which services carried
exploitable vulnerabilities and for how long, useful to an attacker and subject to
whatever retention applies to security records. No personal data. Retention is applied
after every assessment and what was pruned is logged. The latest few served
assessments are held as well (see above), which is the same data in the shape the
page serves it, and are replaced rather than retained.

**Backup** is the database's. That is the point of choosing one that is already
operated over a file on a volume: history cannot be reconstructed once lost, because
the estate no longer looks the way it did.

**Network.** The chart's NetworkPolicy needs an egress rule to the database, which is
usually not on 443. See [deploying.md](deploying.md).

## Operator tasks

### Removing repeated ticket closes

Versions before the fix above recorded the same `ticket_closed` on every assessment
until something else rewrote the item. Reports already count each close once, so this
is tidying rather than a correction, but the item page still lists the repeats. The
statement keeps the earliest close per item and ticket, and a later one only when a
`ticket_raised` for the same ticket on the same item sits between them. Run it in
`psql` against the history database; it stops before committing so the counts can be
checked:

```sql
BEGIN;

-- A close is a repeat when an earlier close of the same ticket on the same item
-- exists with no ticket_raised for that ticket between the two.
CREATE TEMP TABLE repeated_ticket_closes ON COMMIT DROP AS
SELECT c.id
FROM events c
WHERE c.kind = 'ticket_closed'
  AND EXISTS (
    SELECT 1 FROM events p
    WHERE p.kind = 'ticket_closed'
      AND p.item_id = c.item_id
      AND p.payload->>'ticket' = c.payload->>'ticket'
      AND (p.at, p.id) < (c.at, c.id)
      AND NOT EXISTS (
        SELECT 1 FROM events r
        WHERE r.kind = 'ticket_raised'
          AND r.item_id = c.item_id
          AND r.payload->>'ticket' = c.payload->>'ticket'
          AND (r.at, r.id) > (p.at, p.id)
          AND (r.at, r.id) < (c.at, c.id)));

-- Preview: how many rows the DELETE below will remove.
SELECT count(*) AS repeated_ticket_closes FROM repeated_ticket_closes;

DELETE FROM events WHERE id IN (SELECT id FROM repeated_ticket_closes);

-- Check the DELETE count matches the preview, then COMMIT; otherwise ROLLBACK.
```

Run it after the fixed version is deployed, or the next assessment may add another
repeat. It is safe to run more than once: a second run finds nothing.
