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

## What is recorded

The unit is the **work item**: an owner, a service, and what it upgrades to. It is
the same unit the queue page and a ticket use, so a queue row, a ticket and a history
entry are one thing. Deliberately, the version of the target is not part of the key:
a history that reopened an item every time upstream cut a release would report each
one as a lapse.

| Event | When |
|---|---|
| `opened` | The item first carried an actionable finding |
| `changed` | Its rule, priority, signals or target moved while open |
| `reassigned` | Its owner changed but the service and target did not. Not a close and an open |
| `ticket_raised` | Reconciliation created or extended a ticket covering it |
| `ticket_closed` | A ticket that covered it is no longer open, with whether patchwright had evidence the work was done at the time, and the reason when patchwright closed it itself (`upgrade-landed`, `not-running`, `no-longer-actionable`) |
| `resolved` | It left the queue **with evidence**: every image still reported, checked for a newer version, on the latest, with liveness reconciled. The test auto-close uses |
| `lapsed` | It left the queue without that evidence: no longer reported, no longer running, or the data to judge it missing |

Resolved and lapsed are never summed. A time-to-remediate that counted coverage loss
as remediation would improve fastest when the scanner broke.

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

### Total remediation against ticketed work

Four buckets, and a report shows all four:

| Bucket | Field | Meaning |
|---|---|---|
| Resolved, never ticketed | `resolved_unticketed` | Landed by another route: an update bot, a Flux automation, a rebuild done in passing |
| Resolved, ticketed | `resolved_ticketed` | Ticketed work completed. A **subset** of resolved, never a separate total |
| Ticket closed, finding open | `tickets_closed_finding_open` | A human closed the ticket and the old image still runs |
| Lapsed | `lapsed` | Coverage loss or the workload went away. Excluded from every remediation figure |

`resolved_unticketed + resolved_ticketed` is total upgrades and patches.

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
period, opened against resolved against lapsed, the four-bucket delineation, the
per-signal, per-rule and per-team splits, and the queue as the record holds it now.
Once the tracker has been read, the ticketed panel adds a cycle-time table and the
tracker's own ticket counts, each only for the periods that have them, and a chart of
tickets created per day whatever the bucket: click a day, or pick it from the buttons
under the chart, for the tickets behind it.
A lookback and a bucket selector carry in the URL, so a view can be linked. With two
or more periods the direction and movement panels draw interactive charts (hover for
each period's values) using a vendored copy of uPlot; with one period a chart would
be a single block, so the number stands alone. The
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
after every assessment and what was pruned is logged.

**Backup** is the database's. That is the point of choosing one that is already
operated over a file on a volume: history cannot be reconstructed once lost, because
the estate no longer looks the way it did.

**Network.** The chart's NetworkPolicy needs an egress rule to the database, which is
usually not on 443. See [deploying.md](deploying.md).
