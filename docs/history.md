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

Ticket reconciliation reads the same state: a ticket whose image is absent from this
assessment but was reported inside the grace period is held, rather than told its
coverage is gone.

Each item's snapshot carries what a later question is likely to need: its rule,
priority and signals; its risk score and worst counts per severity; where it runs
(accounts and namespaces, kept raw so production can be told apart by whatever names
the estate uses); its exposure; the upgrade's kind and target; the open tickets
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
  `fixable-critical`, `end-of-life`, `exposed`) are what rules are made of and do not
  depend on order, so the per-signal split is the one to compare month on month. The
  per-rule split is there for the sign-off report, which is keyed on rule names by
  design.

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

## Reading it

`GET /api/v1/history?since=90d&bucket=month` returns the report; `since` takes a
number of days or an RFC 3339 timestamp, `until` defaults to now, `bucket` is `month`
or `week`. `GET /api/v1/history/item?key=…` returns one work item's every event. Both
are in the [API reference](api.md) and carry a `schema_version`, because the shape
will move and a consumer should be told rather than find out.

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
