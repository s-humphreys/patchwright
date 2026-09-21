# Design: history, and reporting movement

Status: **phase 1 built** (the event log, the store, the API and retention; see
[docs/history.md](../history.md)). Phases 2 and 3 are not. Supersedes the storage
section of [persistence.md](persistence.md); the problem statement and the evidence
rule there stand.

One decision moved during the build: the item key drops the target **version** and
keeps only the target's name. The queue key includes the version so that two moves
are two rows; a history keyed that way would have closed and reopened an item every
time upstream cut a release, and reported each as a lapse. The version is carried in
the snapshot and a change to it is a `changed` event.

## The ask

Security want to see, month on month with a three-month lookback:

- the direction of risk across the estate;
- what is being resolved, in the terms the policy rules already use: known-exploited
  CVEs resolved this month, EPSS above 0.5 resolved, end-of-life bases retired;
- a clear line between everything that got patched or upgraded and the ticketed work
  that was completed.

Every assessment is a snapshot, so none of this can be answered today. The
persistence note explains why and proposes an event log. This note decides where it
lives and how it is surfaced, and changes two of that note's answers.

## Principles

**Available from the tool, not from a metrics stack.** The aggregates are exported to
Prometheus and that is the right place for alerting. It is the wrong place for this
feature, because a trend that only exists once someone has deployed Prometheus,
granted Grafana access and built a dashboard is a property of one cluster rather than
of patchwright. Anyone running the binary against a database connection should get
the report from the status page and the API, with the same authentication and the
same numbers as the queue. Prometheus keeps its gauges as a side effect.

**Movement is derived from events, never from snapshots.** A stored copy of each
assessment can be diffed, but the diff would re-derive the lifecycle every time and
could not carry what a finding looked like when it was first seen. An append-only
record of transitions is small, bounded by the estate rather than by time, and is the
only shape that keeps the evidence rule honest.

**The same unit as the queue.** Everything is keyed on the work item
(`group.Item.Key`: owner, service, upgrade target), because a queue row, a ticket and
a history entry must be one thing. Counts are in work items, with distinct CVE counts
stated beside them where a CVE is what was asked about. Two numbers for one question
is the confusion `exploit.go` already documents.

## Events

| Event | When | Recorded with it |
|---|---|---|
| `opened` | The key first carries an actionable finding | Rule, priority, signals, risk score, oldest CVE date, the images |
| `resolved` | It stopped, with evidence | Which images, on what version, the evidence string |
| `lapsed` | It stopped without evidence | Why: not reported, workload gone, coverage lost |
| `changed` | Rule, priority, signals or risk score moved while open | The new values |
| `reassigned` | The owner changed but service and target did not | Old and new owner |
| `ticket_raised` | Reconciliation created or extended a ticket for it | Key, project |
| `ticket_closed` | A ticket covering it reached a done status category | Key, whether patchwright had evidence at the time |

`resolved` uses exactly the test ticket auto-close uses (`upgradeComplete`): every
image still reported, remediation checked, versions resolved, no upgrade still
available for the repository, liveness reconciled. Anything short of that is
`lapsed`, and the two are never summed. A time-to-remediate that counts coverage loss
as remediation improves fastest when the scanner breaks.

### Classify by what it was when it opened

The `opened` event snapshots the rule, priority and signals. Reports of "KEVs resolved
this month" and "EPSS above 0.5 resolved" classify each resolution by that snapshot,
not by the finding's last state and not by the current configuration.

This is the decision that keeps the numbers worth reading:

- EPSS scores move daily. A finding whose score decays from 0.6 to 0.4 has left the
  "EPSS above 0.5" bucket with no patch applied. Classified at close, that counts as
  an EPSS resolution. Classified at open, it does not.
- CVEs join KEV after the fact. Classified at open, a resolution on a finding that
  became known-exploited while open is reported as a KEV resolution only if a
  `changed` event says it did, and the report can say so.
- Rules get renamed and reordered. Rule order is first-match-wins, so a finding both
  `exploited-fixable-critical` and `exploited-fixable` match records only the first.
  Signals (`kev`, `epss_high`, `end_of_life`, `fixable_critical`, `exposed`) are what
  rules are made of and do not depend on order, so the signal columns are what a
  monthly comparison should be built on. Rule names are recorded for the sign-off
  report, which is keyed on them by design.

KEV is the headline exploited figure and EPSS sits beside it, with that weight: KEV
is a fact that only grows, EPSS is a forecast. A finding that leaves the EPSS bucket
because its score decayed while open is recorded as its own line in the report. It is
not remediation and it is not hidden either, because how much of the urgent queue is
moving on its own is something security should see.

### Priority is recorded, not inferred

In this estate `minPriority: urgent` means the only ticketed work is the work the two
KEV/EPSS rules caught, so "ticketed work completed" and "exploited work completed"
are the same set today. That is an accident of configuration. The event carries the
priority and whether a ticket was raised, so a change to `minPriority` changes what
gets ticketed from that month on and does not rewrite the past.

## The delineation

Four buckets fall out of the events, and a report shows all four:

| Bucket | Meaning |
|---|---|
| Resolved with evidence, never ticketed | Landed by another route: an update bot, a Flux automation, a rebuild somebody did in passing. This plus the next row is "total upgrades and patches" |
| Resolved with evidence, ticketed | Ticketed work completed. A subset of the row above, never a separate total |
| Ticket closed, finding still open | A human closed the ticket and the old image still runs. Neither resolved nor lapsed |
| Lapsed | Coverage loss or the workload went away. Reported, and excluded from every remediation figure |

A dashboard that shows only the first two is the failure mode to design against.

## Storage

**PostgreSQL, off cluster, behind an interface, off by default.**

The persistence note chose SQLite on a PersistentVolumeClaim and gave two reasons: a
single writer, and not wanting the tool to become something you operate. The first
still holds and is not the constraint. The reasons SQLite is wrong here are
operational:

- History cannot be reconstructed once lost, because the estate no longer looks the
  way it did. A PVC has no backup story unless one is built. A managed database
  already has point-in-time restore and someone operating it.
- An Azure Disk volume pins the pod to one zone. The Trivy cache tolerates that
  because losing it costs a download.
- Retention on a record of exploitable weaknesses is a policy someone will have to
  attest to. That is easier to show and audit on a managed service than on a file
  inside a pod.
- Replicas stop being blocked.

The "something you operate" objection is answered by using a database the
organisation already operates. For deployments that do not, the feature is off and
the tool behaves exactly as it does today: no schema, nothing at rest. There is no
SQLite driver. Two engines is two sets of SQL to keep correct, and the case for a
zero-dependency local store is met by the feature being optional.

- **Driver**: `pgx`. A new dependency, and the only one.
- **Migrations**: numbered SQL files embedded in the binary and applied at startup
  against a version table. No migration library.
- **Credentials**: Entra workload identity to Azure Database for PostgreSQL,
  following `registryAuth.azure.workloadIdentity`. A password in the environment
  remains possible for other deployments. Never in the config file.
- **Network**: the chart's NetworkPolicy needs an egress rule for the database.
- **Writer**: the `serve` process, after each assessment and after each ticket
  reconciliation. One replica and `concurrencyPolicy: Forbid` still make it the only
  writer; the schema tolerates a second one by keying events on
  `(item_key, kind, assessment_id)` so a replayed run inserts nothing twice.

### Schema, in outline

```
assessments   id, started_at, finished_at, provider_data_age, coverage counts
items         key, repository, class, team, upgrade_kind, first_opened_at
events        id, item_key, assessment_id, kind, at, payload jsonb
```

`payload` carries the per-kind columns from the events table above. Everything a
report needs is a query over `events` by month; a rollup table is not required at
this volume and is not built until a query is shown to need it.

Rows hold image references, CVE identifiers, team names and versions. No personal
data, unless a ticket assignee is ever stored, which this design does not do.

## Surface

**Status page.** A history section beside the analytics view, default range ninety
days, bucketed by calendar month: risk score over time; opened, resolved and lapsed
per month; resolutions by signal and by rule; the four-bucket delineation; per-team
versions of each. The page is plain ES modules with a `charts.js` already, so this is
an extension rather than a framework choice.

**API.** `GET /api/v1/history?since=90d&by=month` and `GET /api/v1/history/items?key=`
serve the same data the page draws, from the same code. The response carries a
`schema_version`, because the shape will move and a consumer should be told rather
than find out. Exposed from the first release: the monthly pack for security should
be reproducible from a URL, and the MCP tools need it.

**MCP.** `trend_report`: is this getting better, in words, with the caveats first,
bucketed the same way. Pairs with `policy_report` and `exploitability_report`, which
report a day and say so.

**Prometheus.** Gauges for risk score (`sum`, `p50`, `p90`, `max`), per-rule counts
evaluated independently of match order, and per-signal counts by state. Useful for
the operators' alerting, and nothing the security report depends on.

## What this changes about the tool

- **SECURITY.md** says no database is used and nothing is written to disk beyond the
  cache and a short-lived credential. With history enabled, neither is true. It needs
  the data-at-rest table extended, the classification stated, and a retention
  setting documented before this is switched on anywhere.
- **Retention** is a configuration value with no default that is silently forever.
  Whoever owns the organisation's security-records policy sets it; the tool prunes
  to it on each run and reports what it pruned.
- **Backup** becomes the database's problem, which is the point of the choice.
- **Startup** must degrade rather than refuse. If the database is unreachable the
  assessment still runs and the page still serves, with history marked unavailable
  and an error surfaced, so an outage of the record does not become an outage of the
  queue.

## Phases

1. **Event log and API.** Storage interface, Postgres driver, migrations, the events
   above emitted from the refresh and ticket paths, `/api/v1/history`, retention.
   Also the Prometheus gauges, since they cost little and start the operators' own
   clock.
2. **Page and MCP.** The history section and `trend_report`, over the API.
3. **Tracker dates.** Fetch `created` and `resolutiondate`, index closed tickets, so
   the three intervals in the persistence note (told, prioritised, worked) can be
   reported and the "ticket closed, finding open" bucket has a date.

### Backfill, plainly

Nothing exists to backfill the estate side. Three months after go-live security will
have three months; before that the report says how much it has. The ticketed side is
different: Jira already holds created and resolution dates for every ticket on the
configured epics, so phase 3 can reconstruct ticketed-work history from the day
ticketing was switched on. It cannot attach a rule or signal to those tickets with
any confidence, and should not try. That history is reported as tickets, not as
resolutions.

## Considered and deferred: a separate UI deployment

The page serves from process memory, and readiness means an assessment is cached.
Every frontend change therefore redeploys the worker, and the page serves nothing
until the new pod has assessed every cluster, which can be most of the startup
budget. A scan that runs out of memory takes the page down with it.

Splitting the UI from the worker would fix both, and is not done here. The UI would
have to read the assessment from somewhere other than memory, which means the whole
assessment at rest in the database or an internal API between two processes. That is
a larger change to the security posture than the event log, and a richer page does
not need it: charts are client-side work over JSON the API already serves.

When the rollout coupling starts to hurt, the step before a split is to persist the
latest assessment as a single document so a new pod serves the previous one while it
runs its own. That removes most of the pain with one table, and makes a later split
small, because the UI would already be reading from the database.

## Decisions to sign off

1. **Identity.** The work item key changes when ownership or the upgrade target
   changes. This design records `reassigned` for the first and treats the second as a
   close and an open, on the grounds that a new target is new work. A team
   reorganisation therefore does not show as a remediation spike; a base image
   changing line does.
2. **Retention.** Set by security, not by this document. The tool refuses to enable
   history without a value.
3. **API exposure from day one**, versioned, rather than page-only until the shape
   settles.
4. **No SQLite driver.** Optional feature, one engine.
