# API

`patchwright serve` runs the assessment on a schedule, caches the result, and serves
it read-only over HTTP with a live-status page.

```sh
patchwright serve -i export.csv -c config/ --addr :8080 --interval 1h \
  --live-source kube --live-option contexts=aks-prod --remediation
```

Full reference: [`docs/api/openapi.yaml`](api/openapi.yaml), browsable at
[the published API reference](https://patchwright.shumphreys.com).

| Endpoint | Purpose |
|---|---|
| `GET /` | Status page: coverage, per-class and per-team breakdown, the queue, ticket state |
| `GET /analytics` | What to fix first: the rebuilds that clear the most, and what nobody is acting on |
| `GET /api/v1/findings` | Findings, filterable by `owner_class`, `team`, `priority`, `actionable`, `live`, `upgradable`, `known_exploited`, `suppressed`, `provider_assessed`, `remediation_checked`, `upgrade_resolved` |
| `GET /api/v1/finding?image=<ref>` | One image's finding |
| `GET /api/v1/owners` | Per-team triage: where the fix goes, how much is ticketed, and how much of it is the sharp end (`urgent`, `known_exploited`, `exposed`, `end_of_life`) |
| `GET /api/v1/summary` | Fleet headline, coverage counts, and `unassessed_reasons` |
| `GET /api/v1/analytics` | What to fix first: base upgrades ranked by what they clear, the classes of problem nobody is acting on, and per-owner responsiveness |
| `GET /api/v1/config` | The ownership and policy rules as parsed at startup |
| `POST /api/v1/assessments` | Trigger a refresh |
| `GET /api/v1/tickets` | What ticket reconciliation would do. Changes nothing |
| `POST /api/v1/tickets` | Apply it. Requires `{"confirm": true}` |
| `GET /metrics` | [Prometheus metrics](metrics.md) |
| `GET /healthz`, `GET /readyz` | Health; ready once a first assessment is cached |

## Authentication

Set `PATCHWRIGHT_API_TOKEN` and every request except the health probes and
`/metrics` requires it. Programmatic clients send `Authorization: Bearer <token>`;
browsers are prompted for HTTP Basic with the token as the password. The status page
is gated too — it is a data view.

A shared token has no identity and no per-team scoping: everybody holding it is the same
person, and nothing anyone does can be attributed. For per-user sign-in, set an OIDC
issuer and the page gains a real sign-in flow, with the token still available to scripts
alongside it. See [authentication](authentication.md).

## Ticket state

Given a `jira:` block and credentials, each refresh indexes the project's open
tickets — one JQL query per configured project, not one per image — and returns them
alongside findings as `tickets`, keyed by image repository. Without the config or
credentials the key is absent, meaning *unknown* rather than "no ticket exists".

Writes are opt-in: `--auto-ticket` applies the plan on every refresh, and the
endpoints work either way. Every refresh logs the plan whether or not it will be
applied.

## Pending ticket actions on the page

Its own page, at `/tickets`, linked from the shared header.

It sat above the queue originally, where it was impossible to miss and, on a page whose
subject is the estate, usually beside the point. A separate page rather than a third tab
because the other two tabs are two ways of reading the same findings, and this is a
different subject that happens to be produced by the same service. The dashboard no longer
queries the tracker on load at all.

The page lists changes reconciliation would make, in plain terms — "Raise a new ticket",
"Rewrite the summary and description", "Close it", "Comment: the work may already be
done" — with the ticket each concerns and why. The internal action name is in the hover,
for matching a row to a log line.

Skips and holds are counted rather than listed: one is already correct, the other writes
nothing while waiting on data, and neither answers "what is about to change?". The banner
says whether a scheduled refresh will apply the rest.

Read-only: there is no apply button. A POST that writes to a tracker should not be one
click away from a dashboard behind a shared token. It refreshes on demand rather than
with the page's polling, because computing the plan queries Jira.

## Filtering on the page

One filter bar, governing every view. It sits above the tabs, so it has to mean the same
thing in both: the queue, the grouped-by-service view and the CVE view all render the same
surviving set of findings. The CVE view aggregates what survived rather than the estate,
which is what "the CVEs affecting payments" means.

The options are **faceted**: each dropdown is built from the rows that pass every *other*
filter. So the count beside an option is what choosing it would give you, an option that
could only return nothing is not offered, and narrowing one filter visibly narrows the
rest.

Two deliberate edges:

- A selection that stops matching — because an hourly refresh brought different findings —
  is kept and shown as `(0)` rather than silently cleared. Dropping somebody's filter
  changes what they are looking at without telling them, and leaves the URL describing a
  state the page is not in.
- A link naming a combination with nothing behind it renders empty, with the count saying
  `0 of N findings`. The dangerous alternative is the whole estate under controls that
  appear to narrow it.

Every control is in the query string, including which view is showing, so any filtered
view is a link somebody can send.

## Data gaps on the page

What the assessment cannot tell you is stated once, in a single panel above the tiles:
one line per gap with its count and consequence, and the explanation behind a toggle.

Gaps are ranked rather than shouted equally. A missing vulnerability source is severe
because it disables whole priority tiers — nothing can be urgent, however bad it is —
whereas 4% of images unassessed is worth a line, not a colour. Severity follows the
proportion affected, so the same gap reads differently on an estate where it covers
everything.

The lines are never hidden, only the prose. A gap nobody can see is the failure the
section exists to prevent.

## Rules on the page

"Show config" on the status page reveals the ownership and policy YAML the
assessment was run with, so "why is this not actionable?" is answerable without
repository or cluster access. It is the text parsed at startup, not the files as they
are now — re-reading them would show edits that are not in effect.

Values of keys that look like credentials are replaced with `[redacted]`. Nothing
should match, since credentials come from the environment, but the cost of being
wrong is a credential in a browser tab.

## Coverage on the page

The breakdown rolls up per owner class, with teams beneath, and states every count
as a share of a named denominator. Classes with more than one team expand. The
`CVEs` column splits by severity on click, and reads `?` where nothing in the row
was assessed.

## Signals

Each finding carries a `signals` list — `exposed`, `kev`, `in-flight`, `stale-fix`,
`unassessed`, `suppressed` — and the queue renders it as one column of badges rather
than a column per attribute. The same set is available to rules, so a signal can change
the ordering instead of only being readable.

Every signal is a positive statement. The absence of one asserts nothing: no `exposed`
covers both an internal workload and one whose reachability nobody reported, which is
why `exposure` is a separate three-valued field (`public`, `internal`, `unknown`).

## Who is carrying the sharp end

`GET /api/v1/owners` answers "who has the most work". That is not the question a security
reviewer asks, which is closer to "how many exploited or urgent findings has each team got
in its name" — and the two come apart. A team with 300 findings and no KEV needs a
different conversation from a team with three, two of them exploited and one on a runtime
nobody maintains. The totals cannot tell those apart.

So each owner row also carries, as counts of findings rather than of CVEs:

| Field | Means |
| --- | --- |
| `urgent` | Policy rated it urgent |
| `known_exploited` | Carries a CVE in CISA's KEV catalogue: confirmed exploitation, not a prediction |
| `exposed` | On a workload something reported reachable from the internet |
| `end_of_life` | Built on a line nobody maintains, so no future fix reaches it |

Counts of findings, because a finding is what gets assigned, tracked and fixed; a CVE
count would make one badly-scanned image outrank a team's whole estate.

`end_of_life` is the odd one out and deliberately reported separately: every other count
here falls when somebody rebuilds. That one falls only when somebody migrates, so a team
with three of them has a quarter's work, not an afternoon's.

Suppressed findings are excluded, as they are from every other number in these rows. A
suppression is a decision that something is out of the queue, and quietly counting it in
the urgent column would relitigate that decision in a dashboard.

On the page these appear as columns in the breakdown, and each count is a link that
applies the filters behind it and switches to the queue — the question after "how many" is
always "which ones", and retyping a team name into a filter by hand is how a good number
becomes a dead end. A zero is rendered as a dash rather than a link: offering to show
nothing is worse than saying there is nothing.

## Aggregated endpoints

Three views of one assessment, all filterable with the same parameters as
`/api/v1/findings`:

| Endpoint | Answers |
| --- | --- |
| `GET /api/v1/items` | The queue as work items: one per team, service and upgrade target — the same key a ticket uses. |
| `GET /api/v1/service?repository=X` | One service's outstanding work, for a catalogue component page. |
| `GET /api/v1/cves` | The estate by CVE, worst first, with how far each reaches. |
| `GET /api/v1/cve?id=CVE-…` | One CVE and every image carrying it. |

They exist so a consumer never has to aggregate for itself. On a real estate the
findings payload is around 40 MB, and a component page that pulls it to sum a handful
of numbers is both slow and a second implementation of these rules that will drift from
this one.

Each aggregate states its own limits, because an aggregate is where a report starts
lying:

- `priority` is the worst across an item's deployments, and `priority_where` names where
  it came from. The same image is routinely urgent in production and medium in
  development; "urgent" alone discards the distinction the policy drew.
- `assessed_images` short of `deployments` means `critical` and `high` are the worst
  KNOWN rather than the worst.
- `in_flight_checked` is true only when every deployment was checked.
- `scanned_findings` and `total_findings` travel with every CVE response. Per-CVE detail
  exists only where a vuln source ran, so zero CVEs over zero scanned findings means
  nothing was looked at rather than nothing found.
- `known: false` from `/api/v1/service` means this assessment has no finding for that
  service at all. An empty item list with `known: false` is ignorance, not health.

CVEs report both `images` and `services`, because they answer different questions: how
many deployments carry it, and how many pieces of work fixing it takes. One base-image
CVE on hundreds of images is a handful of rebuilds.

The grouping is implemented twice — in Go here, and in the browser so the queue filters
instantly — and `testdata/grouping.json` plus `testdata/grouping.expected` hold both to
the same expectation, checked in the Go tests and the page tests. Two implementations of
one rule drift silently, since both keep returning plausible numbers.

## Views

The status page shows the same assessment two ways, as tabs, with the view in the URL:

- **Queue** — grouped by service (team, repository and upgrade target) so one row is
  one piece of work: rebuilding a service and promoting it through its environments.
  On a real estate most findings collapsed away into shared items, so most of the queue was the
  same work listed again. A grouped row reports the WORST of its deployments and names
  where that came from ("urgent in Production NA"), marks partial provider coverage
  rather than averaging it away, and only claims a check ran when it ran for every
  deployment. Selecting the row lists them, and selecting one of those drills into it.
  Untick "group by service" for the flat per-deployment list, which is what you want
  when asking where something runs rather than what to do about it.
- **Queue (ungrouped)** — by image, five columns: urgency, severity, the image with its owner and
  namespace, the fix, and whether anything is already in progress. Selecting a row opens
  a panel with everything else, including every CVE on that image.
Both views drill and come back. A CVE lists the images carrying it and a work item lists
its deployments; selecting one of those opens that finding, with a named button back to
where you came from. An image in a CVE's scope that a queue filter is hiding says so on
click rather than doing nothing.

- **CVEs** — by CVE, ranked KEV first, then severity, then exploitation pressure, then
  how many images carry it. Selecting a CVE lists every affected image, the teams
  involved, and where a fix exists. This is the scope-of-work question, which the queue
  can only answer by reading every row.

The CVE view is aggregated in the browser from the findings the API already returns, so
there is no second endpoint that could disagree with the first. It needs a vuln source:
the scan provider reports severity totals rather than individual CVEs, so without
`--vuln-source` the view says so rather than showing an empty list.

## Analytics

`GET /api/v1/analytics` answers a different question from the queue. The queue says
what is wrong; this says what to do first and what nobody is acting on.

Three parts:

- **`wins`** - base upgrades ranked by the CVEs they remove across every image on
  that base, with the services affected. Most of the leverage in an estate is here
  rather than per-team: one rebuild fixes everything built on that base, and images
  are counted per image rather than per finding so one image owned by three teams
  is one rebuild.
- **`issues`** - classes of problem nobody is acting on, grouped by what the problem
  IS rather than by owner, because each needs a different response. Known-exploited
  with a fix nobody started is not the same conversation as known-exploited with no
  fix available. Empty categories are omitted.
- **`teams`** - per-owner responsiveness: age percentiles, work not started, pull
  requests in flight, tickets, KEV, EPSS, and how much of that owner's queue a base
  rebuild would clear.

Read **`notes`** before building anything on this. It lists the questions the
endpoint is asked and cannot answer, and it travels in the payload rather than only
on the page because a consumer needs the gaps as much as the page does. Ticket
resolution time is the notable absence: the tracker index holds only open tickets
and carries no dates, so a pilot can be reported as adopted but not as faster.

Nulls are meaningful throughout. `median_age_days` is null when nothing is dated,
which is not zero - "no age source ran" and "everything was found today" are
different states and only one of them is good news.

## Getting the queue out of the page

The status page filters are multi-select and travel in the URL, so a narrowed view
is a link somebody can send: `?view=cves&signal=kev,exposed&team=orders`. Several
values within one filter mean ANY of them; the filters are still ANDed with each
other.

**Export CSV** beside the queue count writes the rows currently on screen, in
whichever view is showing, with the filters applied - which is the point, since the
reader has usually already narrowed to the thing they were asked about. The
findings export carries the columns somebody would filter or pivot on, including
EPSS and its percentile.

For anything scripted, use the API instead: the page's export is what a person
reaches for mid-question, not a data feed.
