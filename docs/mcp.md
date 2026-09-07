# MCP: asking the estate questions

`patchwright serve` also speaks the [Model Context Protocol](https://modelcontextprotocol.io)
at `/mcp`, so an LLM client can ask the questions people already ask - *what does the
payments team need to fix?*, *what would rebuilding storefront's base actually clear?* -
and get them answered from the assessment rather than from a screenshot somebody
pasted.

It is the same process, the same cached assessment and the same authentication as the
API. There is no second deployment, no second copy of the config, and a tool answer is
exactly as fresh as the page is, because it is the same object.

## Tools

All read-only. Each is one question somebody actually asks, answered completely,
rather than a wrapper around an endpoint - a model given a REST client asks three
calls and a join to learn what a page shows at a glance, and gets the join wrong often
enough to matter.

| Tool | Answers |
|---|---|
| `fix_plan` | **What to DO about one service.** For somebody holding a ticket: the change, what not to do and why, what it achieves, and which of the remainder was never their team's |
| `estate_summary` | The headline: size of the problem, how much of it rebuilds would clear, the biggest wins, and what nobody is acting on |
| `service_report` | Everything about one service: deployments, image age, the upgrade it needs, and exactly what that upgrade clears, leaves and introduces |
| `worst_first` | The work queue, worst first, filterable by team, priority and exposure |
| `team_report` | One team's whole position, including what is already in flight and what is merely open and stale |
| `explain_cve` | One CVE across the estate: who carries it, whether any of them is exposed, and where a rebuild removes it |
| `policy_report` | **The estate against your OWN rules**, by their names in your config: what each caught, what each suppression holds and when it lapses, and what no rule speaks to. For a periodic review or sign-off |
| `exploitability_report` | **What is actually being exploited, and how much is fixable.** KEV and high-EPSS CVE counts with their fixable share, per team beside each team's urgent count, worst CVEs named |
| `list_facets` | The vocabulary: every team, class, priority, exposure and signal that appears, with counts |

**A service answers to any name that identifies it.** The bare repository
(`storefront`), the path (`apps/storefront`), the registry-qualified form
(`reg.example/apps/storefront`), or a full reference with its tag or digest still
attached, as pasted out of a ticket. The qualified form matters most: it is what
`estate_summary` prints, and a name one tool hands out that another will not accept is
a dead end an agent reads as "no such service", one step from "nothing to do here".

An exact identity always beats the forgiving match on a trailing path segment, so
asking for `agent` returns the service called `agent` rather than every image whose
path happens to end that way. Where a name genuinely covers more than one image, the
report says so and names them, instead of quietly reporting three products as one.

`fix_plan` is the one an engineer reaches for. It carries the same data as
`service_report`, shaped as an instruction rather than a dataset - which is the whole
difference, because a report hands over clears, leaves, introduces, a remainder split and a
policy rule, and leaves somebody to work out which of it they are supposed to act on.

```
storefront - insights
why      urgent, internet-facing, 10 known-exploited CVEs, 6,746 vulnerabilities
         across 3 deployments (rule: exploited-fixable-critical)

do       change the base image this is built on
         from  docker.io/python@sha256:3966b818...
         to    docker.io/python:3.12.14      (a version change, not a rebuild)
         yours: yes, across Development US, PreProduction US, Production US
         repository: https://dev.example/org/proj/_git/storefront

do not   go to 3.14.7, the newest available. Policy holds this line at 3.12:
         "the analytics toolkit's dependencies are not 3.14 ready (data team, Aug 2026)"

result   clears 5,857 of 6,746, including all 10 known-exploited
         introduces 296
         880 not yours: still in the new base, upstream's to fix
             linux-libc-dev (518), binutils (57), libbinutils (57) ...
         9 still yours: introduced by the build, so fixable in the repository
             CVE-2026-4171 (critical, fix 2.31.1), CVE-2026-3980 (high, fix 1.4.2),
             CVE-2026-2255 (high, no fix published) ...
         verify: afterwards expect about 1,185 rather than 6,746, with 10 of
                 10 known-exploited gone. A remainder is expected.
         known_exploited: CVE-2025-48384 (cleared), CVE-2026-31431 (cleared) ...

also     reporting-tools takes the same move

unknown  which repository holds the build that sets this
         whether anybody has started
```

Three parts of that are there because of how the answer gets used. The **reason** behind a
ceiling, because "there is a 3.14, why am I being told 3.12" is the first thing anybody
asks and the answer was written by a colleague who knew. Whether the change is **yours**,
because 26 findings on one estate are owned by a chart or an operator and editing the build
would do nothing. And **what was never yours**, because a ticket closed with 880
vulnerabilities left on the service gets reopened unless somebody can say why those 880 are
an upstream wait.

Three of those exist because the reader may be a coding agent rather than a person.
**`repository`** is where the change goes, read from the image's own labels - patchwright
reads images, not the code that produced them, so the build has to say. The keys are
configuration, `remediation.base.repoLabels`, because they belong to the CI system: the
OCI standard `org.opencontainers.image.source` names a project's source, while a CI system
usually writes the repository that ran the build, and only the second answers "would a
pull request here rebuild this image". **`verify`** is what the service should look like
afterwards, so an expected remainder is not read as the change having failed.
**`known_exploited`** names each exploited CVE and whether this change clears it - the
list a pull request description wants, including the ones that survive, because a ticket
that mentions only the wins leaves somebody believing the service is clean of them.

`unknown` is not filler either. Where the image records no repository label there is
nothing to point at, and the plan says which configuration would supply one rather than
leaving an agent to guess.

Not every service has something to bump. Where one is already on the newest base its
line can reach, there is no change to describe and no result to report, so the plan
says what the situation needs instead - and names the CVEs the decision is about:

```
why      urgent, 2 known-exploited CVEs, 4,145 vulnerabilities across 1 deployment

decide   Already on the newest version available (python3.12-bookworm), so this is
         not a bump. The remaining CVEs need a decision: wait for upstream, rebuild
         to pick up a moved tag, or accept and record why.

known_exploited
         CVE-2026-31431 (critical, fix 2.31.1)
         CVE-2025-48384 (high, no fix published)

unknown  whether anybody has started
```

This is the branch that most needs the identifiers and the one where nothing else
supplies them: mitigate, isolate or accept is decided one CVE at a time, and a service
with no upgrade to take has no differential to list what an upgrade would clear. It is
not a rare path - on one estate three of a single team's eight items are in it.

`service_report` is the deep one. Asked about a service it returns the split that
turns a number into a conversation:

```
apps/storefront - payments - urgent in prod, internet-facing
  3 deployments, newest image built 187 days ago
  10 CVEs, 1 known-exploited

  Upgrade: mcr/dotnet/aspnet 9.0 -> 10.0 (version change, not a rebuild)
    clears 6, leaves 2, introduces 1

  What survives:
    2 still in the new base   - upstream's, no action available here
    2 from the application    - installed by the build, the team's
    remainder concentrated in: zlib (2)
    the application's own:    CVE-2026-3 (high), CVE-2026-7 (medium, fix 4.0.1)
```

Two rules hold across every tool, and both exist because prose loses what a table
keeps.

**Every answer carries its freshness** - when the assessment ran, how old the scan
provider's own data is, and which build answered. "Nothing is exploitable in
production" means something different against data from an hour ago and from a
fortnight ago, and a model asked to summarise will drop that unless it is in the
payload.

**Every CVE count is distinct CVEs.** One unit throughout, so the numbers in an answer
can be read against each other: on a service, `clears` + `still_in_base` +
`from_application` + `unattributed` is the total. That is not free - a service deployed
at three tags of one build carries the same CVEs three times, and summing each
deployment's own count told storefront it had 6,746 vulnerabilities of which an upgrade
would clear 17,571. A team cannot act on a number that is impossible on its face.

**A remainder is named on both sides.** The base remainder is broken down by package,
because at that size the question is which upstream package is holding the line. The
application remainder is listed CVE by CVE with its fix version, because that half is
the only part the team can patch in its own repository, and a bare count there is a
task nobody can start. Neither side is a package list *and* a CVE list: nothing scans
the application layer, so those CVEs have identifiers but no package name.

The two exceptions name their unit rather than hiding it. A rebuild win reports
`clears_cve_occurrences`, because a CVE on sixty images is sixty fixes and that is what
ranks the work. And `introduces` is the worst any single deployment reports, since what a
candidate base ADDS is not in the image's CVEs to count.

**Absence never renders as zero.** An unassessed image is not a clean image. Every
answer states its coverage, and each carries a `caveats` list saying what it cannot
support - because nobody re-reads a sentence a chatbot produced.

## Why an answer is empty

Every answer carries `freshness.ran`: which sources the assessment was configured
with, and whether upgrades, the base differential, pull-request matching and exposure
were asked for at all.

This exists because of a real failure. On the first session against a live estate, a
model was told 0 of 817 deployments were scanned and advised finding out why the scan
provider was assessing almost nothing. The numbers were right and the advice was
wrong: the run had simply been started without `--vuln-source`. The payload could not
say which stages had been asked to run, so a confident, actionable, incorrect
diagnosis went out.

The caveats now separate the three cases a bare zero collapses into:

- **not asked for** - *"this run was started WITHOUT a vulnerability source, so every
  CVE count here is zero by configuration, not by measurement"*, which points at the
  command line
- **asked for and produced nothing** - *"a vulnerability source was configured and yet
  scanned none of the 817 deployments; that is a failure worth investigating"*, which
  points at credentials or egress
- **asked for and genuinely clean** - the ordinary case, stated with its coverage

`estate_summary` also carries `unassessed_reasons`: the provider's own explanation for
the coverage gap, counted, so it reads as *"412 need a registry credential"* rather
than *"706 unassessed, cause unknown"*.

Where a [fallback scanner](scanning.md#when-the-provider-never-assessed-an-image) ran,
`coverage` splits the gap into `deployments_scanned_by_fallback` and
`uncovered_deployments`, and a caveat says so. `assessed_deployments` deliberately does
not include the recovered ones: asked how much of the estate the scan provider covers,
a model has to get the provider's answer, and the severities the fallback supplied come
from a different vendor feed than the rest.

## Names, and getting them wrong

`list_facets` returns the team, class, priority, exposure and signal values that
actually appear, with counts. It is there because a miss was not recoverable: asked
about "the payments team", a model called `team_report`, got nothing back, and had to
return to the human to ask what the team was called - when the assessment knew.

Team and service names are also matched forgivingly. Exact match wins; failing that a
single unambiguous substring match is accepted, so `payments` finds
`payments-platform`. Two candidates resolve to neither, because answering for one of
them would look authoritative while describing somebody else's queue - the tool hands
back both instead. Every miss returns the real names alongside it.

`unattributed_work_items` is reported separately, and is usually the reason a team
looks empty: work with no owning team appears in no `team_report` at all.

## Reporting against your own policy

`estate_summary` reports patchwright's view of what is worth acting on: known
exploited, fixes gone stale, end-of-life bases. Those are a reasonable default and a
poor basis for a report somebody signs. The standard a team is accountable to is its
own policy, and if the rules say a critical in pre-production is medium, a report that
calls it urgent is reporting somebody else's standard back at them.

`policy_report` is that report. It is keyed on the rule names in your config, and it
adds nothing to them:

- **What each actionable rule caught** - deployments, services, teams, worst first -
  in the order the rules are evaluated rather than by size. That order is the policy's
  own statement of severity; sorting by count would put the biggest bucket above the
  sharpest one.
- **Rules that caught nothing**, listed rather than omitted. "We have a rule for
  exploited criticals and it fired on nothing" and "we have no such rule" are the same
  empty space in a report built only from findings, and opposite conclusions.
- **Every suppression and when it lapses**: expired, a countdown, or no expiry at all.
  A suppression is an accepted risk, so this is the part somebody has to actively
  agree with — and one holding findings with no expiry date will never come back for
  review on its own.
- **What no rule matched.** Neither queued work nor accepted risk: policy has no
  opinion. It is invisible in every other view, and how many of those carry a
  reported critical is stated beside it.
- The split by your own priority labels and by team.

The same report is served at `GET /api/v1/policy`, from the same code, so a review
pack assembled from the API cannot disagree with one an agent produced from the tool.

Two things it will not do. It has no history, so it reports the state on the day it
ran and says so first, before any number: a monthly cadence invites reading a snapshot
as a record of the month. And the coverage counts bound it — a rule that did not match
an image nobody assessed has not cleared it, it had nothing to match on.

## Exploitation, and what can be moved on

`policy_report` says what your rules decided. `exploitability_report` says what is
actually being exploited and how much of it you can move on today.

**The unit is work items, grouped by service, over actionable findings** — the same
number the queue page shows. Filter it to the `kev` signal and it reports 34 items;
tick "has a fix" and it reports 20. The tool computes that from the same findings, the
same filters and the same grouping code, so:

```
known_exploited: { items: 34, items_with_fix: 20, items_without_fix: 14,
                   items_with_fix_pct: 58.8, deployments: 34, services: 34 }
```

A tool reporting a different number for the same question than the page a team already
uses is worse than one that stays quiet, which is why it is not counted any other way.

One call also gives the per-team breakdown with each team's urgent count beside it, so
the common question is not a join, and the worst CVEs named — a count with no names
cannot be acted on, and the question after "we have 34" is always "which ones".
`epss_threshold` defaults to 0.5, matching what the service and team reports already
treat as high, and the report echoes back the threshold it used.

### Two things that look like one number and are not

**"Has a fix" means an upgrade path, not a published patch.** The queue's tick is a
resolved upgrade with a version available. An image can carry a CVE that was patched
upstream months ago and still have nowhere to move to, because nobody has built a
release containing it. `cves.kev_fixable` is the other reading, and both are reported
so neither can be mistaken for the other. On a real shape those diverge hard: two
distinct exploited CVEs, both patched upstream — 100% fixable as vulnerabilities —
spread across 34 pieces of work of which 20 can actually move.

**Items are not CVEs.** The `cves` block underneath counts distinct vulnerabilities.
One CVE spans many services and one service carries many CVEs, so the two will not
match and neither is derivable from the other. `deployments` and `services` are
reported alongside the item count so blast radius is visible without being confused
with queue length.

Everything else is a floor: per-CVE detail exists only for scanned deployments, so the
unscanned remainder could hold exploited CVEs nobody looked for. With no exploit source
configured every figure is zero because nothing was asked, and the report says outright
not to report them. Non-actionable and suppressed findings are excluded, and both
exclusions are stated.

Served at `GET /api/v1/exploitability` too, with `?epss_threshold=`.

## Suppressed findings

Excluded from every count, and stated in every answer that excludes them. A
suppression is a decision that something is not work, not a claim that it is not
vulnerable, and a rule that has quietly grown to cover a tenth of the estate is a
finding of its own.

`service_report` is the exception: it lists suppressed deployments with
`suppressed: true` rather than hiding them, because somebody asking about a service
wants all of it, and an invisible deployment is how a stale suppression outlives its
reason.

## Connecting

The endpoint is Streamable HTTP at `/mcp`.

```sh
patchwright serve -i export.csv -c config/ --addr :8080
```

Then point a client at `http://localhost:8080/mcp`. In Claude Code:

```sh
claude mcp add --transport http patchwright http://localhost:8080/mcp
```

With a token configured, pass it as a header:

```sh
claude mcp add --transport http patchwright http://localhost:8080/mcp \
  --header "Authorization: Bearer $PATCHWRIGHT_API_TOKEN"
```

## Authentication

Nothing new. `/mcp` is a normal route, so it inherits the middleware that wraps
everything else: the shared token is required where one is configured, and the
endpoint is open where nothing is. Mounting it as an exempt path would have put an
unauthenticated read of the whole estate on the same port as a page that is behind
sign-in, and network policy selects on port rather than path.

One interaction worth stating, because a client cannot report it usefully.
Interactive sign-in and the shared token are alternatives in the same middleware, and
an MCP client is not a browser: with sign-in configured and no token set, a headless
caller has no way to authenticate. It fails clearly - a non-HTML request gets a 401
telling it to present a token rather than a redirect into a login page - but the
answer is to set the token alongside sign-in wherever machine callers are expected.

Authorisation is unchanged and all-or-nothing: whatever reaches the endpoint sees the
whole estate, because the underlying views have no per-team scoping to offer.

## What is deliberately absent

**No `refresh` tool.** It is the one expensive operation - on a real estate around
twenty-five minutes and several GB - and a scheduled assessment already keeps the
cache current. Leaving it out removes the rate-limiting question entirely: reads are
map lookups, so a client calling in a loop costs nothing worth defending against.

**No write tools.** The ticket plan is already exposed read-only with an explicit
apply, and moving that behind a conversational interface deserves its own decision
rather than arriving as a side effect of this one.

**No stdio transport.** It would mean one process per client, each holding its own
credentials and running its own twenty-five-minute assessment before it could answer
anything. Fine for a tool that reads local files; not for this.
