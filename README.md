<p align="center">
  <img src="./docs/images/patchwright.png" alt="Logo" width="200" height="auto" />
</p>
<h1 align="center">patchwright</h1>

Turn noisy container-vulnerability scanner output into a **deduplicated,
owner-attributed, actionable** list.

Security scanners tell you *"this is a problem"* — thousands of rows of it.
patchwright answers the harder questions: *which* problems, *who* can fix them,
and *what is worth acting on now*. It reasons over vendor-neutral primitives
(images, CVEs, vulnerability counts) and pushes all organization-specific
judgement into declarative CEL rules you own.

In practice this collapses **thousands of scanner rows into a few dozen
actionable, owner-attributed findings** — deduplicating by image, splitting work
between platform and engineering teams, routing cloud-provider-managed images
out of the queue, and dropping workloads that aren't actually running.

---

## Concepts

The design keeps a **generic core** and pushes everything specific to the edges:

| Layer | Responsibility | Where the coupling lives |
|---|---|---|
| **Provider** | Ingest scan data and translate it to the generic model | Scanner-specific (Rapid7, later Trivy/Grype/Wiz…) |
| **Model** | Images, vulnerabilities, counts, resources with free-form dimensions/labels | Nothing org- or vendor-specific |
| **Rules (CEL)** | Ownership attribution + actionability policy | Organization-specific — *your* config |
| **Sink** | Render findings (table, JSON; later Jira, GitOps PRs) | Output-specific |

The pipeline is: **provider → dedupe (by image) → attribute (owner) → policy
(actionable?) → sink**.

- **Dedupe** is the primary noise reducer: the same image runs in dozens of
  places but is assessed and remediated once.
- **Attribution** assigns each workload an owner via your rules — commonly
  `platform` / `cloud-provider` / `engineering`, but the classes are yours to
  define. Cloud-provider-managed images (e.g. `mcr.microsoft.com`,
  `registry.k8s.io`) get routed differently because you can't patch them directly.
- **Policy** decides what is actionable and at what priority, and suppresses
  what isn't (accepted risk, not-your-patch, false positives).

## Install / build

Requires Go 1.26+.

```sh
go build ./cmd/patchwright
```

## Usage

**Profile** the raw data first — quantify the noise and sanity-check how it
breaks down before writing rules:

```sh
patchwright profile -i export.csv
```

**Assess** — deduplicate, attribute owners, apply policy, and report:

```sh
# actionable findings, grouped by owner class
patchwright assess -i export.csv -c config/

# only the engineering slice, as JSON (for tooling / later Jira & GitOps sinks)
patchwright assess -i export.csv -c config/ --owner engineering --format json

# everything, including suppressed and non-actionable findings
patchwright assess -i export.csv -c config/ --all --show-suppressed
```

Key flags: `--provider` (default `rapid7`), `-i/--input`, `--mode` (`csv`|`api`),
`-c/--config` (file or directory, repeatable), `-f/--format` (`table`|`json`),
`--owner`, `--all`, `--show-suppressed`. Global: `--log-level`
(`debug`|`info`|`warn`|`error`) and `--log-format` (`text`|`json`) — logs go to
**stderr**, so the report on stdout stays clean (pipe JSON to `jq` freely).

### Rapid7 API instead of a CSV export

`--mode api` queries InsightCloudSec directly rather than reading an export
someone produced by hand. The base URL is your tenant's; the key comes from
`RAPID7_API_KEY` and is deliberately not an option, because options are populated
from config files and Helm values, which live in git.

```sh
export RAPID7_API_KEY=...
patchwright assess --mode api -o base-url=https://example.customer.divvycloud.com \
  -c config/
```

Two reasons to prefer it over the export, beyond not having to produce one:

**It is current.** An export ages from the moment it is written, and a server
refreshing hourly over a mounted file reports a fresh assessment forever while the
data underneath it goes stale. Measured on a real estate, the same query returned
data one hour old where the export in use was seven days old.

**It says why an image was not assessed.** The export leaves `last_assessment`
empty and stops there, so every uncovered image looks alike. They are not alike.
The API returns `assessment_info`, which patchwright carries through to
`assessment_issues` on each finding, to `unassessed_reasons` on the server's
summary, and to the top of the coverage warning:

```
WARN provider never assessed some images — their zero counts are absence of data,
     not a clean result  unassessed_images=773 total_images=854
     top_reason="Can't authenticate to registry. Unable to obtain refresh token..."
     images_affected=734
```

On the estate this was built against, 734 of 773 uncovered images came back to a
single registry credential the platform could not use. A coverage percentage
invites resignation; a named cause is a job someone can pick up. That is the whole
argument for this mode.

The API also carries the cluster name (as `dimensions["cluster"]`, available to
rules without waiting for live reconciliation), the image platform, and the digest
the assessment actually read — so a result is pinned to an image rather than to a
mutable tag. The digest is taken only from a completed assessment; on a failed row
it would name an image nothing was read from.

Per-CVE detail (`fix_available` / `fixed_version`) is **not** in this mode yet, so
`--vuln-source trivy` is still how the `vulns` list gets populated. The endpoints
exist, and the notes are in
[docs/design/rapid7-api.md](docs/design/rapid7-api.md).

### Live reconciliation (multi-cluster)

Scanner exports are a point-in-time snapshot; completed Jobs and scaled-to-zero
workloads still show up as findings. Reconcile against what is *actually
running* to drop that noise. patchwright deploys to one cluster but can read
many, via a kubeconfig with a read-only context per cluster:

```sh
# reconcile against live clusters (the not-running suppress rule then applies)
patchwright assess -i export.csv -c config/ \
  --live-source kube --live-option kubeconfig=$HOME/.kube/config \
  --live-option contexts=aks-prod-uk,aks-prod-us,gke-analytics

# or against an offline snapshot of running images (one image ref per line)
patchwright assess -i export.csv -c config/ \
  --live-source file --live-option path=live-images.txt
```

The report's `LIVE` column shows `yes`/`no` (or `?` when reconciliation didn't
run), and rules can reason over `reconciled` and `live` (see the `not-running`
rule in `config/policy.yaml`).

### Vulnerability scanning — fix availability

Turn "actionable" from a heuristic into "there's a fix to apply". With
`--vuln-source trivy`, each unique image is scanned once (after dedupe) and its
per-CVE detail — including `fix_available` / `fixed_version` — populates the
`vulns` list, so rules can require a fix before paging anyone. Requires the
[`trivy`](https://trivy.dev) binary (it pulls images itself, so it needs egress
and registry credentials for private images).

```sh
patchwright assess -i export.csv -c config/ \
  --vuln-source trivy --vuln-option severity=CRITICAL,HIGH
```

Trivy downloads its vulnerability DB once, before the concurrent scan loop. That
download is the one step in a run that depends on a public CDN, and it is
observably flaky: `mirror.gcr.io` will 404 a layer it has just advertised in its
own manifest, and the identical command succeeds seconds later. Trivy does not
retry that itself, so patchwright does — three attempts, and from the second it
reaches past the mirror list to `ghcr.io/aquasecurity/trivy-db:2` upstream. Point
it somewhere else with `--vuln-option db-repository=registry.internal/trivy-db:2`,
which is also respected on retry rather than being abandoned for the internet, on
the grounds that naming a repository usually means the default is unreachable.

The report's `FIXCRIT` column shows fix-available critical CVEs; the JSON adds
`fixable_critical` and the full `vulns` array. Example rule:
`when: "vulns.exists(v, v.severity == 'critical' && v.fix_available)"`.

**Exploitability** — layer `--exploit-source public` on top to annotate each CVE
with its [EPSS](https://www.first.org/epss/) score (predicted exploitation
probability) and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
membership (exploited in the wild), from public feeds. Rules can then require a
CVE that is *both fixable and being/likely exploited* before paging:

```sh
patchwright assess -i export.csv -c config/ \
  --vuln-source trivy --exploit-source public
```

The `KEV` and `EPSS` columns and JSON `known_exploited` / `vulns[].epss` /
`vulns[].kev` surface it; e.g.
`when: "vulns.exists(v, v.fix_available && (v.kev || v.epss > 0.5))"`.

`EPSS` is the **highest** score across the image's CVEs, since one CVE at 0.93
makes the image urgent however many quiet ones sit beside it. Both columns show
`-` until exploit enrichment runs, so `0`/`0.00` always means "checked, nothing".

Note that severity and exploitability diverge sharply in practice: a CVSS 10.0
at EPSS 0.008 is a poorer use of an afternoon than a CVSS 5 at EPSS 0.93. Rules
that gate on `epss`/`kev` are what stop the queue being sorted by fear.

### Remediation — is a newer version available?

Knowing a CVE has a fix is only half the story; the other half is *can you ship
the fix given how this is deployed*. `--remediation` composes ordered upgrade
sources, deployment-aware first:

1. **Flux Helm chart** (with `--live-source kube`) — reads Flux `HelmRelease`s,
   resolves each chart's repository, and checks the index for a **newer chart
   version**.
2. **Registry image tag** — for any image on a strict-semver tag, checks its
   registry for a **newer tag** (auth via the docker/cloud keychain). Covers
   workloads that aren't Helm charts — plain manifests and Kustomizations.

```sh
# Flux charts + image tags:
patchwright assess -i export.csv -c config/ \
  --live-source kube --live-option contexts=aks-prod --remediation
# image tags only (no cluster needed):
patchwright assess -i export.csv -c config/ --remediation
```

**Actionability.** An upgrade is *directly actionable* only when you can apply it
at that level. A newer image tag for a workload controlled by a Helm chart or an
operator is reported as available but **not actionable** — bumping the tag would
be reverted; the remediation is to upgrade the chart/operator. The
`upgrade_available` policy variable is true only for actionable upgrades, so
automation acts on the right things, and the JSON `upgrade` object carries
`available`, `actionable`, `managed`, and `source`.

The `UPGRADE` column reads:

| Shown | Meaning |
|---|---|
| `current->latest` | a newer version you can apply directly |
| `chart current->latest` | a newer **chart** version — these are chart versions, not the image tag in the IMAGE column |
| `current->latest (helm\|operator)` | a newer version exists but is controlled elsewhere (upgrade the chart/operator) |
| `-` | on the latest version |
| `?` | remediation detection didn't run (no `--remediation`) |

`CRIT`/`HIGH` show `?` when the provider **never assessed** the image. A provider
that cannot reach a registry still emits a row, with zero counts and severity
`UNKNOWN` — and printing that as `0` is the most misleading thing a
vulnerability report can do. JSON carries it as `provider_assessed`, and the run
logs a warning with the count.

This is deliberately about the *provider*, not scanning: a vuln source is
optional and off by default, so `--vuln-source` not having run says nothing about
whether data exists. Unassessed findings are **not** excluded from the queue —
they simply can never match a count-based rule, which is a coverage gap to close
rather than a verdict to hide.

The `FIX` column condenses that into the remediation *path* — "can I act, and
how?", which is what a queue is read to answer:

| Shown | Meaning |
|---|---|
| `direct` | a newer version this image can move to now |
| `managed` | a newer version exists, but a chart/operator owns the tag — fix it there |
| `none` | already on the latest version; nothing to upgrade to |
| `unknown` | detection ran but could not resolve a version (e.g. a private registry whose tags we cannot list) |
| `?` | detection didn't run at all (no `--remediation`) |

`none` is deliberately visible rather than hidden. Criticals with nowhere to go
need a human decision (wait for upstream, rebuild, or accept the risk), and that
is a different conversation from "bump the tag".

`unknown` and `?` are kept apart because they demand opposite responses: `?` is
"you didn't ask", while `unknown` is a coverage gap to chase. JSON carries this
as `remediation_checked`, and anything that skips findings without an upgrade
**must** check it, or it will silently skip images whose versions merely could
not be resolved.

`PRIORITY` carries the policy verdict, including `supp` for suppressed findings
in `--show-suppressed` views.

The table prints a `LEGEND` above the data explaining every mark. It is worth the
dozen lines: the report carries four separate unknown-states (`CRIT ?`, `FIX ?`,
`FIX unknown`, `UPGRADE ?`) that mean different things, and unexplained they all
read as "probably fine" — the exact reading the marks exist to prevent.

The group header adds the same breakdown, because "32 actionable" of which only
9 are `direct` is a materially different day's work from 32 direct bumps:

```
== owner class: platform (32 findings, 32 actionable: 9 direct, 20 managed, 3 none) ==
```

`TEAM` shows `-` when no ownership rule could attribute the workload to a real
team. Resist the temptation to fall back to the namespace name in `teamFrom`: it
renders identically to a genuine team and quietly launders "we don't know" into
a confident-looking answer. `NAMESPACE` already shows where the workload runs,
and an unowned row is a prompt to label the namespace at source.

Git/OCI source revisions are the next remediation kind — see
[docs/design/remediation-availability.md](docs/design/remediation-availability.md).

### Ticket — raise the work

`patchwright ticket` turns actionable findings into tickets from a template you
supply. It reads the JSON an assess run already produced rather than re-running
the assessment: a full run reconciles every cluster and rescans every image, and
ticket creation should act on output you have already looked at.

```sh
patchwright assess -i export.csv -c config/ --remediation \
  --output json:full=findings.json
patchwright ticket -i findings.json -c config/          # dry run, changes nothing
patchwright ticket -i findings.json -c config/ --confirm  # actually create
```

**Dry run is the default.** It prints every ticket in full, and (given
credentials) tells you which would be skipped as already open, so the answer to
"would this create anything?" comes before anything is created.

Credentials come from the environment, never the config file, which is committed:

```sh
export JIRA_BASE_URL=https://your-site.atlassian.net
export JIRA_EMAIL=you@example.com
export JIRA_API_TOKEN=...
```

Configuration lives in a `jira:` block. `board`, `project`, `template`, and one
of `imageField`/`imageLabel` are required; the rest is optional:

```yaml
jira:
  board: 100
  project: PROJ
  template: config/templates/container-vuln.md.tmpl
  imageField: customfield_XXXXX   # array-of-strings field holding the images
  # imageLabel: true              # or use labels, when no such field exists
  epic: PROJ-100
  issueType: Container Vulnerability
  priorityMap:                    # carry the assessment's ordering into Jira
    urgent: Highest
    high: High
    medium: Medium
    low: Low
  priority: Medium                # fallback for anything unmapped
  requireUpgrade: true            # default
```

**No ticket is raised for a finding with nothing to upgrade to.** A ticket saying
"upgrade to the latest version" for an image already on the latest wastes the
assignee's time, which is how a vulnerability queue loses credibility. Skipped
findings are printed with the reason rather than dropped, and the reasons are
distinct on purpose: "already on the latest version" is a resolved question,
while "versions could not be resolved" is one to chase. Set
`requireUpgrade: false` to raise them anyway.

**Exclusions keep work out of ticket creation without hiding it.** `exclude` is a
list of CEL rules over the *same* variables as the policy rules above, so there
is one expression language to learn rather than a second matching syntax:

```yaml
jira:
  exclude:
    - name: crossplane
      when: "dimensions['namespace'].exists(n, n == 'crossplane-system')"
      reason: upgraded together on their own cadence
```

This is deliberately not `suppress`. A suppressed finding is one nobody should
act on and it leaves the assessment entirely; an excluded one is real work simply
tracked elsewhere, so it stays in the report and the queue and is listed as
skipped with the rule name and reason. Excluding something never makes it quiet.

**Routing sends each team's tickets to its own tracker.** One deployment covers
teams that do not share a board: platform work on one project, an SRE team with
its own project, issue type and priority scheme. `routes` matches on the same CEL
variables as everything else, first match wins, and anything matching no route
uses the top-level settings.

```yaml
jira:
  project: PROJ                 # the default for anything unrouted
  issueType: Container Vulnerability
  routes:
    - name: sre
      when: "owner['team'] == 'sre'"
      project: SRE
      issueType: Bug
      imageLabel: true          # this project has no shared custom field
    - name: platform
      when: "owner['class'] == 'platform'"
      project: PROJ
```

A route states **only what differs**; template, image field, priority map and
labels are inherited, so adding a board is three lines rather than a second copy
of the configuration. Each route is validated as the configuration it resolves to,
at load rather than at the first ticket it tries to raise.

Two consequences worth knowing:

- **A group is never split across routes.** Two findings that share one upgrade
  but belong to different teams become two tickets, because an issue cannot exist
  in two projects and merging them would move one team's work onto another team's
  board.
- **Reconciliation searches every configured project**, not just the default. A
  ticket on another team's board still means the work is in flight, and an
  idempotency check that cannot see it raises duplicates forever. Writes to an
  existing ticket resolve its tracker from the issue key's project prefix, so the
  images go into the field that project actually uses.

**`requireRoute: true` means no match, no ticket.** By default an unmatched finding
falls through to the top-level `project`, which suits a single shared board. Set
`requireRoute` and a finding matching no route is reported as skipped instead, with
the owner named in the reason:

```
no ticket route matches its owner (engineering/orders) and requireRoute is set,
so no tracker is configured for this work
```

It is still in the report and the queue — this decides where work is tracked, never
whether it is visible. Worth setting when every tracker is named on purpose: a team
whose coverage arrives before anyone has routed it then produces reported skips
rather than tickets on whichever board happens to be the default.

Dry runs print `Tracker: SRE / Bug (route "sre")` per ticket, and the API's ticket
plan carries `route` on every action, so where work lands is reviewable before
anything is written.

**Priority carries across.** Without `priorityMap`, every ticket is raised at the
single `priority` value, and the tracker cannot tell an urgent, exploited, fixable
finding from a low one. The map is deliberately not defaulted: priority schemes are
per-instance, and a name that does not exist fails ticket creation. A dry run prints
`urgent -> Highest` per ticket so a flattened queue is visible before anything is
created.

**A stale ticket nobody has picked up is corrected, not commented on.** When the
version a ticket asks for has moved on, what happens next depends on whether anyone
has engaged with it. If the ticket is unassigned *and* still in a "new" status
category, the summary and description are rewritten to the current target: leaving
a wrong summary with the right answer in a comment underneath wastes the reader's
time twice, once working out that the title is wrong and again finding the real
target further down.

If it is assigned, or already in progress, it is only commented on. Both halves of
that test matter. An unassigned ticket in progress is being worked by someone who
has not claimed it, common on boards that assign at standup; an assigned ticket in
To Do has an owner who has read it and knows what it says. Rewriting either changes
the task after someone engaged with it.

Only the wording is replaced. Priority is left alone, because a human may have
deliberately changed it and silently reverting someone's triage is a worse bug than
a stale summary, and the images are unchanged since the draft covers the same group
by definition. No comment is posted alongside: Jira records field edits in the issue
history, which is a better audit trail than a comment asserting that an edit
happened.

**`autoClose: true` closes tickets whose work is provably finished.** The case this
exists for is ordinary: someone merges a Renovate PR, it rolls out, and nobody ever
opens the ticket. Reconciliation closes it with a comment stating the evidence.

The word "provably" is carrying weight. A finding *disappearing* is never treated as
done, because a provider that stopped assessing an image looks exactly the same —
that path still only comments. Closing needs every image on the ticket to satisfy
all of:

- still reported in the assessment, so this is not the absent-data case;
- `remediation_checked`, or "no upgrade available" only means nobody looked;
- `upgrade.resolved`, or "on the latest" is unproven — an unreadable private
  registry reports exactly this;
- no finding for that repository with an upgrade still available, which is what
  catches an old tag still running somewhere;
- liveness reconciled, so "everywhere" is a checked claim about running workloads
  rather than an assumption.

Any one of those failing means a comment instead. Set `closeTransition` when the
workflow offers more than one way to finish: "Done" and "Won't Do" say very
different things about the same work, so patchwright refuses to choose rather than
guessing, and names the alternatives in the error.

Both settings are **per route**, because both belong to the tracker rather than the
deployment: one team may want closing automated while another does not, and a
transition named "Done" in one project says nothing about another project's
workflow.

```yaml
jira:
  project: PROJ
  autoClose: false              # off for anything unrouted
  routes:
    - name: sre
      when: "owner['team'] == 'sre'"
      project: SRE
      autoClose: true
      closeTransition: Ship It  # SRE's workflow, not PROJ's
```

For tickets that already exist the settings are resolved by the issue key's
**project**, not by the route that created it — the board a ticket sits on decides
how it can be finished, and a route may since have been renamed or removed.

The closing comment is short and states only what was observed, so a reader can
disagree with a fact rather than an argument. It is posted in the same request as
the transition: a separate comment first would leave a ticket explaining a closure
that never happened if the transition then failed, and the next run would comment
again, so a workflow patchwright cannot complete would accumulate one comment per
run forever. Where a transition screen rejects an attached comment, the transition
is retried bare and the reason posted separately, since a closed ticket with no
explanation still beats an open ticket nobody is reading.

**A note is posted once, not every run.** Reconciliation is a loop, so a ticket
sitting in a state that warrants a comment would collect an identical one every
refresh — hourly, indefinitely — burying the ticket's own history and teaching people
to skip anything patchwright writes. Each note carries a reference, rendered as inline code
(`` `patchwright-ref: note-done` ``) so it reads as machine bookkeeping rather than
part of the sentence, and existing comments are read before posting.

The reference includes the facts that would make a fresh comment worth reading, so a
note whose content genuinely changed is still posted: a staleness note is keyed on
the version now available, so a target that moves again is said again, while the same
target is not. Comments with no reference — the explanation attached to extending a
ticket — always post, because that only happens when the images actually changed.

A comment that was already present is reported as `already_present`, never counted as
posted: claiming a write that did not happen is the same error as counting an
unassessed image as clean.

**It reconciles rather than only creating.** A queue that is only ever added to rots
three ways, all of which happened on a real project inside a day: a ticket covering
one image of a change suppresses the rest, leaving them with no ticket and nothing
saying so; the version a ticket asks for moves on; and the work gets done but the
ticket stays open. So a run produces actions, not just creations:

| Action | When |
|---|---|
| `create` | no open ticket covers any of the change's images |
| `extend` | a ticket covers part of the change; the rest are added to it, with a comment saying why |
| `note-stale` | the available version has moved on since the ticket was raised |
| `note-done` | nothing is reported for the ticket's images any more |
| `skip` | already covers the change correctly |

**Nothing is ever closed.** A finding can leave the queue because it was fixed or
because nothing is assessing the image any more, and those are indistinguishable
from the queue alone. Closing on the second would quietly retire real work, so
`note-done` comments and says which of the two it cannot rule out.

**Duplicates are prevented by asking Jira, not by local state.** Before creating,
it searches for open tickets carrying the image in `imageField` (or the label),
and skips when one exists. A state file would drift the moment someone closed a
ticket by hand. Tickets in a Done status do not suppress a new one: a recurrence
after a completed upgrade is genuinely new work.

**Findings that one change would fix share a ticket.** Grouping is by deployment
source, so a set of controllers owned by one operator becomes a single ticket.
Where a controller gives each package its own object (every Crossplane provider
has its own `ProviderRevision`), the object name is collapsed so a family groups
rather than producing a ticket each. A grouped ticket never claims a single
target version unless every image really shares one, and is never titled after
one of its images.

The template is Go `text/template`, first line `Summary: ...`, then a blank line,
then the description. See
[config/templates/container-vuln.md.tmpl](config/templates/container-vuln.md.tmpl)
for the available fields; it is an example, meant to be edited.

A small amount of markup is translated into Atlassian Document Format: `**bold**`,
`` `code` ``, bullet lists, headings, and bare URLs become links so an upgrade target
is clickable rather than something to copy out by hand. Code spans are left
untouched inside, since an image reference or a command is exactly the kind of thing
that contains characters the other rules would otherwise treat as markup. Anything
unrecognised, including an unmatched `` ` `` or `**`, is passed through as written:
a stray character should look wrong, not silently reformat everything after it.

### Serve — the assessment as an API

A CronJob that logs findings is write-only. `patchwright serve` runs the same
assessment on a schedule, caches the latest result, and exposes it over a
read-only HTTP/JSON API so people and tools can *query* current findings — the
foundation for a UI, a Backstage plugin, and (next) Jira actioning.

```sh
patchwright serve -i export.csv -c config/ --addr :8080 --interval 1h \
  --live-source kube --live-option contexts=aks-prod --remediation
```

| Endpoint | Purpose |
|---|---|
| `GET /` | Live-status page: coverage, a per-class and per-team breakdown, the queue, open Jira tickets. Embedded in the binary and reads the API below, so the two cannot disagree. |
| `GET /api/v1/findings` | Findings, filterable: `owner_class`, `team`, `priority`, `actionable`, `live`, `upgradable`, `known_exploited`, `suppressed`, `provider_assessed`, `remediation_checked`, `upgrade_resolved`. |
| `GET /api/v1/finding?image=<ref>` | A single image's finding. |
| `GET /api/v1/owners` | Per-team triage: total / actionable / fixable / upgradable / unassessed, plus where the fix goes (`direct` / `managed`) and how much is already tracked (`ticketed`). |
| `GET /api/v1/summary` | Fleet-wide headline, including coverage (`provider_assessed`, `provider_unassessed`, `remediation_unresolved`, `actionable_unassessed`, `scanned`, `exploit_checked`) and `unassessed_reasons`. |
| `POST /api/v1/assessments` | Trigger a refresh (async). |
| `GET /api/v1/tickets` | What ticket reconciliation would do against the cached assessment. Changes nothing. |
| `POST /api/v1/tickets` | Apply it. Requires `{"confirm": true}`; without it, 400 and the plan. |
| `GET /metrics` | Prometheus metrics, all prefixed `patchwright_`. Authenticated, unlike the probes. |
| `GET /healthz`, `GET /readyz` | Health (ready once a first assessment is cached). |

Given a `jira:` config block and `JIRA_*` credentials, `serve` also indexes the
project's **open** tickets on each refresh (one JQL query for the whole project,
not one per image) and returns them alongside findings as `tickets`, keyed by image
repository, so the page can show whether someone is already on a finding. Only
search is used; `serve` never creates anything. Without the config or the
credentials the key is absent, which means *unknown* rather than "no ticket
exists".

**The breakdown section** on the page rolls `/api/v1/owners` up per owner class and
then per team, and states every count as a share of a named denominator. Raw counts
alone mislead in both directions here: two actionable findings out of six reads as
quieter than twenty out of seven hundred, and full coverage of four images is not
better shape than 40% of two hundred. So each row reports its share of the estate,
what fraction of it was actually assessed, and — of the actionable subset — how much
is directly fixable, how much is owned by a chart or operator, and how much already
has a ticket. A class with only one team is not broken down further, and the
`Ticketed` column reads `?` rather than `0%` when Jira is not configured.

The `CVEs` column totals the scan provider's own severity counts, and clicking its
header splits it into `CRIT` / `HIGH` / `MED` / `LOW` for every row. It is drawn
only from findings the provider assessed, so `?` means none were, which is not the
same as no CVEs; how many contributed is in the cell's tooltip, and the `Assessed`
column states the same denominator. Provider counts only, matching the report's `CRIT`/`HIGH` columns, so a
finding that exists solely because Trivy looked where the provider did not
contributes nothing here. The number is a floor, never a ceiling.

Classes with more than one team collapse, and start collapsed, with the team count
in the class row so a rollup never reads as the whole story. The section replaces
the old flat per-owner table, which showed a subset of the same numbers with no
denominators; `upgradable` is the one column it dropped, still available from
`/api/v1/owners` and largely answered by `direct`.

**A missing signal is reported by its consequence.** Running without a vuln source
is the chart's default, and in that mode every rule of the form
`vulns.exists(...)` — fix availability, EPSS, KEV — is false, so the priority tiers
that depend on them cannot fire and the queue reads as calm when it is merely
uninformed. The page says so at the top rather than leaving a column of dashes to
imply it, and the summary reports `scanned` and `exploit_checked` so a consumer can
tell the same story without inspecting every finding.

The EPSS column stays in both cases. `-` says the signal was not collected;
removing the column would say the signal does not exist, and hiding a gap is the
one thing this tool is built not to do.

### Metrics

`GET /metrics` exposes Prometheus metrics prefixed `patchwright_`, plus the standard
`go_*` and `process_*` collectors. Enable scraping with
`metrics.serviceMonitor.enabled` (a ServiceMonitor is the default choice, since
server mode already has a Service) or `metrics.podMonitor.enabled` for a Prometheus
scoped to pods. Enabling both is refused: two monitors on one target double every
counter.

The endpoint is **behind the same token as the API**, unlike the health probes.
These numbers are the estate's posture — how many unpatched criticals, how much of
it nobody has data for — not liveness. The chart wires Prometheus to the same Secret
the server uses, so there is one credential rather than two.

Two things worth alerting on that the rest of this README exists to explain:

```promql
# The scan provider's data going stale behind a freshly-generated report. -1 means
# the provider reports no timestamps at all, which is not the same as fresh.
patchwright_provider_data_age_seconds > 86400 * 3

# Coverage lost to one fixable cause. On a real estate this was a single expired
# registry credential accounting for 96% of the estate.
topk(3, patchwright_findings_unassessed_by_reason)

# Ticketing has stopped working because the credentials expired, which otherwise
# looks identical to "no work to raise".
increase(patchwright_jira_requests_total{outcome="auth_error"}[15m]) > 0
```

Coverage is reported per owner as `patchwright_owner_findings{class,team,state}`,
where `state` is `total`, `actionable`, `unassessed` or `ticketed`. Series are reset
between assessments, so a team that leaves the estate stops being reported rather
than freezing at its last value.

A counter appears on its first occurrence, so `patchwright_jira_requests_total`
carries no `auth_error` series until one happens. Write alerts as `increase(...) > 0`
rather than comparing an absent series to zero.

**Cardinality is bounded deliberately.** There is no per-image or per-CVE label
anywhere — 800 images would be 800 series behind one metric, and the JSON API
already answers questions at that grain. Provider-supplied reason strings are
trimmed to their first clause and capped, with the tail summed into `other` so the
totals still add up.

**Authentication.** Set `PATCHWRIGHT_API_TOKEN` and every request except the health
probes requires it. Programmatic clients send `Authorization: Bearer <token>`;
browsers are prompted for HTTP Basic with the token as the password, since a browser
cannot attach a bearer token when it navigates to the page. The status page is gated
too: it is a data view, so protecting the API while leaving the page open would
protect nothing.

```sh
export PATCHWRIGHT_API_TOKEN="$(openssl rand -base64 32)"
patchwright serve -i export.csv -c config/
curl -H "Authorization: Bearer $PATCHWRIGHT_API_TOKEN" localhost:8080/api/v1/summary
```

Without the variable both are unauthenticated and `serve` warns on every start.
That is fine on a laptop and is not fine anywhere else: the API serves an estate's
unpatched criticals. Set `server.auth.secretName` in the chart to wire it from a
Secret.

This is the floor, not the ceiling — one shared token, no identity, no per-team
scoping. Put OIDC in front (an ingress authenticator or oauth2-proxy) for anything
beyond a trusted network.

Every response carries an `assessment` block (`generated_at`, `running`, and
`started_at` while a run is in flight) so clients know how fresh the *assessment*
is. `summary` separately reports `provider_data_newest` / `provider_data_oldest`,
which is when the scan provider last looked. The two are different questions: a
server refreshing hourly over a mounted export reports a fresh assessment forever
while the vulnerability data underneath it ages, and a week-old export is otherwise
indistinguishable from a current one. The status page states both, and `assess`
warns when the export is more than two days old. This is how patchwright is deployed — the
Helm chart runs it as a Deployment + Service. See
[docs/design/api-server.md](docs/design/api-server.md).

## Writing rules

Rules are YAML with [CEL](https://github.com/google/cel-go) expressions.
Ownership rules match per-workload; policy rules match per finding
(one image, one owner, aggregated across its workloads). First match wins;
suppression beats actionability. See [`config/`](config/) for a documented,
editable starting point.

```yaml
# ownership.yaml — first match wins
owners:
  - name: cloud-provider-managed-images
    match: "image.registry in ['mcr.microsoft.com', 'registry.k8s.io']"
    class: cloud-provider
    team: aks
  - name: platform-system-namespaces
    match: "dimensions['namespace'] in ['kube-system', 'flux-system', 'cert-manager']"
    class: platform
    team: platform-engineering
  - name: engineering-by-label          # preferred once live labels are available
    match: "'team' in labels"
    class: engineering
    teamFrom: "labels['team']"
  - name: engineering-by-namespace      # fallback
    match: "true"
    class: engineering
    teamFrom: "dimensions['namespace']"
```

```yaml
# policy.yaml
suppress:
  - name: cloud-provider-managed
    when: "owner['class'] == 'cloud-provider'"   # can't patch these directly
actionable:
  # With --vuln-source + --exploit-source, exploitation pressure can outrank
  # environment: a fixable bug being exploited now beats an unexploited critical.
  - name: exploited-fixable-critical
    when: "vulns.exists(v, v.severity == 'critical' && v.fix_available && (v.kev || v.epss > 0.5))"
    priority: urgent
  - name: production-critical
    when: "counts['critical'] > 0 && dimensions['account'].exists(a, a.startsWith('Production'))"
    priority: high
  - name: any-critical
    when: "counts['critical'] > 0"
    priority: low
```

`priority` is free-form, but only `urgent` > `high` > `medium` > `low` are
**ranked** for report ordering — any other label sorts after all of them. Add a
new tier to `priorityRank` (`pkg/sink/sink.go`) rather than inventing one in
config alone, or it lands at the bottom of the queue.

### How "actionable" is decided

Actionability is **purely the policy rules above, evaluated over the data
patchwright already has** — severity counts, environment (`dimensions`),
ownership, and liveness. There is **no live registry or CVE lookup today**: a
finding is "actionable" because it matched an `actionable` rule and no
`suppress` rule, not because a fix has been confirmed to exist.

The missing signal — *is there a patched image to move to?* — comes from
Trivy today (the Rapid7 API can supply it too, see
[docs/design/rapid7-api.md](docs/design/rapid7-api.md)), which populates the `vulns` list with `fix_available`
/ `fixed_version` so rules can require a fix before paging anyone. See
[docs/design/trivy-integration.md](docs/design/trivy-integration.md).

### Variables available to rules

**Ownership** (per occurrence): `image` `{registry, repository, tag, digest, ref}`,
`dimensions` `map<string,string>`, `labels` `map<string,string>`,
`counts` `map<string,int>` (standard severities always present),
`resource` `{id, type, name}`.

**Policy** (per finding): `image`, `counts`, `risk` (double),
`owner` `{class, team}`, `dimensions` `map<string,list<string>>` (union across
workloads), `labels` `map<string,list<string>>`, `vulns` `list` of
`{id, severity, cvss, fix_available, fixed_version}` (when the provider supplies
per-CVE detail).

## Deploying

patchwright ships as a container ([`Dockerfile`](Dockerfile)) and a Helm chart
([`deploy/helm/patchwright`](deploy/helm/patchwright)) that runs it as a
Deployment serving the [assessment API](#serve--the-assessment-as-an-api).

**Auth is just RBAC.** For the cluster patchwright runs in, the chart creates a
ServiceAccount and a minimal read-only ClusterRole — `get`/`list` on `pods` and
`namespaces`, nothing else, no secrets, no writes. That is all reconciliation of
the local cluster needs; there are no credentials to manage.

```sh
# 1. make the scanner export available as a Secret (csv mode)
kubectl create secret generic patchwright-export --from-file=export.csv=./export.csv

# 2. install
helm install pw deploy/helm/patchwright \
  --set provider.input.secretName=patchwright-export

# 3. query the API
kubectl port-forward svc/pw-patchwright 8080:8080 &
curl localhost:8080/api/v1/summary        # includes coverage counts
curl 'localhost:8080/api/v1/findings?provider_assessed=false'   # never scanned
```

**Multi-cluster.** patchwright deploys to one cluster but reconciles many. Read
the local cluster via its ServiceAccount, and remote clusters via a kubeconfig
Secret of read-only contexts. In each remote cluster, apply
[`deploy/rbac/readonly-clusterrole.yaml`](deploy/rbac/readonly-clusterrole.yaml)
and bind it to the identity your kubeconfig authenticates as:

```sh
helm install pw deploy/helm/patchwright \
  --set provider.input.secretName=patchwright-export \
  --set reconcile.remote.kubeconfigSecret=pw-kubeconfig \
  --set 'reconcile.remote.contexts={aks-prod-uk,aks-prod-us,gke-analytics}'
```

**Scanning (Trivy) & private registries.** Trivy is bundled in the image; set
`scan.enabled=true` (and `scan.exploitSource=public` for EPSS/KEV) to scan images
in-cluster. Trivy pulls the images itself, so it needs credentials for **private
registries** — patchwright delegates to Trivy's standard auth. Two ways:

```sh
# Workload identity is provider-scoped (registryAuth.azure|gcp|aws) — no secrets.
# Azure (AKS + ACR): grant the managed identity AcrPull; the chart adds the SA
# client-id annotation AND the pod's `azure.workload.identity/use: "true"` label.
helm install pw deploy/helm/patchwright \
  --set provider.input.secretName=patchwright-export \
  --set scan.enabled=true \
  --set registryAuth.azure.workloadIdentity.enabled=true \
  --set registryAuth.azure.workloadIdentity.clientId=<managed-identity-client-id>

# GKE (Artifact Registry): --set registryAuth.gcp.workloadIdentity.enabled=true \
#                          --set registryAuth.gcp.workloadIdentity.serviceAccount=<gsa-email>
# EKS (ECR, IRSA):         --set registryAuth.aws.irsa.enabled=true \
#                          --set registryAuth.aws.irsa.roleArn=<role-arn>
# Any registry:            --set registryAuth.dockerConfigSecret=acr-pull  # a docker-config Secret
```

A per-image scan failure (e.g. a private image with no creds) is **tolerated** —
that finding is reported unscanned (`err` in the report) and the run continues.
Trivy also needs egress for its vuln DB (`ghcr.io/aquasecurity/trivy-db`) and, for
`exploitSource: public`, the CISA/FIRST feeds.

**Required inputs:** (1) the scan data — either `provider.mode: api` with your
tenant URL and an API-key Secret (preferred: current, and it reports why an image
was not assessed), or `provider.mode: csv` with the export as a Secret you refresh
out-of-band; (2) ownership + policy rules
(the chart ships editable examples in a ConfigMap via `config.ownership` /
`config.policy`); (3) optionally, a kubeconfig Secret for remote clusters, and
registry credentials if scanning private images. See
[`values.yaml`](deploy/helm/patchwright/values.yaml).

## Architecture & design

- [`docs/architecture`](docs/architecture) — C4 diagrams (LikeC4): system
  landscape, containers, the pipeline components, the assess flow, and the
  deployment topology. `likec4 start docs/architecture` to browse.
- [`docs/design`](docs/design) — design notes:
  [Trivy / fix-availability & exploitability](docs/design/trivy-integration.md),
  [remediation availability / upgrade path](docs/design/remediation-availability.md),
  the [MCP server](docs/design/mcp-server.md), and the
  [API-first server / Backstage](docs/design/api-server.md).

## Security

[SECURITY.md](SECURITY.md) covers what patchwright touches and what it deliberately
cannot do: the data it handles and how sensitive each kind is, the read-only cluster
RBAC (no Secrets access, no write verbs), every outbound connection and the flag that
enables it, the container's hardening, and the known limitations of the shared-token
authentication. Written for a security review as much as for operators.

## Roadmap

- **Phase 1** ✅ — noise-killer: CSV in, deduplicated, owner-attributed,
  actionable owner-split report out.
- **Phase 2** — in progress. ✅ multi-cluster live reconciliation (client-go
  `kube` + offline `file` live sources; drop not-running findings); ✅ ownership
  enrichment from live namespace labels like `team`; ✅ Helm chart + Docker
  image (CronJob, read-only RBAC, multi-cluster); ✅ kind-based e2e suite;
  ✅ Rapid7 API provider (`--mode api`), which also reports *why* an image was
  not assessed. Remaining: per-CVE detail from the API, so Trivy becomes
  optional.
- **Phase 3** — vulnerability intelligence.
  ✅ [fix availability](docs/design/trivy-integration.md) (`--vuln-source trivy`):
  scan each image once, populate `vulns` with `fix_available` / `fixed_version`.
  ✅ **exploitability** (`--exploit-source public`): annotate CVEs with EPSS +
  CISA KEV so rules require a fixable *and* exploited/likely CVE. Remaining:
  digest cache, VEX, `govulncheck`-style reachability, Rapid7-API vuln source.
- **Phase 4** — [remediation availability / upgrade path](docs/design/remediation-availability.md):
  detect deployment mechanism (Helm/Flux/Argo/manifest) and whether a newer
  version is available — the bridge to auto-remediation.
- **Phase 5** — [MCP server](docs/design/mcp-server.md) for less-technical users
  (natural-language queries over findings).
- **Phase 6** — Jira sink, then GitOps/Flux PR automation to roll fixes out.

## Development

```sh
make build             # build all packages + the binary into bin/patchwright
make check             # fmt + vet (incl. e2e build tag) + unit/golden tests
make test              # unit + golden tests (no cluster required)
make deps              # install kind + ginkgo for integration tests
make test-integration  # kind-based e2e suite (requires docker + kind)

# refresh the golden file after an intended output change
go test ./pkg/pipeline -run TestAssessGolden -update
```

### Running against your own data

Put your scanner export and (optionally) your own rules in `local/` — the whole
directory is gitignored:

```sh
make report       # assess local/*.csv with local/config, print to stdout
make report-live  # + reconcile against every kubeconfig context, + remediation,
                  #   saved to local/out/{findings.json,actionable.txt,run.log}
```

`report-live` defaults `CONTEXTS` to every kubeconfig context except local
`kind-*` clusters. Override any of it:

```sh
make report-live CONTEXTS=aks-prod-uk,aks-prod-us OUT=local/prod-only
make report-live SCAN=1          # add Trivy fix-availability + EPSS/KEV
```

Both files come from a **single** assessment, via repeatable `--output`:

```sh
patchwright assess ... \
  --output json:full=findings.json \    # everything, suppressed included
  --output table:queue=actionable.txt   # actionable only
```

`format[:view]=path` — the view is `full` (every finding, suppressed included)
or `queue` (actionable only); omit it to inherit `--all`/`--show-suppressed`.
Use `-` as the path for stdout. This matters once scanning is on: rendering two
formats with two commands re-runs the whole pipeline, re-reconciling every
cluster and re-scanning every image, for output that is already in hand.

The e2e suite (`test/e2e`, `//go:build e2e`) stands up a real kind cluster,
deploys a running Deployment and a completed Job, and asserts that the
client-go live source and full pipeline mark running images live and
completed/absent ones as not-running.
