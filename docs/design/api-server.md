# Design: API-first server (frontend, Backstage, Jira)

Status: **read-only API shipped** (#14). `patchwright serve` runs the assessment
on a schedule, caches it, and serves findings / owners / summary / refresh /
health. The next increments are at the end of this document.

## Why

A CronJob that logs findings is write-only: nobody can *ask* it anything, and
stateful actions (like Jira ticketing without duplicates) are painful from a
fresh process each run. Turning patchwright into a **service with an API** is the
unlock:

- Security/engineering can query "what's actionable for team X right now?".
- Jira actioning becomes stateful and idempotent (reconcile findings ↔ tickets).
- A web UI, Backstage plugin, and the MCP server all become clients of one API.

The principle is **API-first**: one documented HTTP/JSON API is the source of
truth; the CLI, MCP, UI, and Backstage are clients of it.

## Decisions

- **No GitOps PR sink.** Flux + Renovate already own "newer version → PR". Our
  value is deciding *what's worth changing* and routing it; we hand the
  remediation `source` (chart repo / CR / git path) to a human or to Renovate,
  not open PRs ourselves.
- **Jira is the first action**, built on the API, next after `serve`.

## The server

`patchwright serve` runs the **same pipeline library** the CLI uses. It:

1. runs an assessment on a schedule and on demand,
2. caches the latest result (findings + timestamp + run status) in memory,
3. serves it over HTTP.

It takes the same inputs as `assess` (provider, `--config`, `--live-source`,
`--vuln-source`, `--exploit-source`, `--remediation`) plus `--addr` and
`--interval`. It is the chart's only deployment shape — a long-lived
**Deployment** (there is no CronJob mode; `assess` remains for local/CI runs).

## API (v1, read-first)

All responses carry an `assessment` block: `{ generated_at, running, error }`,
so clients know how fresh the data is.

| Method & path | Purpose |
|---|---|
| `GET /api/v1/findings` | Findings, filterable: `owner_class`, `team`, `priority`, `actionable`, `live`, `upgradable`, `known_exploited`, `suppressed`. |
| `GET /api/v1/findings/{image}` | One image (path-escaped ref): verdict, reasons, workloads, CVEs, upgrade. |
| `GET /api/v1/owners` | Per owner class/team: counts of total / actionable / fixable / upgradable — a triage leaderboard. |
| `GET /api/v1/summary` | Totals + the noise-reduction headline + the freshness block. |
| `POST /api/v1/assessments` | Trigger a refresh; returns 202 and the run status (async). |
| `GET /healthz`, `GET /readyz` | Liveness / readiness (ready once a first assessment has completed). |

Findings use the same JSON shape the CLI already emits (`sink.FindingView`), so
the schema is defined. An OpenAPI spec follows once the shape settles, to make
client generation (incl. the Backstage plugin) trivial. Auth (bearer/OIDC, then
per-team scoping) is a later phase; start bound to the cluster network.

## State — deliberately stateless to start

The server holds only the **latest assessment in memory** (a cache, rebuilt each
refresh). No database.

For **Jira reconciliation** (next feature), durable "finding → ticket" mapping is
needed to avoid duplicates. Approach, cheapest first:

1. **Stateless reconcile-from-Jira** (default): give each finding a **stable key**
   (e.g. `image + owner.team`), stamp it on the Jira issue (a label or a custom
   field), and each run query Jira by that key to decide create/update/close. No
   DB to operate; state lives in Jira.
2. Add a small persistent store (SQLite/Postgres) only if reconcile-from-Jira
   proves too slow or limited.

## Relationship to the MCP server

The [MCP server](mcp-server.md) and this REST API are two adapters over the same
pipeline + results cache; `serve` can host both, so natural-language and
programmatic access share one backend and one freshness guarantee.

## Phasing

1. ✅ **`serve` + read-only API** over an in-memory results cache:
   findings/owners/summary + refresh + health; Helm Deployment mode.
2. ✅ **Jira ticketing** — shipped as `patchwright ticket` (#16, #17), a CLI over
   a saved assessment rather than an API action. See "Correcting the drift".
3. Auth; OpenAPI; Backstage plugin; optional web UI; MCP co-hosted.

---

# Next increments

Written after running the tool against 11 live clusters and a 4,311-row export,
so the ordering reflects what the data actually showed rather than the original
guess at sequencing.

## Where we are

| Piece | State |
|---|---|
| `GET /api/v1/findings` + filters | done (`owner_class`, `team`, `priority`, `actionable`, `live`, `upgradable`, `known_exploited`, `suppressed`) |
| `GET /api/v1/finding?image=` | done |
| `GET /api/v1/owners` | done |
| `GET /api/v1/summary` | done |
| `POST /api/v1/assessments` | done (202 + run status) |
| `GET /healthz`, `GET /readyz` | done |
| Helm Deployment, read-only RBAC | done |
| Auth | none — bound to the cluster network |
| OpenAPI | none |
| Ticketing via API | no — CLI only |

The API serves `sink.FindingView`, so the provenance fields added since the
design was written (`provider_assessed`, `remediation_checked`,
`upgrade.resolved`, `upgrade.manager`) are already exposed for free. What is
missing is anything that *aggregates* them.

## 1. Make coverage a first-class API concept (highest value, smallest change)

`GET /api/v1/summary` reports findings / actionable / suppressed /
known_exploited / upgradable / unique_images. On the estate we tested, the honest
headline is not in that list:

    820 findings, 35 actionable
    98 of 820 assessed by the scan provider   (12%)
    697 of 820 with no resolvable upgrade     (85%)

A consumer reading only that summary — a dashboard, Backstage, an MCP answer —
sees "35 actionable" and concludes the estate is in good shape, when the truth is
that most of it was never looked at. The report learned this lesson the hard way
(CRIT `?` rather than `0`); the API has not learned it yet, and every future
client inherits whatever the summary implies.

- Add to `summaryView`: `provider_assessed`, `provider_unassessed`,
  `remediation_unresolved`, and `images_unassessed`.
- Add filters: `provider_assessed`, `remediation_checked`, `upgrade_resolved`.
- Add `unassessed` to `ownerStats`, since coverage is wildly uneven by team
  (engineering 9/651 vs platform 37/101) and that asymmetry is invisible today.

Cheap, no new endpoints, and it stops every downstream client from repeating the
mistake independently.

## 2. Correcting the drift: ticketing behind the API

This document says "Jira is the first action, **built on the API**". It shipped as
a CLI reading a saved `findings.json`. That was the right call for getting it
working — planning is pure and reviewable, and a dry run costs nothing — but it
leaves the stated principle unmet, and two consequences follow:

- Ticketing cannot be triggered by anything other than a person at a terminal
  with the config and a credential.
- The service and the CLI can disagree about what is actionable, because they may
  be looking at different assessments.

Proposal, keeping `pkg/ticket` exactly as it is (it is already free of transport):

    POST /api/v1/tickets          { "dry_run": true }   -> the plan: drafts + skips
    POST /api/v1/tickets          { "dry_run": false }  -> creates, returns keys
    GET  /api/v1/tickets          -> last run's drafts/skips/created

Constraints that must survive the move:

- **Dry run stays the default.** `dry_run` absent means true. A POST that creates
  Jira issues by omission is the wrong default for an HTTP API.
- **The plan is computed from the cached assessment**, so the API answers "what
  would you raise from the data you are serving?" rather than from a file.
- **Jira credentials stay in the environment**, never in a request body.
- Idempotency is unchanged: query Jira by image, skip when an open ticket exists.

Open question worth settling before building: should creation be allowed at all
over HTTP, or should the API expose only the *plan* and leave creation to the CLI
and CI? A read-only API with a `plan` endpoint is a smaller blast radius and still
lets a UI show "here is what would be raised".

## 3. Ticket reconciliation (needs 2)

Today ticketing only creates. The design's "reconcile findings ↔ tickets" implies
two more verbs, both now cheap because `upgrade.resolved` and
`remediation_checked` make the states unambiguous:

- **Update** an open ticket when the target version moves on (its summary says
  0.20.1, latest is now 0.21.0) — a comment, not a silent edit.
- **Close, or comment and let a human close**, when a finding disappears because
  the upgrade landed. Distinguishing "fixed" from "no longer scanned" is exactly
  what `provider_assessed` is for; closing a ticket because coverage lapsed would
  be a serious misstep.

## 4. OpenAPI spec

Deliberately after 1-3. The finding schema gained four fields in one day of real
use; publishing a spec over a shape still moving generates clients that break.
Once coverage fields and the ticket endpoints settle, generate the spec from the
Go types and treat it as the contract. This is the prerequisite for the Backstage
plugin, not the plugin itself.

## 5. Auth

Currently unauthenticated and reachable from the cluster network. That is
defensible while the API is read-only and internal. Two triggers make it urgent:

- exposing it beyond the cluster (a UI or Backstage outside the mesh), or
- adding write endpoints (increment 2) — an unauthenticated endpoint that creates
  Jira issues is an obvious abuse vector.

Start with a bearer token from a secret, then OIDC, then per-team scoping so a
team's findings are only visible to that team (`/api/v1/findings` already filters
by `team`, so scoping is a matter of binding identity to that filter).

## 6. MCP co-hosted

Unchanged from [mcp-server.md](mcp-server.md): the same cache and pipeline behind
a second adapter, so natural-language and programmatic access share one freshness
guarantee. Worth doing after the OpenAPI spec, since the MCP tool definitions and
the REST schema should not be described twice by hand.

## Recommended order

1 → 2 (plan-only first) → 5 (auth, before any write endpoint ships) → 3 → 4 → 6.

Increment 1 is a couple of hours and improves every existing consumer. Everything
after it is a real feature, and 2 has a design question to settle first.
