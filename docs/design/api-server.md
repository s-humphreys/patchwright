# Design: API-first server (frontend, Backstage, Jira)

Status: **building** — `patchwright serve` (read-only API) is the current work.

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
`--interval`. Deployed as a **Deployment** (a Helm value flips the chart from the
assessment CronJob to the server), reading clusters exactly as the CronJob does.

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

1. **`serve` + read-only API** over an in-memory results cache (this work):
   findings/owners/summary + refresh + health; Helm Deployment mode.
2. **Jira sink** as an API-driven, stateless reconcile (stable finding key ↔
   issue label).
3. Auth; OpenAPI; Backstage plugin; optional web UI; MCP co-hosted.
