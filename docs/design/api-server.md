# Design: API-first server (frontend, Backstage)

Status: **proposed** (planned for later — agreed)

## Why

The assessment output is valuable to people who won't touch a CLI — engineering
leads, service owners, risk. They want a **live view** of what their team owns
and needs to act on. And it should be consumable by other tools, e.g. a
**Backstage plugin** that shows a service's actionable findings on its catalog
page.

The unlock is to be **API-first**: a stable, documented HTTP/JSON API is the
source of truth, and everything else — the CLI, the [MCP server](mcp-server.md),
a web UI, a Backstage plugin — is a client of that same API. Nothing bypasses it.

## The server

A `patchwright serve` mode built on the **same pipeline library** the CLI uses.
It runs assessments on a schedule (and on demand), caches the latest result, and
serves it. Deployed as a Deployment (a Helm value flips the chart from the
assessment CronJob to a long-running server), reading clusters exactly as the
CronJob does.

## API (read-first, versioned `/api/v1`)

Returns the existing finding view (the JSON the CLI already emits), so the model
is already defined.

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/findings` | Findings, filterable: `owner`, `team`, `priority`, `actionable`, `live`, `upgrade_available`, `known_exploited`. |
| `GET /api/v1/findings/{image}` | One image: verdict, reasons, workloads, CVEs, upgrade. |
| `GET /api/v1/owners` | Per owner class / team: counts of actionable / fixable / upgradable — a triage leaderboard. |
| `GET /api/v1/summary` | Totals + the noise-reduction headline. |
| `GET /api/v1/profile` | The raw-data profile. |
| `POST /api/v1/assessments` | Trigger a refresh; results are async, polled via a status field. |
| `GET /healthz` `GET /readyz` | Health. |

Every response carries the **assessment timestamp** so clients can show how
current the data is. A published **OpenAPI** spec makes client generation
(including the Backstage plugin) trivial. Auth: bearer token / OIDC, with
per-team scoping later.

## Backstage plugin

Backstage models ownership as groups; patchwright already attributes each finding
to a `team`. So a plugin maps **Backstage entity owner ↔ patchwright `owner.team`**
and, on a service's catalog page, shows that service's actionable findings, fix
availability, exploitability, and **available upgrades** — the same signals, in
the place engineers already look. It's a thin frontend (+ a small backend proxy
for auth) over `GET /api/v1/findings?team=…`. For now we won't implement this, only
bear it in mind during designs for later implementation.

## Web UI

Optional and secondary to the API: a lightweight owner-split dashboard (live
view, filters, the priority queue) served by the server. Given Backstage covers
the per-team view, a standalone UI is mainly for security's fleet-wide view.

## Relationship to the MCP server

The [MCP server](mcp-server.md) and this REST API are two adapters over the same
pipeline + results cache. The `serve` process can host both (REST for
apps/Backstage, MCP for LLM clients), so natural-language and programmatic access
share one backend and one freshness guarantee.

## Phasing

1. `serve` with a results cache + read-only `GET` endpoints + OpenAPI.
2. `POST /assessments` refresh + async status; auth.
3. Optional fleet-wide web UI; MCP co-hosted.
