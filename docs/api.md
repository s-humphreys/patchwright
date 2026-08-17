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
| `GET /api/v1/findings` | Findings, filterable by `owner_class`, `team`, `priority`, `actionable`, `live`, `upgradable`, `known_exploited`, `suppressed`, `provider_assessed`, `remediation_checked`, `upgrade_resolved` |
| `GET /api/v1/finding?image=<ref>` | One image's finding |
| `GET /api/v1/owners` | Per-team triage, including where the fix goes and how much is ticketed |
| `GET /api/v1/summary` | Fleet headline, coverage counts, and `unassessed_reasons` |
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

A shared token has no identity and no per-team scoping. Put OIDC in front for
anything beyond a trusted network.

## Ticket state

Given a `jira:` block and credentials, each refresh indexes the project's open
tickets — one JQL query per configured project, not one per image — and returns them
alongside findings as `tickets`, keyed by image repository. Without the config or
credentials the key is absent, meaning *unknown* rather than "no ticket exists".

Writes are opt-in: `--auto-ticket` applies the plan on every refresh, and the
endpoints work either way. Every refresh logs the plan whether or not it will be
applied.

## Pending ticket actions on the page

The page lists writes that reconciliation would make — creations, rewrites, closes and
comments — with the tracker each lands on, and says whether a scheduled refresh will
apply them. Skips are counted rather than listed.

Read-only: there is no apply button. A POST that writes to a tracker should not be one
click away from a dashboard behind a shared token. It refreshes on demand rather than
with the page's polling, because computing the plan queries Jira.

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
