# Metrics

`GET /metrics` serves Prometheus metrics prefixed `patchwright_`, plus the standard
`go_*` and `process_*` collectors. Unauthenticated by default; `metrics.requireAuth`
(or `--metrics-require-auth`) brings it under the API token.

Enable scraping with `metrics.serviceMonitor.enabled` — a ServiceMonitor is the
default choice since server mode has a Service — or `metrics.podMonitor.enabled`.
Enabling both is refused: two monitors on one target double every counter.

## Assessment health

| Metric | Notes |
|---|---|
| `patchwright_assessment_runs_total{result}` | `success` / `failure` |
| `patchwright_assessment_duration_seconds` | Most recent completed run |
| `patchwright_assessment_last_success_timestamp_seconds` | |
| `patchwright_provider_data_age_seconds` | Age of the newest timestamp in the **provider's** data, or `-1` when it reports none |
| `patchwright_provider_fetches_total{result}` | |

## Coverage

| Metric | Notes |
|---|---|
| `patchwright_findings` | Unsuppressed findings |
| `patchwright_findings_by_state{state}` | `actionable`, `suppressed`, `provider_assessed`, `provider_unassessed`, `scanned`, `exploit_checked`, `upgradable`, `known_exploited`, `remediation_unknown`, `actionable_unassessed` |
| `patchwright_findings_unassessed_by_reason{reason}` | The provider's stated reasons |
| `patchwright_owner_findings{class,team,state}` | `total`, `actionable`, `unassessed`, `ticketed` |
| `patchwright_images_unique` | |

## Failures

| Metric | Notes |
|---|---|
| `patchwright_jira_requests_total{operation,outcome}` | `outcome` is `ok`, `auth_error`, `rate_limited`, `client_error`, `server_error`, `network_error` |
| `patchwright_ticket_actions_total{action,result}` | `result` is `applied`, `noop`, `failed` |
| `patchwright_image_scans_total{result}` | `ok`, `failed`, `skipped` |

## Alerting

```promql
# The provider's data going stale behind a freshly-generated report.
patchwright_provider_data_age_seconds > 86400 * 3

# Coverage lost to one fixable cause.
topk(3, patchwright_findings_unassessed_by_reason)

# Ticketing stopped because credentials expired, which otherwise looks
# identical to having no work to raise.
increase(patchwright_jira_requests_total{outcome="auth_error"}[15m]) > 0

# Nothing has completed an assessment recently.
time() - patchwright_assessment_last_success_timestamp_seconds > 7200
```

A counter appears on first occurrence, so write alerts as `increase(...) > 0` rather
than comparing an absent series to zero.

## Cardinality

No per-image or per-CVE labels: 800 images would be 800 series behind one metric, and
the JSON API answers at that grain. Jira paths reduce to bounded operation labels.
Provider reason strings are trimmed to their first clause and capped, with the tail
summed into `other`. Gauges reset between assessments, so a team that leaves the
estate stops being reported rather than freezing at its last value.
