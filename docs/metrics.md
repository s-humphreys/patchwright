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
| `patchwright_findings_by_state{state}` | `actionable`, `suppressed`, `provider_assessed`, `provider_unassessed`, `scanned`, `exploit_checked`, `upgradable`, `known_exploited`, `remediation_unknown`, `actionable_unassessed`, `fallback_scanned`, `uncovered` |
| `patchwright_findings_unassessed_by_reason{reason}` | The provider's stated reasons |
| `patchwright_findings_fallback_failed_by_reason{reason}` | Why the fallback could not cover them either |
| `patchwright_owner_findings{class,team,state}` | `total`, `actionable`, `unassessed`, `ticketed` |
| `patchwright_owner_responsiveness{class,team,metric}` | `unstarted`, `stale_unstarted`, `in_flight_stale`, `median_age_days` |
| `patchwright_images_unique` | |

## Failures

| Metric | Notes |
|---|---|
| `patchwright_jira_requests_total{operation,outcome}` | `outcome` is `ok`, `auth_error`, `rate_limited`, `client_error`, `server_error`, `network_error` |
| `patchwright_ticket_actions_total{action,result}` | `result` is `applied`, `noop`, `failed` |
| `patchwright_image_scans_total{result}` | `ok`, `failed`, `skipped` |
| `patchwright_fallback_scans_total{result}` | `ok`, `failed`, `skipped` — scans of provider-unassessed images only |

## Alerting

```promql
# The provider's data going stale behind a freshly-generated report.
patchwright_provider_data_age_seconds > 86400 * 3

# Coverage lost to one fixable cause.
topk(3, patchwright_findings_unassessed_by_reason)

# The scan provider failing to assess images. Alert on THIS, not on `uncovered`:
# a fallback scanner covering the gap is not the provider working, and an alert
# that goes quiet because something compensated is an alert that never fires
# again when the provider degrades further.
patchwright_findings_by_state{state="provider_unassessed"} > 0

# The residual: findings nothing has any data for. A second, higher-severity
# threshold on the same problem.
patchwright_findings_by_state{state="uncovered"} > 0

# The safety net failing for one cause — usually the same registry credential
# the provider failed on.
topk(3, patchwright_findings_fallback_failed_by_reason)

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

## Responsiveness

The coverage series describe what is wrong. `patchwright_owner_responsiveness`
describes whether anyone is acting on it, which is the difference between a report
and an alert.

| Metric value | Meaning |
|---|---|
| `unstarted` | Actionable findings with an upgrade available, no open pull request and no ticket |
| `stale_unstarted` | Those older than the configured threshold. The one worth paging on: a fix has existed for a month and nothing has moved |
| `in_flight_stale` | Pull requests open past the threshold. Somebody did the work and it has not landed, which is a review bottleneck rather than an engagement one |
| `median_age_days` | Median age of actionable findings, dated from each one's oldest CVE |

`median_age_days` is **-1 when nothing here is dated**, which is not zero. Without
an age source no finding carries a date, and a dashboard that drew that as zero
would show a team with no history as the most current in the estate. Alert on the
difference, not on the value.

`stale_unstarted` counts only findings whose age is KNOWN, for the same reason:
without dates an unstarted fix is not evidence of anything, and counting it would
manufacture the signal out of missing data.
