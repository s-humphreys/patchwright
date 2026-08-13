# CLI

Four commands. Logs go to stderr, so stdout stays pipeable.

| Command | Purpose |
|---|---|
| `profile` | Quantify the raw data before writing rules: volume, dedupe headroom, breakdown by dimension |
| `assess` | Deduplicate, attribute owners, apply policy, report |
| `ticket` | Raise and reconcile tickets from a saved assessment ([ticketing](ticketing.md)) |
| `serve` | Run the assessment on a schedule behind an HTTP API ([API](api.md)) |

```sh
patchwright profile -i export.csv
patchwright assess -i export.csv -c config/
patchwright assess -i export.csv -c config/ --owner engineering --format json
patchwright assess -i export.csv -c config/ --all --show-suppressed
```

## Flags

| Flag | Purpose |
|---|---|
| `--provider` | Scan-data provider (default `rapid7`) |
| `--mode` | Provider mode: `csv` or `api` ([providers](providers.md)) |
| `-i`, `--input` | Input path for the provider |
| `-o`, `--option` | Provider option as `key=value`, repeatable |
| `-c`, `--config` | Config file or directory, repeatable |
| `-f`, `--format` | `table` or `json` |
| `--output` | `format[:view]=path`, repeatable (see below) |
| `--owner` | Only findings for this owner class |
| `--all` | Include non-actionable findings |
| `--show-suppressed` | Include suppressed findings |
| `--live-source`, `--live-option` | [Live reconciliation](reconciliation.md) |
| `--vuln-source`, `--vuln-option` | [Vulnerability scanning](scanning.md) |
| `--exploit-source`, `--exploit-option` | EPSS + KEV enrichment |
| `--age-source`, `--age-option` | Date CVEs from the provider's first-seen times |
| `--remediation` | [Upgrade detection](remediation.md) |
| `--log-level`, `--log-format` | `debug`\|`info`\|`warn`\|`error`, `text`\|`json` |

## Multiple outputs from one run

`--output format[:view]=path` writes several renderings from a single assessment.
The view is `full` (every finding, suppressed included) or `queue` (actionable
only); omit it to inherit `--all` / `--show-suppressed`. Use `-` for stdout.

```sh
patchwright assess -i export.csv -c config/ --remediation \
  --output json:full=findings.json \
  --output table:queue=actionable.txt
```

Two commands would re-run the whole pipeline — re-reconciling every cluster and
re-scanning every image — for output already in hand.

## Reading the report

The table prints a legend above the data. Four different unknown-states appear in
it and they mean different things:

| Mark | Meaning |
|---|---|
| `CRIT ?` / `HIGH ?` | the scan provider never assessed this image; the counts are absent data, not zero |
| `FIX ?` | upgrade detection did not run (no `--remediation`) |
| `FIX unknown` | detection ran but could not resolve a version, e.g. an unreadable private registry |
| `UPGRADE ?` | as `FIX ?` |
| `EPSS -` / `KEV -` | exploit enrichment did not run, so `0.00` always means "checked, nothing" |
| `AGE -` | no CVE on the image is dated: no age source ran, or the provider has not seen them |
| `TEAM -` | no ownership rule attributed the workload to a team |

Unassessed findings stay in the queue. They can never match a count-based rule,
which is a coverage gap to close rather than a verdict.

Do not fall back to the namespace name in `teamFrom`: it renders identically to a
real team and launders "we don't know" into an answer. `NAMESPACE` already shows
where a workload runs.
