# Vulnerability scanning and exploitability

## Fix availability

`--vuln-source trivy` scans each unique image once, after dedupe, and populates
`vulns` with per-CVE detail including `fix_available` / `fixed_version`. Rules can
then require a fix before paging anyone. Needs the [`trivy`](https://trivy.dev)
binary; it pulls images itself, so it needs egress and credentials for private
registries.

```sh
patchwright assess -i export.csv -c config/ \
  --vuln-source trivy --vuln-option severity=CRITICAL,HIGH
```

| Option | Purpose |
|---|---|
| `severity` | Limit severities scanned, e.g. `CRITICAL,HIGH` |
| `binary` | Path to the trivy binary (default `trivy`) |
| `timeout` | Per-scan timeout (default `5m`) |
| `db-repository` | Vulnerability DB source, e.g. an internal mirror |

The DB download is retried three times, reaching past the default mirror list to
`ghcr.io/aquasecurity/trivy-db:2` from the second attempt — the mirror has served
404s for layers it had just advertised. A configured `db-repository` is kept on
retry rather than abandoned for the internet.

A per-image scan failure is tolerated: that finding reports `err` and the run
continues.

Surfaces as the `FIXCRIT` column, `fixable_critical` and the `vulns` array in JSON:

```yaml
when: "vulns.exists(v, v.severity == 'critical' && v.fix_available)"
```

## Exploitability

`--exploit-source public` annotates each CVE with its
[EPSS](https://www.first.org/epss/) score and
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
membership. It annotates CVEs that already exist, so it does nothing without a
vuln source.

```sh
patchwright assess -i export.csv -c config/ \
  --vuln-source trivy --exploit-source public
```

```yaml
when: "vulns.exists(v, v.fix_available && (v.kev || v.epss > 0.5))"
```

`EPSS` is the highest score across the image's CVEs: one CVE at 0.93 makes the
image urgent however many quiet ones sit beside it.

Severity and exploitability diverge sharply. A CVSS 10.0 at EPSS 0.008 is a poorer
use of an afternoon than a CVSS 5 at EPSS 0.93; gating on `epss`/`kev` is what stops
the queue being sorted by fear.

## Without a vuln source

Every `vulns.exists(...)` rule is false, so the priority tiers built on them cannot
fire and the queue reads as calm when it is uninformed. The status page says so
explicitly, and the API reports `scanned` / `exploit_checked`.
