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

## Per-CVE detail without pulling images

`--vuln-source rapid7` takes the CVE detail from the platform that already scanned the
images, rather than scanning them again:

```sh
patchwright assess --provider rapid7 --mode api -o base-url=https://example.customer.divvycloud.com \
  -c config/ --vuln-source rapid7 --vuln-option base-url=https://example.customer.divvycloud.com
```

This matters where Trivy cannot help. Trivy pulls each image itself, so it needs
registry credentials wherever it runs — and on a private registry with no local
credentials that means no per-CVE detail for exactly the images an organisation cares
most about. The platform scanned those images from inside the account and hands over
what it found: severity, CVSS, its own risk score, whether a public exploit exists,
first-found dates, and the fixed version per CVE.

It supplies neither EPSS nor CISA KEV, because the API carries neither. Run
`--exploit-source public` alongside for those.

Per-image requests run 16 at a time, because a "scan" here is one HTTP request rather
than an image pull - at the scanner's cautious default of four, 768 images measured
2m19s of a ten-minute assessment, almost all of it waiting. `--vuln-option
concurrency=N` tunes it for a tenant whose rate limits are tighter or more generous.

`--age-source rapid7` and `--exploit-source rapid7` read the same endpoint, and it is
now swept once per assessment and shared: separately, each sweep was about two minutes
of that same run. The sweep is scoped to the run, so a later assessment fetches fresh
data rather than reusing intelligence from the last one.

The endpoint is keyed by resource rather than image, so the source maps each image to a
resource running it, preferring one the platform actually assessed — an unassessed
resource reports no CVEs, which would read as a clean image. An image no resource runs
is an error rather than an empty result, for the same reason.

## What a base rebuild would fix

A newer base image being available is not the same as knowing what moving to it
buys. Without that, every row asks a team for an upgrade of unknown value.

```yaml
remediation:
  baseDiff:
    enabled: true
    concurrency: 8
```

It scans the base image the finding was built on and the base it is being asked to
move to, then answers by subtraction:

| | |
|---|---|
| in the base as built | the base image's, not the team's |
| in the image, not in its base | the Dockerfile installed it, the team owns it |
| gone in the candidate base | this upgrade fixes it |

Which produces the sentence the queue was missing: *rebuilding clears 3,664 of these
4,890, and leaves 93 that are actually yours*. What the upgrade INTRODUCES is
reported too - an upgrade described only by what it fixes stops being trusted the
first time somebody checks.

Only BASE images are scanned, not the estate: on a real deployment that was about
110 distinct base tags against several thousand images, shared by everything built
on them and cached per digest. The cost is fixed in the number of bases. The first
run after a restart is the expensive one - 1m44s on that estate - and every run
after it reuses the cache until it expires.

```yaml
remediation:
  baseDiff:
    maxAge: 12h   # default; "never" to disable
```

That expiry is a correctness setting more than a performance one, and it is worth
understanding before changing it. A CVE **absent from the base scan is attributed to
the application**, which is the whole point of the subtraction. An image's own CVEs
are re-read every assessment, so if its base's scan is never re-read, every CVE
published against a base package afterwards is blamed on the team that builds the
image - for as long as the process lives, which on a server is weeks. The window
bounds how long that can be wrong for; twelve hours sits just above the daily cadence
of Trivy's own database updates.

`base_images_rescanned` in the run log counts scans discarded as too old, reported
apart from `base_images_scanned` because re-reading forty bases is different work from
finding forty new ones.

The base is identified by digest wherever the build recorded one, because a tag can
have moved since and scanning where it points now would credit the base's
since-fixed CVEs to the application.

It also names the package. For a CVE the base scan found, the package and the
version that fixes it come from the same pass, so the version always belongs to the
named package's ecosystem. Application-introduced CVEs carry no package: nothing
scanned that layer, and the provider's own per-CVE package field names an ecosystem
the image does not even contain 66% of the time - see
[docs/design/package-attribution.md](design/package-attribution.md) for the
measurement.

Needs the `trivy` binary (it ships in the image) and pull access to the base
images. Credentials are resolved through patchwright's own registry keychains and
handed to Trivy in an isolated docker config rather than letting it find its own -
see [SECURITY.md](../SECURITY.md).

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

### Combining sources

`--exploit-source` accepts a comma-separated list, and the fields are merged with the
first source to set one winning:

```
--exploit-source public,rapid7
```

- `public` supplies **EPSS** (FIRST.org, a probability between 0 and 1 of exploitation
  in the next 30 days), its **percentile**, and **KEV** (membership of CISA's Known
  Exploited Vulnerabilities catalogue).

  Both EPSS numbers are carried because either alone misleads. Almost every CVE
  scores near zero, so 0.08 reads as negligible and is in fact the 94th percentile;
  a high percentile with a low score is a crowded field rather than a real threat.
  Threshold on the score, read the percentile.
- `rapid7` supplies **`risk_score`**, the platform's own composite ranking, and
  `exploit_known` where it has a public exploit on record.

Keep them apart in rules. A risk score is a severity-and-exposure weighting on a scale
running to roughly 1000; EPSS is a probability. Writing `v.epss > 0.5` against a risk
score would match every CVE in an estate. Rapid7 exposes no EPSS and no KEV field at
all, so `public` is not optional if you want either — and KEV is worth taking from
CISA directly regardless, since any scanner's KEV flag is a copy of that catalogue.

Within a merged exploit source, one feed failing fails that lookup: an absent EPSS reads
as "not exploitable" to every rule that thresholds it, so it must not be silently treated
as zero.

But it does not fail the assessment. Transient HTTP failures — a 429, a 5xx, a dropped
connection — are retried with jittered backoff first, and if exploit intelligence still
cannot be gathered the run completes without it: `exploit_checked` stays false, every
EPSS and KEV cell reads "not checked" rather than "none found", and the failure is
reported in `source_failures` and on the page. One 502 from a public feed, one request in
a hundred, used to discard an entire completed scan.

`EPSS` is the highest score across the image's CVEs: one CVE at 0.93 makes the
image urgent however many quiet ones sit beside it.

Severity and exploitability diverge sharply. A CVSS 10.0 at EPSS 0.008 is a poorer
use of an afternoon than a CVSS 5 at EPSS 0.93; gating on `epss`/`kev` is what stops
the queue being sorted by fear.

## Ageing

`--age-source rapid7` dates each CVE from the scan provider's own first-seen times,
so the queue has a time dimension. Requires a vuln source: it stamps CVEs that
already exist.

```sh
patchwright assess -i export.csv -c config/ \
  --vuln-source trivy \
  --age-source rapid7 --age-option base-url=https://example.customer.divvycloud.com
```

The `AGE` column shows days since the oldest CVE on the image was first seen; JSON
carries `oldest_cve_days`, `oldest_cve_first_seen`, and `first_seen` per CVE. `-` and
an absent field mean no CVE is dated — no age source ran, or the provider has never
seen those CVEs. Nothing reports `0` for unknown, which would make everything look
new.

Nothing is stored locally. A state file would start empty, so every finding would
look new on the first run and ages would only become true months later.

One limit worth knowing: the provider reports when it first saw a CVE **anywhere in
the estate**, not on this image. For "how long have we known about this" that is
right; for "how long has this image been exposed" it can be earlier than the truth if
the image adopted the CVE later.

## How old is the image

First-party images carry a build date, read from the same image config the base
resolver already reads - so it costs no extra registry calls. The detail panel
shows it as "Image built 187 days ago".

It is there because most of a queue is not neglect. An image drifts because nothing
has rebuilt it, and the base it was built on has moved on since, so a finding is
usually less "you ignored this" than "this has not shipped since March". Those are
different conversations to have with a team, and no severity count tells them apart:
four hundred CVEs on an image built last week is a base image problem, and the same
count on one built a year ago is a release cadence problem.

Third-party images are not read. A vendor's build date is the vendor's business, and
reading it would mean a config blob per image for a fact nobody here can act on.

An image that records no date reports "not stated" rather than a date. Some builders
omit the field and some deliberately zero it for reproducibility, and treating that
as a timestamp would date them all to 1970 and sort them to the top of anything
ordered oldest-first.

## Turning scanning off in one environment

`scan.disabled: true` in a config file turns scanning off even when `--vuln-source` is
passed, so the same flags work on a laptop with no registry credentials and in a
cluster that has them. Set it in the local config file and leave it out of the
deployed one.

The run says so on startup, and findings still report `scanned: false`, so a run with
scanning off is never mistaken for one that scanned and found nothing.

## Without a vuln source

Every `vulns.exists(...)` rule is false, so the priority tiers built on them cannot
fire and the queue reads as calm when it is uninformed. The status page says so
explicitly, and the API reports `scanned` / `exploit_checked`.
