# Design: Trivy / per-CVE fix availability

Status: **core implemented** — `VulnSource` + image-level `ImageScanner` (post
dedupe) + a `trivy` source are wired through the pipeline, CLI
(`--vuln-source trivy`), and sinks (`FIXCRIT` / `fixable_critical`). Remaining:
digest cache, Trivy server mode, and a Rapid7-API vuln source (see "Phasing").

## Why

Today "actionable" is decided **entirely by policy rules over the data we
already have** — severity counts, environment (via `dimensions`), ownership,
and liveness. There is **no live registry or CVE lookup**. So a finding is
"actionable" when, e.g., it has a critical and runs in Production and is live —
not because we've confirmed a fix exists.

The missing signal is **fix availability**: *is there a patched image/tag I can
actually move to?* A critical with no upstream fix is a very different task from
a critical that a version bump resolves. Trivy (or Grype, or the Rapid7 API)
provides exactly this per CVE (`FixedVersion`, fixed/won't-fix status).

The model already has the shape for it — `model.Vulnerability` carries
`FixAvailable` and `FixedVersion`, and policy already exposes a `vulns` list to
CEL. It's just not populated yet.

## Shape: an image-level enricher, after dedupe

Trivy should scan each **unique image once**, so it belongs **after dedupe** (a
few hundred images, not thousands of occurrences). This is a new enrichment
point on `AssessedImage`, distinct from the existing occurrence-level enrichers
(liveness, labels).

```go
// pkg/enrich — new capability
type VulnSource interface {
    Name() string
    // Scan returns per-CVE detail for one image reference.
    Scan(ctx context.Context, image model.Image) ([]model.Vulnerability, error)
}
```

- **`trivy` source**: shell out to `trivy image --format json --scanners vuln <ref>`
  (or Trivy server mode / the Go module) and map results → `model.Vulnerability`
  with `FixAvailable = FixedVersion != ""`.
- Pipeline: after `dedupe.ByImage`, run the vuln enricher per image, populating
  `AssessedImage.Vulns`; these flow into every `Finding` for that image.
- **Cache by image digest** — scans are expensive and images are immutable.
  Persist a digest→result cache so re-runs only scan new/changed images.

## Feeding actionability & prioritisation

Once `vulns` is populated, rules become sharper — all in config, no code change:

```yaml
actionable:
  # Only page someone when there's a critical with a fix to move to.
  - name: fixable-critical
    when: "vulns.exists(v, v.severity == 'critical' && v.fix_available)"
    priority: high
suppress:
  # A critical with no available fix isn't a patch task — track it elsewhere.
  - name: no-fix-yet
    when: "counts['critical'] > 0 && !vulns.exists(v, v.fix_available)"
```

Prioritisation can then rank by *fixable* critical count rather than raw counts,
which is a much better proxy for "cheap, high-impact work".

## Open questions

- **Registry auth.** Trivy must pull private images (e.g. the app registry).
  Supply credentials via the standard docker config / cloud keychain, mounted
  into the CronJob.
- **Where scanning runs.** In-cluster CronJob (needs egress + registry creds) vs
  a Trivy **server** patchwright queries (offloads DB updates and caching).
- **Redundancy with Rapid7.** Rapid7's API may already expose fix data; if so, a
  `rapid7` (api mode) `VulnSource` avoids a second scanner. Trivy stays valuable
  as a vendor-neutral / self-hostable option.
- **Cost.** Hundreds of scans per run — cache aggressively, scan incrementally,
  and consider only scanning images that reached an actionable finding.

## Phasing

1. `VulnSource` interface + image-level enrichment stage in the pipeline.
2. `trivy` source (CLI shell-out) + digest cache.
3. Example rules using `fix_available`; prioritise by fixable criticals.
4. Optional: Trivy server mode; `rapid7` api `VulnSource`.
