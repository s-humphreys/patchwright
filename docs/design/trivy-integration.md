# Design: Trivy / per-CVE fix availability

Status: **core implemented** — `VulnSource` + image-level `ImageScanner` (post
dedupe) + a `trivy` source are wired through the pipeline, CLI
(`--vuln-source trivy`), and sinks (`FIXCRIT` / `fixable_critical`). Remaining:
digest cache, Trivy server mode, and a Rapid7-API vuln source (see "Phasing").

## Check before replacing this with a provider-native vuln source

**Open question, to be answered with evidence before dropping the scanner.**

The obvious simplification, once a provider exposes per-CVE detail over its API, is
to drop the separate image scan: the provider has already assessed the images, so
scanning them again looks like duplicated work. On the estate this was built
against, that reasoning does not hold, and the numbers are worth recording because
they are counter-intuitive.

From a real InsightCloudSec export of 4,311 rows covering 815 images:

    provider assessed          98 of 820 findings   (12%)
    never assessed            722 of 820           (empty last_assessment,
                                                    severity UNKNOWN, all counts 0)

The gap is not about private-registry access, which is the intuitive explanation.
Whole public registries were unassessed too: `xpkg.crossplane.io` (143 rows),
`registry.datadoghq.com`, `registry.istio.io`, `cr.agentgateway.dev`. And where the
scanner was allowed to look at those same public images, it found real work:

    14 of 35 actionable findings existed ONLY because the scanner ran

All fourteen were Crossplane packages, each with 2-3 fixable criticals, for which
the provider reported nothing at all.

So before treating a provider-native vuln source as a replacement:

1. Query the provider's API for an image it reported no data for in the export (a
   public one, to remove registry credentials from the question) and check whether
   it returns CVE detail and an assessment timestamp.
2. If it does, the export was the limitation and the API is a genuine coverage fix.
3. If it does not, the provider simply has not assessed those images, and removing
   the scanner deletes findings rather than duplicating them.

Either way, keep the scanner for deployments that do not use that provider, and
consider keeping it as a cross-check: on this estate the two disagreed on critical
counts in 40 of 68 jointly-covered findings, with the provider lower in 14 of them.

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

## Exploitability & reachability

Fix availability tells you a patch exists; it does not tell you the CVE is worth
acting on. That is layered on separately, in tiers of accuracy/cost:

- **EPSS + KEV — implemented** (`--exploit-source public`): each CVE is annotated
  with its FIRST EPSS score and CISA KEV membership, exposed to rules as
  `vulns[].epss` / `vulns[].kev`. Cheap (CVE-id lookups), no code analysis.
- **VEX — future:** consume producer VEX documents (Trivy supports this) to
  suppress "not affected" CVEs authoritatively.
- **Reachability — future, opt-in, language-scoped:** determine whether the
  vulnerable *symbol* is actually reachable in the image (e.g. `govulncheck` for
  Go binaries drops most unreachable "criticals"). High accuracy, high effort,
  per-language — a distinct enricher, not part of the base scan.

See also [remediation-availability.md](remediation-availability.md) for the
separate question of whether a fix is reachable via how the image is deployed.
