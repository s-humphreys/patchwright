# Remediation

Knowing a CVE has a fix is half the answer; the other half is whether you can ship
it given how the workload is deployed. `--remediation` composes ordered upgrade
sources, deployment-aware first.

1. **Flux Helm chart** (needs `--live-source kube`) — reads `HelmRelease`s,
   resolves each chart's repository, checks the index for a newer chart version.
2. **Registry image tag** — for images on a strict-semver tag, checks the registry
   for a newer tag. Auth via the docker/cloud keychain.

```sh
# charts and image tags
patchwright assess -i export.csv -c config/ \
  --live-source kube --live-option contexts=aks-prod --remediation

# image tags only, no cluster needed
patchwright assess -i export.csv -c config/ --remediation
```

## Actionability

An upgrade is *directly actionable* only if you can apply it at that level. A newer
image tag for a workload controlled by a Helm chart or an operator is reported as
available but not actionable — bumping the tag would be reverted. The
`upgrade_available` rule variable is true only for actionable upgrades; JSON carries
`available`, `actionable`, `managed`, `resolved` and `source`.

## Columns

`UPGRADE`:

| Shown | Meaning |
|---|---|
| `current→latest` | a newer version applicable directly |
| `chart current→latest` | a newer chart version, not the image tag |
| `current→latest (helm\|operator)` | newer version exists but is controlled elsewhere |
| `-` | on the latest version |
| `?` | detection did not run |

`FIX` condenses that into the remediation path:

| Shown | Meaning |
|---|---|
| `direct` | can move now |
| `managed` | a chart or operator owns the tag; fix it there |
| `none` | already on the latest version |
| `unknown` | detection ran but no version could be resolved |
| `?` | detection did not run |

`none` stays visible: criticals with nowhere to go need a human decision, which is
a different conversation from bumping a tag. `unknown` and `?` are kept apart
because they demand opposite responses. Anything skipping findings without an
upgrade must check `remediation_checked`, or it silently skips images whose
versions merely could not be resolved.

Group headers repeat the split, since "32 actionable" of which 9 are `direct` is a
different day's work from 32 direct bumps:

```
== owner class: platform (32 findings, 32 actionable: 9 direct, 20 managed, 3 none) ==
```

## First-party images

For an application image you build yourself, a newer tag is a release number, not a
fix — the CVEs live in the base image. Name your registries and the base becomes the
remediation path:

```yaml
remediation:
  firstPartyRegistries: [registry.example.com]
```

For those images the tag source stays quiet, and instead patchwright reads the base
reference the image records about itself — `org.opencontainers.image.base.name`, or
BuildKit's `image.base.ref.name`, or any key you name in `remediation.base.refLabels`
— and checks whether that base has a newer version. The reported upgrade is the base:
`base dotnet/aspnet/10 1.0.2 → 1.1.1`, actionable by rebuilding.

Three behaviours worth knowing:

- **Comparison stays on the same track**: same major, and same suffix. Base images use
  the semver prerelease slot to mark a variant, so `10.0.3-azurelinux3.0` upgrades to
  `10.0.11-azurelinux3.0` and never to plain `10.0.11`, which would swap the operating
  system and call it a patch.
- **Chains are followed** while each base is first-party, up to
  `remediation.base.maxDepth` (4). An application on the newest available base whose
  base is itself behind reports that link, so the ticket reaches whoever can move it.
- **A floating base tag** has no version to compare, so the recorded base digest is
  compared against what the tag resolves to now. The report names the tag rather than
  only the digests, because two hashes say nothing and the tag is the line in the
  Dockerfile:

  ```
  base mcr.microsoft.com/dotnet/aspnet:10.0-alpine moved 1e37a8236c55 → c4b29bf36800
  ```

  JSON carries `comparison: "version" | "digest"` so a consumer knows which it is
  looking at. Base names are registry-qualified throughout: a bare `dotnet/aspnet` is
  ambiguous between an internal mirror and the upstream it was copied from, and those
  have different owners.

An image that records no base is reported **unresolved with the reason**, never "no
upgrade": the fix there is a build-system change, and naming it is the point.

Design notes: [design/base-image-remediation.md](design/base-image-remediation.md).

## How far to upgrade

"Newest available" is the wrong recommendation often enough to matter. A Python base on
`3.12.3` has both `3.12.14` and `3.14.7` published. Recommending `3.14.7` asks a team to
migrate a runtime, and their dependency tree may not be ready — so the finding sits in
the queue looking like neglect, while the patch bump that would have closed the same
CVEs goes unmade.

```yaml
remediation:
  upgrade:
    strategy: latest          # patch | minor | latest
    rules:
      - name: docker.io/python
        strategy: patch       # the minor is the compatibility boundary for a runtime
        ceiling: "3.12"       # never recommend beyond this
        until: 2026-12-31     # when the ceiling lapses
        reason: dependencies are not 3.14 ready
      - name: mcr.microsoft.com/dotnet/*
        strategy: minor
```

`strategy` sets the distance: `patch` stays on the current minor, `minor` on the current
major, `latest` takes the newest in track. Rules match an image name, optionally with a
trailing `*`, and the first match wins.

A **ceiling** is for a constraint somebody actually knows — a runtime minor a dependency
tree cannot take yet. It is better than suppressing the finding, because patch upgrades
keep flowing: the CVEs stay fixable while the migration waits. `until` matters for the
same reason a suppression needs one: a constraint with no end date becomes permanent by
accident. An **expired ceiling is not applied**, and is reported as expired so somebody
revisits the decision rather than the estate being held back silently.

Both moves are reported. `latest` is what to do now, `newest` is what exists, and a
consumer offers the reader both rather than choosing:

```
base docker.io/python 3.12.3 → 3.12.14   newest 3.14.7
```

Not every ecosystem needs a rule. Whether the default is already right depends on
where the ecosystem puts its compatibility boundary relative to semver:

| Base | Shape | Default behaviour |
| --- | --- | --- |
| Python | `3.12.3`, minor inside the major | **Needs a rule.** Same-major allows 3.12 → 3.14, a runtime migration. |
| .NET | `10.0.3`, minor always 0 | Already right: same-major means patch, 10.0.3 → 10.0.11. |
| .NET SDK | `10.0.100`, feature band in the patch field | Watch it: 10.0.100 → 10.0.400 is a tooling jump that looks like a patch. Hold a band with `ceiling: "10.0.199"`, which is an upper bound rather than a prefix. |
| An internal mirror | `dotnet/aspnet/10:1.1.1` | The strategy applies to the mirror's own numbering, not the runtime's — the runtime major is pinned by the path. |

Where policy recommends nothing at all but newer versions exist, the finding is
`held_back` rather than `none`. "None" would say the image is up to date, which is a
different thing.

## Remediation already in flight

An upgrade somebody has already opened a pull request for is not work waiting on a
decision, it is work waiting on a review. Detection reports it so the two can be told
apart:

```yaml
remediation:
  inFlight:
    provider: azuredevops
    organisation: example
    projects: [DevOps, Apps]
    authors: [renovate@example.com]   # optional; empty means any author
    # Author matching is exact, and a bot's identity is usually an email: check
    # what your provider reports before relying on this filter.
    branchPrefixes: [renovate/]       # optional; empty means any branch
    staleAfterDays: 14
  base:
    repoLabels:
      - com.azure.dev.image.build.repository.name
      - org.opencontainers.image.source
```

The token comes from `AZURE_DEVOPS_PAT` (code read scope). A missing token is an
error rather than an empty result: an unauthenticated run would report no pull
requests at all, which is indistinguishable from nothing being in progress.

A match requires all three of:

1. **The pull request is in the repository that builds this image**, read from
   `remediation.base.repoLabels`. A pull request bumping a shared base image in the
   base-image repository does not fix the applications consuming that base, which
   still have to rebuild. Without this constraint one such pull request silences
   every finding that asks for exactly that rebuild.
2. **The dependency matches exactly.** The pull request title is parsed for the
   dependency and target version rather than searched for a substring, because
   `dotnet/aspnet` is a prefix of `dotnet/aspnet/10` and a substring check reports
   the wrong dependency with full confidence.
3. **The target version matches.** A pull request bumping the same dependency to a
   different version is reported as a possible match (`exact: false`, shown as
   `PR?`) and must never be read as this upgrade being applied.

Output: `in_flight` per finding in JSON, an **In flight** column on the queue, and
`in_flight` / `in_flight_possible` / `in_flight_stale` in the summary. Every one of
them is paired with `in_flight_checked`, because zero matches with detection off
means "we did not look", not "nobody has started".

Ticketing is unchanged: nothing is suppressed, closed or deprioritised on the basis
of a match. Match quality has to be judged against a real estate first.

Design notes: [design/remediation-in-flight.md](design/remediation-in-flight.md).

Git/OCI source revisions are also outstanding:
[design/remediation-availability.md](design/remediation-availability.md).
