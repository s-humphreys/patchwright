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

## When the line itself is dead

Everything above assumes there is somewhere to go on the current line. Sometimes there is
not, and that case is worth separating because it is the one a vulnerability queue reports
most misleadingly.

An image pinned to a runtime's end-of-life major sits on the last build of that tag
forever. Nothing newer will be published to it, so a version comparison finds nothing and
a digest comparison sees a digest that never moves. Both report "no upgrade available",
which renders as an empty Fix column, which reads as nothing-to-do — on the one image in
the queue whose CVE count only ever goes up, because no fix is coming to it at all.

A real example. An image built on `docker.io/node:20-alpine`, four months after Node 20
went end of life: 369 CVEs, 23 of them critical, 147 with a published vendor fix that will
never reach the image, and a Fix column showing nothing.

Turn support checking on and it says so instead:

```sh
patchwright assess -c config/ --remediation --support-source endoflife
```

```
FIX  PRIORITY  IMAGE                      UPGRADE
eol  urgent    …/nightwatch-orchestrator  end of life: move to nodejs 24
```

### Why not simply recommend the newest

Because the newest major of a runtime is frequently one nobody should adopt yet, and a
recommendation a team is right to ignore is worse than none: it spends the credibility the
next one needs.

When Node 20 died the registry held `22-alpine`, `24-alpine` and `26-alpine`. Node 26 was
maintained, and its LTS promotion was still two months away — so the takeable answer was
24, the newest line that is **both** maintained **and** already long-term supported.
That is the recommendation, and it changes on its own as dates pass rather than when
somebody remembers to edit a table.

Three lines are reported, because they answer different questions:

| | |
|---|---|
| **recommended** | newest maintained and already LTS. The default answer. |
| **nearest** | smallest supported move. When the recommended jump is too far to plan this quarter, this is the one that stops the bleeding. |
| **newest** | what exists, named but not recommended, so nobody has to go and check. |

Products with no LTS designation at all — Alpine, Python, Go — are not held to the LTS
test, or nothing would ever be adoptable.

### What it will not do

The recommended tag is **verified against the registry** before it is offered. If
`24-alpine` upstream exists but this repository has no such tag, no upgrade is named: a
fix that 404s is worse than an honest blank, and the end-of-life verdict still stands on
its own.

The suffix is preserved across the move, so `20-alpine` becomes `24-alpine` and never a
bare `24`. Dropping it would swap the operating system underneath the application and call
it an upgrade.

An in-track upgrade still wins where one exists. On a line with newer patches, the safe
rebuild is the better first move and a migration can follow; the out-of-track
recommendation appears only when there is nothing left in track.

### Not checked is not supported

Support status has three states, and the third is the reason this is not a boolean:

- **maintained**, with the date it ends
- **not maintained**, with the date it ended
- **not checked** — no support source ran, or the base image is not one the source
  recognises

"Not checked" renders as not checked. It is never rendered as supported, and never as
end-of-life: an estate nobody has data for must not be escalated, and the images that most
need the flag must not be quietly cleared.

### Naming your own base images

The built-in table covers the common upstream bases. A first-party base image is
unrecognisable from its path, so declare what it is built from:

```yaml
remediation:
  supportProducts:
    example.azurecr.io/dotnet/aspnet/10: dotnet
    example.azurecr.io/internal/base: ""      # suppress the check entirely
```

Names are [endoflife.date](https://endoflife.date) products. Matching is on trailing path
segments, so a mirror prefix does not defeat it, and an override outranks the built-in
table.

### Using it in policy

The verdict reaches rules as the `end-of-life` signal and the `end_of_life` variable, so
what to do about it stays a policy decision:

```yaml
actionable:
  - name: end-of-life-base
    when: "end_of_life && counts.critical > 0"
    priority: urgent
```

`end_of_life` is false for an unchecked base as well as a maintained one. A rule that
needs to tell those apart should read `signals`, where absence asserts nothing.

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
