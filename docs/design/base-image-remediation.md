# Fix availability for first-party images

## The problem

For a third-party image, "is a fix available" is answered by the registry: is there a
newer tag. For a first-party application image it is not. Our tags are release
numbers — `1.0.79`, `1.0.381-rc` — and a newer one means somebody shipped application
code, which says nothing about the CVEs. Those live in the base image.

So the useful question is: **is there a newer base image, and would it fix these
CVEs?**

## What is already there

Verified against the live registry, so this design starts from fact rather than
assumption. Taking one real image:

```
registry.example.com/poc-credit-approval-jobs:1.0.79
```

Its config carries the base explicitly:

```
image.base.ref.name  = registry.example.com/dotnet/aspnet/10:1.0.5
image.base.digest    = sha256:395636da1552e928c52620806dd8de096a6d4073f8141659b1d4663fbae…
```

It also carries a SLSA provenance attestation listing every resolved input, which
distinguishes the runtime base from build-only stages:

```
pkg:docker/registry.example.com/dotnet/aspnet/10@1.0.5   ← final stage
pkg:docker/registry.example.com/dotnet/sdk/10@1.1.0      ← build stage only
pkg:docker/docker/dockerfile@1-labs
```

And the base is itself first-party, with its own base recorded:

```
registry.example.com/dotnet/aspnet/10:1.0.5
  → image.base.ref.name = mcr.microsoft.com/dotnet/aspnet:10.0.7-azurelinux3.0
```

Tags available for `dotnet/aspnet/10`: `1.1.1`, `1.1.0`, `1.0.5`, `1.0.4`, … so this
application is two minor base versions behind, and that is the actionable fact the
queue cannot currently state.

Also in the labels, for free: the ADO repository, build definition, branch and commit
that produced the image. The remediation is "re-run that pipeline once the base moves",
and we can name the pipeline.

## Survey of the estate

All 707 first-party images running across the clusters, read from the registry:

| | |
|---|---|
| Declare a base image in their config labels | **699 (99%)** |
| Carry a base digest label | 698 |
| Carry a SLSA provenance attestation | 665 |
| Name their ADO repository | 700 |
| Pin their base by digest instead of a tag | 0 |

Every one of the 699 uses the key `image.base.ref.name`, not the OCI standard
`org.opencontainers.image.base.name`. Both are worth reading, in that order.

Of those, 459 are built on a **first-party** base, and only **nine** base repositories
account for all of them:

| Images | Base | On | Newest | Behind |
|---|---|---|---|---|
| 183 | `dotnet/aspnet/10` | 1.0.2 | 1.1.1 | 5 |
| 88 | `dotnet/aspnet/10` | 1.0.5 | 1.1.1 | 2 |
| 46 | `dotnet/aspnet` | 8.0.13 | see below | — |
| 38 | `dotnet/runtime/10` | 1.0.2 | 1.1.1 | 5 |
| 17 | `dotnet/aspnet/10` | 1.0.4 | 1.1.1 | 3 |

**445 of 459 (97%) are on an outdated base.** One bump — `dotnet/aspnet/10` to 1.1.1 —
covers 183 images by itself.

The internal bases are mostly current with upstream, so the work is in the
applications rather than the base pipelines:

```
dotnet/aspnet/10:1.1.1   → mcr.microsoft.com/dotnet/aspnet:10.0.11-azurelinux3.0  (current)
dotnet/runtime/10:1.1.1  → mcr.microsoft.com/dotnet/runtime:10.0.11-azurelinux3.0 (current)
dotnet/aspnet:10.0.1     → mcr.microsoft.com/dotnet/aspnet:10.0.1-azurelinux3.0   (10 patches behind)
```

The last is the legacy repository naming (`dotnet/aspnet` rather than
`dotnet/aspnet/10`); images still on it are behind twice over.

## Three remediations, three owners

The single word "fix" hides three different jobs, and conflating them is what makes a
queue unactionable:

| CVE lives in | Remediation | Owner |
|---|---|---|
| Base image OS packages | Rebuild on a newer base tag | the application team, via its pipeline |
| Base image, no newer tag | Rebuild the base from upstream | whoever maintains `dotnet/aspnet/10` |
| Application dependencies (NuGet, npm, Go) | Bump the dependency | the application team, in its repo |

A base bump does not fix a NuGet CVE, and saying it does would be worse than saying
nothing. So attribution matters as much as availability.

## Design

### 1. Base image as an upgrade source

A new upgrade kind, `base`, sitting alongside the existing chart and image-tag sources.
For each image:

1. Read the image **config** — a few KB, not the layers — and look for the base
   reference. Key order, configurable, defaulting to
   `org.opencontainers.image.base.name` (the OCI standard) then
   `image.base.ref.name` (what BuildKit writes here today).
2. If absent, read the **SLSA provenance attestation** and take the final-stage
   dependency. Present on these images already.
3. If still absent, report the base as **unresolved** — not "no upgrade". The fix is
   then a build-system change: emit the base labels. That is a cheap, concrete ask,
   and the same shape as the registry-credential finding.
4. With a base reference in hand, run the **existing registry tag lister** against it.
   The base is a normal image in a registry; nothing new is needed.

Three refinements the survey forced, each of which would otherwise produce a wrong
answer:

**Compare within a track, not across the repository.** `dotnet/aspnet` holds both
`8.0.13` and `10.0.1`. Taking the newest semver would tell a .NET 8 application to
move to a .NET 10 base, which is a framework migration presented as a patch. The
comparison is restricted to the same major, and a newer major is reported separately
as "a newer track exists" rather than as the upgrade.

**Follow the chain while it stays first-party.** `dotnet/aspnet-ironpdf/10:2.0.0` is
built on `dotnet/aspnet/10:1.1.0`, so an application on the ironpdf base is two hops
from upstream. The walk continues while each base is first-party, capped at four hops,
and reports the first outdated link — which is the one whose owner can act.

**A floating tag has no newer version.** Nine images sit on `dotnet/aspnet:10`, where
tag comparison is meaningless. There, the base digest label is compared against the
digest the tag currently resolves to: equal means current, different means the base
moved and a rebuild would pick it up.

Layer-digest matching against a catalogue of known bases is the usual fallback when
no labels exist. It is deliberately **out of scope**: it is heuristic, needs a
maintained catalogue, and the labels are already there.

### 2. First-party images stop reporting tag upgrades

Configuration names the registries or repositories whose tags are release numbers
rather than remediation:

```yaml
remediation:
  firstParty:
    registries: [registry.example.com]
```

For those, a newer application tag is not a fix and is not reported as one. The
remediation path becomes the base image. Without this, the queue advertises
`1.0.79 → 1.0.80` as a fix, which is the misleading answer this document exists to
remove.

### 3. Attribution: would the base bump actually fix it?

Both vulnerability sources already say where a CVE lives — Trivy reports a target
class (`os-pkgs` vs `lang-pkgs`) and package type, and Rapid7's packages endpoint
reports `clazz` and `package_type`. Summing per finding gives:

```
34 of 40 criticals are in OS packages   → fixed by rebuilding on aspnet/10:1.1.1
 6 of 40 are in NuGet packages          → fixed in the application repository
```

That split is the report's most useful line for a first-party image, and it decides
whether a base bump closes the finding or only part of it.

### 4. Chain depth two

An application is behind its base; the base may be behind upstream. Both are worth
reporting, to different people:

- App image → base: reported on the finding, owned by the app team.
- Base → its own base: reported once per base image, owned by whoever builds it.

Depth is capped at two hops. Deeper chains are possible but the second hop already
reaches a public upstream, and an unbounded walk is a lot of registry calls for
diminishing returns.

### 5. One base bump fixes many images

Grouping already exists for this shape: findings that one change would fix share a
ticket. Keyed on the base image, "upgrade `dotnet/aspnet/10` to 1.1.1" becomes one
ticket naming every application affected, rather than one ticket per application
telling each team the same thing.

## Phasing

1. **Base detection and reporting.** Config labels, provenance fallback, tag lookup on
   the base, `UPGRADE`/`FIX` columns and JSON reporting the base path. Findings whose
   base cannot be determined report unresolved with the reason.
2. **First-party tag suppression.** Config, and the queue stops advertising release
   tags as fixes.
3. **Attribution.** Per-finding split of CVEs into base-fixable and
   application-fixable, in the report, the API and the ticket body.
4. **Base-of-base reporting**, and grouping tickets by base image.

## Open questions

- **Is the label always present?** Verified on one image. It needs checking across the
  estate before the queue depends on it; where it is missing, phase 1 reports that as
  a build-system gap rather than as "no fix".
- **Does the base tag ordering carry meaning?** `1.0.5 → 1.1.1` looks like semver, and
  the existing lister requires strict semver. Worth confirming that base rebuilds
  always bump the version rather than retagging.
- **Are base images ever pinned by digest?** A digest-pinned base has no "newer tag"
  in the usual sense; the comparison becomes digest inequality against a moving tag.
- **Credentials.** Reading a config blob needs registry pull. The same `AcrPull` grant
  that lets Trivy scan these images covers it, so this is one permission rather than
  two.
