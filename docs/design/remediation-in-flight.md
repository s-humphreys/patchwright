# Remediation already in flight

## The problem

patchwright raises tickets for work a dependency bot has already started. On a real
estate, five of the changes it wanted tickets for had open Renovate pull requests when
it asked:

| Open Renovate PR | patchwright was ticketing |
|---|---|
| `Update capitalontap.azurecr.io/dotnet/aspnet/10 Docker tag to v1.1.1` (3 days old) | the same base bump |
| `Update docker.io/octopusdeploy/kubernetes-agent Docker tag to v3.13.0` (7 days) | the agent upgrade |
| `Update tryretool/backend Docker tag to v3.334.28` (3 days) | the retool base bump |
| `Update busybox Docker tag to v1.38` (3 days) | the datadog init image |
| `Update Helm release k8s-guardrails to v5.3.0` (4 days) | the chart upgrade |

A ticket asking somebody to do work that is sitting in a review queue is worse than no
ticket: it costs triage time and teaches people that the queue is noise.

## The reframing

"A fix exists" is not a finding. **"A fix exists and nobody has landed it"** is.

| State | What patchwright should do |
|---|---|
| Fix available, PR open | Nothing. Show it on the queue as in flight |
| Fix available, PR open and stale | This is the finding: one item, "waiting N days on review" |
| Fix available, no PR | A ticket earns its place — nothing is happening |
| No fix, or unresolvable | Coverage problem, as today |

That makes patchwright an auditor of the automation you already run, rather than a second
backlog competing with it.

## What the data says

Two facts that shape the scope, from the same estate:

**Renovate covers part of it.** Of 57 distinct changes patchwright found, 8 container
related Renovate PRs existed, and 39 changes had no PR by any matching. Renovate is
deployed on the platform repositories and being rolled out to application repositories —
one PR in the survey was a repo opting in. So this de-duplicates the platform's work and
leaves the application estate untouched, which means it **complements** grouping tickets
by base image rather than replacing it.

**Matching naively is dangerous.** A prototype matcher on "image name appears in the PR
title" produced 14 matches, and the ones it found were mostly wrong:

```
capitalontap.azurecr.io/dotnet/aspnet 8.0.13→8.0.22
  matched  chore(aspnet-ironpdf10): Update capitalontap.azurecr.io/dotnet/aspnet/10 …
```

`dotnet/aspnet` is a prefix of `dotnet/aspnet/10`, so substring matching conflated two
different base images. Suppressing a ticket on that basis hides real work — the one
direction this must never fail in.

## Matching

Three constraints, all required:

1. **The PR must be in the repository that builds this image.** This is the constraint
   the prototype was missing, and the one that matters most. The
   `aspnet/10 → 1.1.1` PR lives in the repository that builds the *base images*; it does
   not remediate the 58 applications consuming that base. Matching them to it would have
   silenced 58 findings on the strength of a PR that cannot fix them.

   Images record their build repository — 700 of 707 on the estate surveyed — in the same
   config labels the base reference comes from, so this is a lookup rather than a guess.

2. **The dependency must match exactly**, comparing full registry-qualified references
   with boundaries, not substrings.

3. **The target version must match.** Renovate puts it in both the title and the branch:

   ```
   title:  chore(retool): Update tryretool/backend Docker tag to v3.334.28
   branch: renovate/retool-tryretool-backend-3.x
   ```

Anything meeting 1 and 2 but not 3 is a **weaker signal**: the dependency is being worked
on, but not necessarily to the version we want. Those are reported as "possible" and do
**not** suppress a ticket. Failing safe means erring towards a ticket, never towards
silence.

## A base PR is not an application fix

Worth stating separately because it is the subtlest part. A PR that moves the base
image's own base — in the repository that builds the base — makes the *next* build of
that base carry the fix. Every application on it still needs to rebuild afterwards.

So an in-flight PR remediates the image whose repository it is in, and nothing else. For
consumers, the finding stays open; what changes is that its base bump will shortly have a
newer target. Reporting otherwise would mark hundreds of applications as handled by one
PR.

## Design

A new optional source, configured like every other integration and with nothing
company-specific in the code:

```yaml
remediation:
  inFlight:
    provider: azuredevops        # github to follow
    organisation: example
    projects: [DevOps, Apps]
    # Which pull requests count as automated remediation. Defaults cover Renovate's
    # conventions; Dependabot and others are named the same way.
    authors: [renovate.automations]
    branchPrefixes: [renovate/]
    # A fix sitting in review this long is itself the finding.
    staleAfter: 14d
  base:
    # The build repository comes from the same labels as the base reference.
    repoLabels:
      - com.azure.dev.image.build.repository.name
      - org.opencontainers.image.source
```

Credentials from the environment, never config, as with every other integration.

One project-scoped API call returns the active pull requests — around 40 on this estate —
so this is one request per project per run, not one per image.

Findings gain an `in_flight` object: the PR URL, title, age, and whether the match was
exact or possible. Then:

- **Ticketing** treats an exact in-flight match as a policy skip, using the existing
  distinction between "configuration declined to ticket this" and "the work is done", so a
  PR appearing never marks tickets as finished.
- **The queue** shows `PR open 3d` rather than an upgrade target, because the action is
  review, not a version bump.
- **Stale PRs** get their own section, oldest first, and are the only in-flight state that
  earns a ticket.
- **Metrics**: `patchwright_remediation_in_flight`, and the age of the oldest unmerged
  fix — "fixes rotting in review" becomes alertable, which nothing currently measures.

## Phasing

1. Read pull requests, match exactly, expose `in_flight` in the JSON and on the queue.
   No behaviour change to ticketing yet, so the match rate can be judged against reality
   before anything is suppressed.
2. Suppress ticketing on exact matches; surface possible matches without suppressing.
3. Stale-PR reporting, section and metric, and a ticket for the stale ones.
4. GitHub as a second provider.

Phase 1 deliberately changes nothing about ticketing. The whole design rests on match
quality, and the prototype already showed how confidently a bad matcher can be wrong.

## Open questions

- **Merged-but-not-deployed.** A merged PR fixes the repository, not the cluster. The
  finding stays until the rebuild is deployed, so a recently merged PR is a third state
  worth showing rather than a resolved one.
- **Renovate's own dashboard.** Renovate maintains a dependency dashboard listing what it
  is holding back and why (rate limits, config). That is a richer signal than open PRs
  and might replace this matching entirely where it exists; worth checking what it looks
  like on a provider without issues.
- **Application-repo coverage.** This is worth much less until Renovate reaches the
  application repositories. Measuring how much of the estate its PRs could ever cover is
  a prerequisite for phase 2.
- **Multiple projects.** Repositories are spread across projects, and a build repository
  label names a repository but not necessarily its project. Either scan all configured
  projects, or resolve the project once per repository and cache it.
