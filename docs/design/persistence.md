# Design: remembering what changed

Status: **proposed, not built.**

## The problem

Every assessment is a snapshot. The service holds one in memory and rebuilds it on
refresh, which was a deliberate simplification and has held up well: no schema, no
migrations, no stale rows, and a security posture with nothing at rest.

The cost is that nothing the tool says is about MOVEMENT.

- **Time to remediate** cannot be reported. It was asked for directly in a security
  review, with the strongest argument anyone made there: an engineering manager who
  says a fix will take time can be answered with how long it is already taking.
- **A pilot can be reported as adopted but not as faster**, and faster is the number
  that wins the next team.
- **"Is this getting better?"** has no answer. Four hundred and eighty-seven
  untouched fixes might be three hundred last month or six hundred; nothing knows.
- The base differential can say a rebuild would clear 3,664 CVEs. It cannot say
  whether the rebuild happened, or what it actually cleared.

That last one matters most. The tool now spends real effort telling people what to
do, and cannot tell them whether doing it worked.

## What NOT to build

**Not a time-series database.** The aggregates are already in Prometheus - findings
by state, per owner, and now per-owner responsiveness - and it stores them properly,
with retention and downsampling and a query language. "Is the queue shrinking" is a
Prometheus question and should stay one. Reimplementing that inside this service
would be a worse TSDB alongside a good one.

What Prometheus deliberately cannot answer is anything about a specific thing.
Labels carry no image, CVE or ticket identifier, on purpose: metrics are readable by
anything that reaches the port, and an estate's unpatched criticals should not be in
a scrape. So per-ENTITY history has nowhere to live, and that is the gap - not
aggregates.

## Phase 1: what changed since the last run

**No storage at all.** Keep the previous assessment in memory beside the current one
and diff them.

That alone answers the question people ask most often, which is not "how are we
doing this quarter" but "what changed today":

- findings that appeared, and whether they are new CVEs or a newly-deployed image
- findings that disappeared, and the honest caveat below about why
- findings that got worse - a new KEV, an upgrade that stopped being available
- an image that was rebuilt, visible now that build dates are read

It survives nothing. A restart loses the comparison, and the first run after one has
nothing to compare against and must say so rather than reporting everything as new.
That is a real limitation and still worth having: it is an afternoon, it needs no
deployment change, and it will show whether anybody actually uses this before a
schema exists.

## Phase 2: a small event log

The smallest thing that answers the lifecycle questions. Not a copy of the
assessment - an append-only record of transitions:

| Event | When |
|---|---|
| `finding_opened` | An image and its owner first carried an actionable finding |
| `finding_resolved` | It stopped, WITH evidence - see below |
| `finding_lapsed` | It stopped without evidence: no longer scanned, or the workload went away |
| `ticket_raised` | Reconciliation created one |
| `image_rebuilt` | The image's build date moved |

Keyed by the work item - team, service, upgrade target - which is the same key
tickets already group by, so a queue row, a ticket and a history entry are the same
unit. Rows are small and bounded by the estate rather than by time: a few thousand a
month.

### Resolution needs evidence, not absence

This is the part that decides whether the numbers are worth anything.

A finding leaving the queue is ambiguous between "fixed", "no longer scanned" and
"the workload was deleted". Ticket auto-closing already refuses to treat
disappearance as success, and requires positive evidence that every image is still
reported, was checked for a newer version, resolved its versions, has no upgrade
available, and had liveness reconciled. The same rule has to govern this, for a
sharper reason: a "time to remediate" that counts coverage loss as remediation
produces a flattering number that improves fastest when the scanner breaks.

So `finding_resolved` and `finding_lapsed` are different events, both recorded, and
any duration reported is over the first. A dashboard that shows only the good one is
the failure mode to design against.

### Where it lives

SQLite on a PersistentVolumeClaim, following the pattern the chart already has for
the Trivy cache - including its reasoning, which applies unchanged: there is only
ever one writer, because the Deployment runs one replica and the CronJob sets
`concurrencyPolicy: Forbid`.

Off by default, like the cache. Without it the tool behaves exactly as it does now.

Alternatives considered:

- **Object storage.** Survives rescheduling with no volume and would tolerate more
  than one replica. Costs a credential, a client, and a consistency story for
  concurrent writers that does not exist today. Worth revisiting only if replicas
  ever exceed one.
- **A real database.** Correct at a scale this is not at, and it makes the tool
  something you operate rather than something you run.
- **Writing history into Jira.** Tempting because tickets are already there, and
  wrong: it only covers work somebody ticketed, and this needs to measure the work
  nobody did.

## Phase 3: tracker dates

The event log knows when patchwright first saw something and when it stopped. It
does not know when a human picked it up, and that is most of the remediation time.

Two changes, both in the tracker client: fetch `created` and `resolutiondate`, and
index closed tickets rather than only open ones. The index exists today to avoid
raising duplicates, so it reasonably ignores anything done; measuring cycle time
needs the opposite.

That yields the three intervals worth separating, because each one blames something
different:

| Interval | What a long one means |
|---|---|
| finding opened → ticket raised | Nobody was told |
| ticket raised → in progress | Told, not prioritised |
| in progress → resolved | Being worked, slowly |

Reporting one number for all three would hand a team an average that flatters
whichever part they are good at.

## What this changes about the tool

Worth stating plainly, because it is the reason this is a design note rather than a
ticket.

**Data at rest.** SECURITY.md currently says nothing is written to disk but the
scanner cache and a short-lived credential, and that no database is used. That stops
being true. The event log is a history of which services carried exploitable
vulnerabilities and for how long - useful to an attacker, and subject to whatever
retention policy the organisation applies to security records. It needs a retention
setting and a line in SECURITY.md before it is switched on anywhere.

**Backup becomes a question.** Today losing the pod loses nothing. After this it
loses history that cannot be reconstructed, because the estate no longer looks the
way it did. That is an argument for keeping the schema small enough to be cheap to
back up, and for the tool to degrade to today's behaviour when the volume is absent
rather than refusing to start.

## Open questions

1. **Is Phase 1 enough?** "What changed today" may be most of the value, and it
   needs no storage, no retention policy and no security review. Worth building
   first and seeing what people ask for next, rather than assuming the lifecycle
   questions are the ones being asked.
2. **What identifies a finding across runs?** The work-item key is stable across tag
   changes, which is what makes "this took 40 days" meaningful. But it changes when
   ownership changes or an upgrade target moves, and a team reorganisation would
   close every finding and open an identical one. Needs deciding before any duration
   is reported.
3. **Retention.** A year is the obvious answer for trends and probably wrong for a
   record of exploitable weaknesses. Whoever owns the security-records policy should
   set it, not this document.
4. **Does the API expose history, or only the page?** An endpoint invites somebody to
   build a dashboard on a schema that will move. Possibly worth keeping internal
   until the shape settles.
