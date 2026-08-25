# Ticketing

`patchwright ticket` turns actionable findings into Jira tickets from your template,
and reconciles the ones that already exist. It reads the JSON an assess run
produced rather than re-running the assessment.

```sh
patchwright assess -i export.csv -c config/ --remediation \
  --output json:full=findings.json
patchwright ticket -i findings.json -c config/            # dry run
patchwright ticket -i findings.json -c config/ --confirm   # apply
```

**Dry run is the default.** It prints every ticket in full, the tracker each lands
on, and every skip with its reason.

Credentials come from the environment, never the config file:

```sh
export JIRA_BASE_URL=https://your-site.atlassian.net
export JIRA_EMAIL=you@example.com
export JIRA_API_TOKEN=...
```

## What one ticket covers

```yaml
jira:
  groupBy: service     # or campaign
  routes:
    - name: data-engineering
      groupBy: campaign
```

`service` (the default) raises one ticket per repository and upgrade target: one
rebuild, promoted through its environments. `campaign` raises one per owning team and
target, listing every service that needs it.

Which is better is the team's call, not this tool's, and the route is where that
preference lives. A platform team with a handful of repositories wants a ticket per
service. A team with thirty repositories on one shared base wants one ticket saying
"rebuild these six", because thirty tickets is how a queue gets ignored.

## Linking back to the evidence

`dashboard.url` is where the status page is reachable from outside the cluster:

```yaml
dashboard:
  url: https://patchwright.example.internal
```

Every ticket then carries a deep link to its own queue entry — the same work item, with
its CVEs, coverage, fix path and whatever is already in progress. The link names the
team and service rather than an image tag, because the tag will have moved on by the
time somebody clicks a ticket while the service and its owner have not.

Unset means no link is written. The server binds a port and cannot know what hostname
anybody reaches it through, and a ticket pointing at `localhost:8080` is worse than a
ticket with no link.

A link naming something no longer in the queue opens nothing and says why. Showing
somebody the nearest match instead would mean quietly presenting a different service
than the one they clicked through for.

## Configuration

`board`, `project`, `template` and one of `imageField` / `imageLabel` are required.

```yaml
jira:
  board: 100
  project: PROJ
  template: config/templates/container-vuln.md.tmpl
  imageField: customfield_XXXXX   # array-of-strings field holding the images
  # imageLabel: true              # or labels, where no such field exists
  epic: PROJ-100
  issueType: Container Vulnerability
  priorityMap:                    # carries the assessment's ordering into Jira
    urgent: Highest
    high: High
    medium: Medium
    low: Low
  priority: Medium                # fallback for anything unmapped
  requireUpgrade: true            # default
  autoClose: false                # default
  requireRoute: false             # default
```

`imageField` (or the label) is the idempotency key: it is how an existing ticket for
an image is found. `priorityMap` is not defaulted — priority schemes are
per-instance and a name that does not exist fails ticket creation.

## What a run does

| Action | When |
|---|---|
| `create` | no open ticket covers any of the change's images |
| `extend` | a ticket covers part of the change; the rest are added, with a comment |
| `update` | the target moved on and nobody has picked the ticket up |
| `close` | the work is provably finished (needs `autoClose`) |
| `note-stale` | the target moved on, but someone has picked the ticket up |
| `note-done` | the finding no longer asks for anything, so the work appears done |
| `hold` | nothing can be judged yet, because the data needed is missing. **Writes nothing** |
| `skip` | already covers the change correctly |

**A policy decision is not the work being done.** A finding that leaves the queue because
it was fixed and one that leaves because configuration declined to ticket it — an
exclusion, a priority threshold, no matching route — are indistinguishable from the
drafts. Reporting the second as done means raising `minPriority` marks every ticket it
newly excludes as finished, while the upgrade it asks for is still available. Those
tickets are held instead, naming the setting that dropped them.

**A ticket nobody can judge is held, not commented on.** A finding leaves the queue
either because the work is done or because we could not establish whether it is — an
unreadable registry, or upgrade detection not having run. Those look identical from the
queue, and only the first means anything is finished.

So `note-done` now requires the finding to have stopped asking for anything. A finding
that is still actionable but whose upgrade could not be resolved produces a `hold`,
which **writes nothing at all**: our own blind spot is not news for somebody else's
tracker, and a comment saying "this looks done" on work that is merely unmeasurable is
worse than silence. Holds appear in the plan and the logs, with the blocker named.

Before this, an expired registry credential turned every ticket it touched into a
comment claiming the work looked finished.

Duplicates are prevented by asking Jira, not by local state: a state file drifts the
moment someone closes a ticket by hand. Tickets in a Done status do not suppress a
new one — a recurrence after a completed upgrade is new work.

Findings that one change would fix share a ticket, grouped by deployment source, so
a set of controllers owned by one operator becomes one ticket. Where a controller
gives each package its own object (a Crossplane `ProviderRevision` per provider),
the object name is collapsed so a family groups. A grouped ticket never claims a
single target version unless every image shares one.

## Work already in flight

A dependency bot raising pull requests for the same upgrades makes patchwright's tickets
duplicates: the fix is in a review queue, not waiting on a decision. Reconciling against
that so the queue shows "PR open" instead of raising a ticket, and so a *stale* PR becomes
the finding, is designed in
[design/remediation-in-flight.md](design/remediation-in-flight.md) and not built yet.

## Only ticket what is worth ticketing

`minPriority` sets the lowest assessment priority that gets a ticket:

```yaml
jira:
  minPriority: high        # urgent and high are ticketed; medium and low are not
```

The queue and the tracker answer different questions. A queue holds a hundred
low-priority findings usefully; a tracker holding a hundred tickets nobody will action
this quarter is one people stop reading, and it takes the urgent ones down with it.

Judged on the **ticket**, not each finding: a low-priority image that shares an upgrade
with an urgent one still rides along, because it is one change. Filtering findings
before grouping would split that change and send half of it nowhere.

Below-threshold findings are reported as skipped with the reason, so this decides what
gets a ticket and never what is visible. It is per route as well as global, so one team
can take only urgent work while another takes everything. A value that is not on the
ranked ladder (`urgent` > `high` > `medium` > `low`) fails at load: a typo would rank
below everything and silently ticket the lot.

## Skips

No ticket is raised for a finding with nothing to upgrade to; `requireUpgrade: false`
raises them anyway. Skips are printed with the reason, and the reasons are distinct:
"already on the latest version" is resolved, "versions could not be resolved" is one
to chase.

`exclude` keeps work out of ticket creation without hiding it — CEL over the same
variables as policy rules:

```yaml
jira:
  exclude:
    - name: crossplane
      when: "dimensions['namespace'].exists(n, n == 'crossplane-system')"
      reason: upgraded together on their own cadence
```

Unlike `suppress`, an excluded finding stays in the report and the queue and is
listed as skipped with the rule name.

## Routing

`routes` sends each owner's tickets to its own tracker. First match wins; anything
unmatched uses the top-level settings. A route states only what differs — template,
image field, priority map and labels are inherited.

```yaml
jira:
  project: PROJ
  autoClose: false
  routes:
    - name: sre
      when: "owner['team'] == 'sre'"
      project: SRE
      issueType: Bug
      imageLabel: true            # this project has no shared custom field
      autoClose: true
      closeTransition: Ship It    # SRE's workflow, not PROJ's
    - name: platform
      when: "owner['class'] == 'platform'"
      project: PROJ
```

- A group is never split across routes: two findings sharing one upgrade but owned
  by different teams become two tickets.
- Reconciliation searches **every** configured project. A ticket on another board
  still means the work is in flight.
- For tickets that already exist, settings resolve by the issue key's project, not
  by the route that created it.
- Each route is validated as the configuration it resolves to, at load.

`requireRoute: true` means no match, no ticket: an unmatched finding is reported as
skipped rather than falling through to the default project.

```
no ticket route matches its owner (engineering/orders) and requireRoute is set,
so no tracker is configured for this work
```

## Updating and closing

**A stale ticket nobody has picked up is rewritten, not commented on.** If it is
unassigned *and* still in a "new" status category, the summary and description are
replaced with the current target. If it is assigned, or in progress, it gets a
comment instead — both halves of that test matter, since an unassigned ticket in
progress is being worked by someone who never claimed it.

Only the wording changes. Priority is left alone, in case a human re-triaged it.

**`autoClose: true` closes tickets whose work is provably finished** — the Renovate
PR that landed while nobody looked at the ticket. A finding *disappearing* is never
treated as done, because a provider that stopped assessing an image looks identical;
that path only comments. Closing requires every image on the ticket to be:

- still reported in the assessment;
- `remediation_checked`, or "no upgrade available" only means nobody looked;
- `upgrade.resolved`, or "on the latest" is unproven;
- free of any finding for that repository with an upgrade still available, which
  catches an old tag still running somewhere;
- liveness reconciled, so "everywhere" is checked rather than assumed.

Set `closeTransition` where the workflow offers more than one way to finish:
"Done" and "Won't Do" are not interchangeable, so patchwright refuses to choose and
names the alternatives.

**`closeTransitionUnworked` covers boards with no reachable Done.** Some workflows
only allow Done once a ticket has been refined and started, so a ticket nobody touched
cannot be completed — only abandoned:

```yaml
jira:
  closeTransition: Done
  closeTransitionUnworked: WON'T BE DONE
```

It applies **only to tickets nobody picked up** — unassigned and never started. For
those, "not done" is the accurate record: the upgrade landed by another route, so the
ticket was never actioned. A ticket somebody worked still refuses to close this way
and fails loudly, because recording their work as not-done would misrepresent it.
`closeTransition` wins wherever it is available, since "done" is the truer statement
about finished work. The comment says which case it is, so a closed-as-not-done ticket
does not read as a decision to skip the work.

`closePriorityUnworked` clears the priority on that path:

```yaml
jira:
  closeTransitionUnworked: WON'T BE DONE
  closePriorityUnworked: Unprioritised
```

A ticket closed as not-worked that keeps its original priority still appears in every
"highest priority open work" filter until someone notices it is closed. Applied only
on the unworked path — work somebody completed keeps the priority it was triaged at,
which is a record of how urgent it was. Where a transition screen refuses the field,
the priority is set in a follow-up edit rather than lost.

## Comments

Each note carries a reference (`` `patchwright-ref: note-done` ``) and existing
comments are read before posting, so a long-lived ticket does not collect an
identical note every run. The reference encodes what would make a fresh comment
worth reading — a staleness note is keyed on the version now available, so a target
that moves again is said again. A comment already present is reported as
`already_present`, never counted as posted.

## Template

Go `text/template`: first line `Summary: ...`, then a blank line, then the
description. See
[`config/templates/container-vuln.md.tmpl`](../config/templates/container-vuln.md.tmpl)
for the available fields.

`**bold**`, `` `code` ``, bullet lists, headings and bare URLs are translated to
Atlassian Document Format. Code spans are left untouched inside. Anything
unrecognised, including an unmatched `` ` ``, is passed through as written.
