# Plan: Jira ticket sink

Status: **plan only, not implemented.**

Turn actionable findings into Container Vulnerability tickets, from a
config-supplied template, without re-raising a ticket that already exists.

Derived by reading a real, already-working ticket of the shape we want to
generate, rather than designing against the Jira API in the abstract. Identifiers
below are placeholders; substitute your own.

| Element | Example value | Notes |
|---|---|---|
| Project | `PROJ` (id `10000`) | may be team-managed (`simplified: true`) |
| Issue type | `Container Vulnerability` (bespoke type id) | hierarchy level 0 |
| Parent epic | `PROJ-100` | set via the `parent` field |
| Image field | `customfield_XXXXX` = `["acme/wiremock"]` | array of strings |
| Board | `<board id>` | found on the sprint field of an existing ticket |
| Priority | `Highest` | |
| Summary | `Upgrade WireMock to the latest version` | |

Two details that shape the design:

1. **The image custom field holds a bare repository** (`acme/wiremock`) — no
   registry, no tag. It is an *array*, so one ticket can cover several images.
   That makes it the natural **idempotency key**: JQL can find existing tickets
   by image without any local state.
2. **The description is a fixed four-heading template** (Business
   objective/requirements, Technical Requirements & Actions, Test Strategies,
   Acceptance Criteria) with the service name substituted, plus standing
   instructions about validating Flux automation and `flux_automations_branch`.
   That is a template file, not string-building in Go.

## Config

```yaml
jira:
  # Required.
  board: 100                        # your board id
  project: PROJ
  template: jira/container-vuln.md.tmpl

  # Where the image goes. Exactly one of field/label is required.
  imageField: customfield_XXXXX     # array-of-strings custom field
  # imageLabel: true                # alternative: labels, when no field exists

  # Optional.
  epic: PROJ-100                    # parent; omitted = no parent
  issueType: Container Vulnerability  # default: Task
  priority: Highest
  labels: [container-vuln]

  # Only raise tickets for findings with somewhere to go (see below).
  requireUpgrade: true              # default true
```

Template is Go `text/template` over a view of the finding, so the wording stays
with whoever owns the process rather than in the binary:

```
Summary: Upgrade {{ .ServiceName }} to the latest version

**Business objective/requirements**

Upgrade {{ .ServiceName }} to {{ .Upgrade.Latest }}.
...
{{ range .FixableCriticals }}- {{ .ID }} (CVSS {{ .CVSS }}, EPSS {{ .EPSS }}) fixed in {{ .FixedVersion }}
{{ end }}
```

`Summary:` on the first line, blank line, then the description body — one file
per ticket shape, no separate summary config.

## requireUpgrade: don't raise what can't be fixed

Agreed: **no ticket when there is nothing to upgrade to.** An image already on its latest upstream
release is the case in point: many criticals, many workloads, and nothing to bump
to. A ticket saying "upgrade to the latest version" when it *is* the latest
version wastes the assignee's time, which is how vulnerability queues lose
credibility.

So `requireUpgrade: true` (the default) skips a finding unless
`upgrade.available` is true. Three consequences worth being explicit about:

- Findings with `upgrade.actionable == false` (Flux/operator-managed) **still get
  a ticket** — there is a real version to move to, just via the chart or
  operator. The template can say which, since `upgrade.managed` and
  `upgrade.source` (a GitOps repo URL) are already in the model.
- Findings with no upgrade are **not silently dropped**: the run logs them and
  reports a count, because "7 criticals and nowhere to go" is exactly what
  someone should look at by hand.
- Set `requireUpgrade: false` to raise them anyway.

## Idempotency

The hard part, and the reason this is a plan rather than a patch.

Before creating anything, search by the image field:

```
project = PROJ AND issuetype = "Container Vulnerability"
  AND cf[XXXXX] ~ "natsio/prometheus-nats-exporter"
  AND statusCategory != Done
```

- **Open ticket exists** → skip (optionally comment when the target version has
  moved on since the ticket was raised).
- **Only Done tickets exist** → create a new one. A recurrence after a completed
  upgrade is a genuinely new piece of work.
- **Nothing** → create.

Deliberately no local state file: Jira is the source of truth, and a state file
would drift the moment someone closes a ticket by hand.

Open question: for team-managed projects `cf[NNNNN]` JQL support varies. Verify
against your project before committing to it; fallback is a label
(`patchwright/<sanitised-image>`), which is always JQL-queryable.

## Grouping

N findings is not N tickets. The image field being an array is the hint that
grouping is expected:

- **A set of Flux controllers** → one ticket. One operator bump fixes all of them.
- **A family of Crossplane providers** → one ticket per family.
- Two sidecars from the same chart → one ticket.

Proposal: group by `upgrade.source` (the GitOps repo path) when present, since
findings sharing a deployment source are fixed by one change. Everything else is
its own ticket. Grouped tickets list every image in the image field, which
also keeps the idempotency search working per image.

## Shape in the codebase

`sink.Sink` already fits (`Emit(w io.Writer, findings []model.Finding) error`),
but a Jira sink needs a client, and writing to `w` is the wrong contract for
"create remote side effects". Two options:

- **A: a `jira` sink** behind the existing interface, `w` used for a written
  report of what it did. Fits `--output jira=-`, but overloads a rendering
  interface with a mutating one.
- **B: a separate `patchwright ticket` command** taking the same config, run
  after `assess`. Keeps `assess` read-only, which matters for a tool people run
  ad hoc against production, and makes `--dry-run` natural.

**Recommend B.** `assess` stays safe to run at any time; ticket creation is an
explicit, separately-invoked, dry-runnable action. It also composes with any
existing ticket-raising tooling rather than competing with it.

## Package names: NOT a prerequisite

Earlier drafts of this plan listed package names as a prerequisite. That was
wrong. When a ticket exists at all, `requireUpgrade` guarantees there is a
version to move to, and the action is "bump the image/chart" — the engineer does
not need to know which bundled Go module carried the CVE.

Package names only matter for the *no-upgrade* triage case (on the latest
version, criticals remain, decide whether to wait, rebuild, or accept), and by
design that case never becomes a ticket. So: a nice-to-have for the report and
JSON, worth a few lines in the Trivy adapter one day, and no blocker here.

## Sequence

1. Verify `cf[NNNNN]` JQL works on the target project; pick field-vs-label
   fallback. Cheapest to settle while implementing rather than up front.
2. `pkg/ticket` — config, template loading, grouping, idempotency search.
3. `patchwright ticket --dry-run` printing intended tickets. Review by hand.
4. Live creation behind an explicit `--confirm`.

`remediation_checked` and `upgrade.resolved` are now in the JSON, so
`requireUpgrade` can skip on "no newer version" while treating "we could not
find out" as a gap to report rather than a silent skip. That was the one real
prerequisite and it is done.
