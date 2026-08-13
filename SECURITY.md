# Security

What patchwright touches, what it needs, and what it deliberately cannot do. Written
for a security review as much as for operators: if something here is wrong or
missing, that is a bug worth raising.

## What it is

A read-mostly analysis tool. It ingests a vulnerability scanner's output,
reconciles it against live clusters, decides what is worth acting on, and
optionally raises Jira tickets. It does not patch anything, does not open pull
requests, and does not change cluster state.

## Data it handles

| Data | Sensitivity | Where it lives |
|---|---|---|
| Scanner export (CSV) | **Sensitive.** An estate-wide list of unpatched vulnerabilities, by image and environment | Mounted read-only from a Secret; held in memory during a run |
| Cluster inventory (images, namespaces, labels) | Internal | In memory only |
| CVE metadata, EPSS scores, KEV membership | Public | In memory only |
| Jira credentials, API token | **Secret** | Environment variables from Secrets |

No personal data is processed. Nothing is written to disk except Trivy's cache
(`/tmp`, an `emptyDir`), and no database is used: the service holds one assessment
in memory and rebuilds it on refresh.

The assessment itself is sensitive output. Anyone who can read the API or the status
page can see which production images have unpatched criticals and no fix applied,
which is a useful shopping list to an attacker. Treat access accordingly.

## Cluster access

Read-only, and narrow. The chart's ClusterRole grants `get` and `list` only, on:

- `pods`, `namespaces`
- `deployments`, `statefulsets`, `daemonsets`
- Flux resources: `helmreleases`, `kustomizations`, `helmrepositories`,
  `gitrepositories`, `ocirepositories`
- custom resources named by an ownerReference, to determine whether an image's tag
  is set in a CR spec

It has **no access to Secrets**, no write verbs anywhere, and no ability to exec
into or delete anything. Multi-cluster access uses a kubeconfig mounted from a
Secret; nothing is stored.

## Outbound connections

Everything is opt-in via flags: with none of them, patchwright makes no outbound
connections beyond the Kubernetes API.

| Destination | Why | Enabled by |
|---|---|---|
| Kubernetes API servers | Reconcile against live clusters | `--live-source=kube` |
| Image registries (`ghcr.io`, `quay.io`, `docker.io`, your own) | Read tags to detect newer versions; pull images to scan | `--remediation`, `--vuln-source` |
| Helm chart repositories (from your own HelmReleases) | Read chart versions | `--remediation` |
| `api.first.org` | EPSS exploitation-probability scores | `--exploit-source=public` |
| `www.cisa.gov` | CISA Known Exploited Vulnerabilities catalogue | `--exploit-source=public` |
| Trivy's vulnerability database (an OCI registry) | Scanner database updates | `--vuln-source=trivy` |
| Your Jira instance | Search for existing tickets; create, edit, comment, and (opt-in) transition to done | `jira:` config + credentials |

The chart can render a NetworkPolicy restricting this (`networkPolicy.enabled`).
Registry and Helm-repository destinations depend on what you run, so the egress
allowlist is yours to set.

## Authentication and authorisation

`PATCHWRIGHT_API_TOKEN` requires a shared bearer token on the API and the status
page; health probes stay open. Comparison is constant-time over SHA-256 digests.

**Known limitations, stated plainly:**

- **One shared token, no identity.** Everyone who has it is the same principal, so
  writes cannot be attributed to a person. Audit entries record that a write came
  via the API rather than the schedule, but not who made it.
- **No per-team scoping.** Any valid token sees the whole estate, including other
  teams' findings.
- **No TLS in-process.** Serve behind an ingress or mesh that terminates TLS; the
  token would otherwise cross the network in plaintext.
- **No rate limiting.** `POST /api/v1/assessments` triggers a full assessment;
  concurrent refreshes collapse into one, so the cost is bounded, but it is
  authenticated for a reason.

For anything reachable beyond a trusted network, put OIDC in front (an ingress
authenticator or oauth2-proxy). The built-in token is a floor, not a substitute.

## Writes to Jira

The only mutating integration. What it can do:

| Write | When | Gated by |
|---|---|---|
| Create an issue | Actionable work with no open ticket covering it | credentials |
| Add images to an issue's field or labels | An open ticket covers part of a change | credentials |
| Comment | A ticket's target moved on, or its work looks finished | credentials |
| Edit an issue's summary and description | The target moved on **and** nobody has picked the ticket up (unassigned, still in a "new" status category) | credentials |
| Transition an issue to a done status | Every image it covers is provably already on its latest version | `autoClose`, off by default |

It **cannot** assign, delete, change priority, or transition anywhere other than a
done status reached by a named or unambiguous transition. Priority is deliberately
left alone on an edit: a human may have re-triaged it, and silently reverting that
would be worse than a stale summary.

Closing deserves explanation, because an earlier version of this document said it
would never happen. The reasoning behind that has not changed: a finding *leaving*
the queue is ambiguous between "fixed" and "no longer scanned", so disappearance
never closes anything — that case still only comments. Closing requires positive
evidence that every image on the ticket is still reported, was checked for a newer
version, resolved its versions, has no upgrade available, and had liveness
reconciled. Any one of those missing produces a comment instead.

Comments are deduplicated by a reference in the comment body, read before each
write, so a long-lived ticket does not accumulate an identical note per run.

Every write is logged with what triggered it — a scheduled refresh or an API call —
which ticket, which action, which tracker, and why. The shared API token carries no
identity, so a write cannot be attributed to a person; recording that it came from
the schedule rather than a caller is the most that can honestly be said.

Automatic ticketing is off by default. Enabling it (`--auto-ticket`, or
`ticketing.autoTicket`) requires credentials, and the chart refuses to render
without them. `autoClose` is separately off by default, and both it and the
transition used are per-tracker, so enabling closing for one team's board does not
enable it anywhere else.

## Metrics

`GET /metrics` serves Prometheus metrics in server mode. It sits behind the same
token as the API rather than alongside the health probes, because the counts it
exposes — unpatched criticals, coverage gaps per team, the age of the scan
provider's data — describe the estate's security posture. A reader who cannot see a
finding should not be able to count them either.

No finding, image, CVE or ticket identifier appears in a label. Labels are owner
class, team, and small closed sets such as an action kind or an HTTP outcome class.
Provider-supplied reason strings are the one free-text source, and they are trimmed
to their first clause and capped in number.

## Container

- `gcr.io/distroless/static:nonroot` — no shell, no package manager, no libc
- static binary, `CGO_ENABLED=0`, `-trimpath`
- `runAsNonRoot`, `allowPrivilegeEscalation: false`, all capabilities dropped,
  `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`
- writable paths limited to an `emptyDir` at `/tmp` for the scanner cache

## Supply chain

- dependencies updated by Renovate; `go.sum` pins every module
- CI runs `gofmt`, `go vet` (including the e2e build tag), unit and golden tests, a
  kind-based integration suite, `helm lint`, `govulncheck` over our own modules, and
  a Trivy scan of our own image. A tool that reports other people's vulnerabilities
  should be scanned on the same terms.
- The image scan gates on the base image and our own binary, and **reports without
  gating** on the bundled Trivy binary. Trivy's own dependencies are not ours to
  patch: at the time of writing its latest release carries two fixable HIGHs
  (go-git CVE-2026-71556, oras-go CVE-2026-50163), so gating on them would block
  every change until upstream ships a fix, and relaxing the gate for everything to
  get a green build would hide our own problems too. They remain visible in CI output
  and Renovate bumps the bundled version. If you would rather not ship a scanner at
  all, run with `--vuln-source` unset, or point it at a Trivy you provide.
- release builds publish an SBOM alongside the image

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public issue.
