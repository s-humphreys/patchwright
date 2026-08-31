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
| Registry credentials for base-image scanning | **Secret** | Minted per scan, written to a private file under `/tmp` for the length of one scan, then deleted |

No personal data is processed. Nothing is written to disk except Trivy's cache and
that credential file (`/tmp`, an `emptyDir`, mode 0600 and removed when the scan
returns), and no database is used: the service holds one assessment in memory and
rebuilds it on refresh.

The credential file deserves a note, because handing a subprocess a secret is
exactly the kind of thing a review should ask about. Base-image scanning shells out
to Trivy, which would otherwise find its own credentials through the docker
credential helper chain - and that chain carries GO-2026-6225, credential leakage
to untrusted hosts, with no fixed version. Rather than let it, patchwright resolves
the credential itself through its own registry keychains and writes an isolated
docker config holding exactly one registry, with no `credsStore` and no
`credHelpers`. That both keeps the vulnerable path out of the process and stops
Trivy inheriting an ambient config it was never meant to read.

The assessment itself is sensitive output. Anyone who can read the API or the status
page can see which production images have unpatched criticals and no fix applied,
which is a useful shopping list to an attacker. Treat access accordingly.

## Cluster access

Read-only, and narrow. The chart's ClusterRole grants `get` and `list` only, on:

- `pods`, `namespaces`
- `services` and Gateway API `httproutes`, to measure whether a workload is
  reachable from the internet (only when exposure is enabled)
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
| Image registries (`ghcr.io`, `quay.io`, `docker.io`, your own) | Read tags to detect newer versions; read image labels to find a base image; pull images to scan | `--remediation`, `--vuln-source`, `remediation.baseDiff` |
| Helm chart repositories (from your own HelmReleases) | Read chart versions | `--remediation` |
| `api.first.org` | EPSS exploitation-probability scores | `--exploit-source=public` |
| `www.cisa.gov` | CISA Known Exploited Vulnerabilities catalogue | `--exploit-source=public` |
| `endoflife.date` | Whether a base image's line is still maintained | `--support-source=endoflife` |
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

### Sign-in (OIDC)

For anything reachable beyond a trusted network, use the built-in OIDC sign-in
rather than the shared token. Authorization code flow with PKCE, state and nonce,
JWKS fetched from the provider, and an HMAC-signed session cookie; see
[docs/authentication.md](docs/authentication.md).

It answers the limitations above: sign-ins carry an identity, and access is decided
by the provider rather than by possession of a string. Two things still worth
stating:

- **It fails closed on a missing groups claim.** A provider that stops sending
  groups, or that truncates the claim because the user is in too many, denies
  access rather than granting it. That is the correct direction and it will look
  like an outage.
- **Authorisation is still all-or-nothing.** Signing in gets the whole estate;
  there is no per-team scoping.

The shared token remains for machine callers and for environments with no provider.
It is a floor, not a substitute.

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

## MCP

`/mcp` serves read-only Model Context Protocol tools over the same cached assessment
the API serves, in the same process.

It is registered as a normal route, so it is authenticated exactly like every other
one: the shared token where a token is configured, open where nothing is. This is the
deliberate part - an exempt path would have been an unauthenticated read of the whole
estate on the same port and hostname as a page that is behind sign-in, and network
policy selects on port rather than path, so nothing downstream could have separated
them.

Authorisation is unchanged and all-or-nothing: whatever reaches the endpoint sees the
whole estate. The underlying views have no per-team scoping to offer, so a narrowing
enforced by something in front cannot be enforced here.

Every tool is read-only, and there is no `refresh`: an MCP client can read the
assessment and can neither trigger one nor write a ticket. What it reads is the same
data `/api/v1/findings` returns to the same caller, so the endpoint widens the
transport rather than the exposure.

## Metrics

`GET /metrics` serves Prometheus metrics in server mode, **unauthenticated by
default**, alongside the health probes.

Stated plainly because it is a deliberate trade and a reviewer should weigh it: the
counts describe the estate's security posture — how many unpatched criticals, which
teams have no coverage, how stale the scan data is — so anything that can reach the
port can read that shape without a credential. It cannot read the findings
themselves: no image, CVE, ticket or namespace appears in any metric.

The reasoning is that scrape configs needing bearer tokens are the friction that
stops monitoring being set up at all, and unmonitored coverage decay is the larger
risk. Network policy is the intended control, and `metrics.requireAuth` brings the
endpoint under the API token for environments that judge otherwise; the chart's
monitors then present that token from the same Secret.

No finding, image, CVE or ticket identifier appears in a label. Labels are owner
class, team, and small closed sets such as an action kind or an HTTP outcome class.
Provider-supplied reason strings are the one free-text source, and they are trimmed
to their first clause and capped in number.

## Container

- `gcr.io/distroless/static:nonroot` — no shell, no package manager, no libc
- static binary, `CGO_ENABLED=0`, `-trimpath`
- `runAsNonRoot`, `allowPrivilegeEscalation: false`, all capabilities dropped,
  `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`
- writable paths limited to an `emptyDir` at `/tmp`, for the scanner cache and the
  short-lived per-scan registry credential described above

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
- release builds publish an SBOM and build provenance alongside the image
- the Helm charts ship as OCI artefacts beside it, versioned with it, and are **signed
  with cosign keylessly** - the signature is bound to the release workflow's identity,
  so there is no signing key to hold, rotate or lose. A cluster can require it:
  `OCIRepository.spec.verify` with `matchOIDCIdentity` refuses a chart this repository's
  workflow did not produce.

  This is stricter than what it replaces. The charts were consumed from a git tag, and
  a tag can be moved by anyone with write access to the repository; a digest cannot, and
  a signature cannot be forged by them.

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public issue.
