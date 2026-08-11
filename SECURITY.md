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
| Your Jira instance | Search for existing tickets; create and comment | `jira:` config + credentials |

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

The only mutating integration. Ticket reconciliation and `--auto-ticket` are
described here as designed; if this document has landed ahead of them, treat this
section as the intended behaviour rather than the shipped behaviour. It can create issues, add images to an existing
issue's field, and comment. It **cannot** close, transition, assign, or delete
anything, by design: a finding leaving the queue is ambiguous between "fixed" and
"no longer scanned", so closing is always a human decision.

Automatic ticketing is off by default. Enabling it (`--auto-ticket`, or
`ticketing.autoTicket`) requires credentials, and the chart refuses to render
without them.

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
- release builds publish an SBOM alongside the image

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public issue.
