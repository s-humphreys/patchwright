<p align="center">
  <img src="./docs/images/patchwright.png" alt="Logo" width="200" height="auto" />
</p>
<h1 align="center">patchwright</h1>

Turn noisy container-vulnerability scanner output into a **deduplicated,
owner-attributed, actionable** list.

Security scanners tell you *"this is a problem"* — thousands of rows of it.
patchwright answers the harder questions: *which* problems, *who* can fix them,
and *what is worth acting on now*. It reasons over vendor-neutral primitives
(images, CVEs, vulnerability counts) and pushes all organization-specific
judgement into declarative CEL rules you own.

In practice this collapses **thousands of scanner rows into a few dozen
actionable, owner-attributed findings** — deduplicating by image, splitting work
between platform and engineering teams, routing cloud-provider-managed images
out of the queue, and dropping workloads that aren't actually running.

---

## Concepts

The design keeps a **generic core** and pushes everything specific to the edges:

| Layer | Responsibility | Where the coupling lives |
|---|---|---|
| **Provider** | Ingest scan data and translate it to the generic model | Scanner-specific (Rapid7, later Trivy/Grype/Wiz…) |
| **Model** | Images, vulnerabilities, counts, resources with free-form dimensions/labels | Nothing org- or vendor-specific |
| **Rules (CEL)** | Ownership attribution + actionability policy | Organization-specific — *your* config |
| **Sink** | Render findings (table, JSON; later Jira, GitOps PRs) | Output-specific |

The pipeline is: **provider → dedupe (by image) → attribute (owner) → policy
(actionable?) → sink**.

- **Dedupe** is the primary noise reducer: the same image runs in dozens of
  places but is assessed and remediated once.
- **Attribution** assigns each workload an owner via your rules — commonly
  `platform` / `cloud-provider` / `engineering`, but the classes are yours to
  define. Cloud-provider-managed images (e.g. `mcr.microsoft.com`,
  `registry.k8s.io`) get routed differently because you can't patch them directly.
- **Policy** decides what is actionable and at what priority, and suppresses
  what isn't (accepted risk, not-your-patch, false positives).

## Install / build

Requires Go 1.26+.

```sh
go build ./cmd/patchwright
```

## Usage

**Profile** the raw data first — quantify the noise and sanity-check how it
breaks down before writing rules:

```sh
patchwright profile -i export.csv
```

**Assess** — deduplicate, attribute owners, apply policy, and report:

```sh
# actionable findings, grouped by owner class
patchwright assess -i export.csv -c config/

# only the engineering slice, as JSON (for tooling / later Jira & GitOps sinks)
patchwright assess -i export.csv -c config/ --owner engineering --format json

# everything, including suppressed and non-actionable findings
patchwright assess -i export.csv -c config/ --all --show-suppressed
```

Key flags: `--provider` (default `rapid7`), `-i/--input`, `--mode` (`csv`|`api`),
`-c/--config` (file or directory, repeatable), `-f/--format` (`table`|`json`),
`--owner`, `--all`, `--show-suppressed`. Global: `--log-level`
(`debug`|`info`|`warn`|`error`) and `--log-format` (`text`|`json`) — logs go to
**stderr**, so the report on stdout stays clean (pipe JSON to `jq` freely).

### Live reconciliation (multi-cluster)

Scanner exports are a point-in-time snapshot; completed Jobs and scaled-to-zero
workloads still show up as findings. Reconcile against what is *actually
running* to drop that noise. patchwright deploys to one cluster but can read
many, via a kubeconfig with a read-only context per cluster:

```sh
# reconcile against live clusters (the not-running suppress rule then applies)
patchwright assess -i export.csv -c config/ \
  --live-source kube --live-option kubeconfig=$HOME/.kube/config \
  --live-option contexts=aks-prod-uk,aks-prod-us,gke-analytics

# or against an offline snapshot of running images (one image ref per line)
patchwright assess -i export.csv -c config/ \
  --live-source file --live-option path=live-images.txt
```

The report's `LIVE` column shows `yes`/`no` (or `?` when reconciliation didn't
run), and rules can reason over `reconciled` and `live` (see the `not-running`
rule in `config/policy.yaml`).

### Vulnerability scanning — fix availability

Turn "actionable" from a heuristic into "there's a fix to apply". With
`--vuln-source trivy`, each unique image is scanned once (after dedupe) and its
per-CVE detail — including `fix_available` / `fixed_version` — populates the
`vulns` list, so rules can require a fix before paging anyone. Requires the
[`trivy`](https://trivy.dev) binary (it pulls images itself, so it needs egress
and registry credentials for private images).

```sh
patchwright assess -i export.csv -c config/ \
  --vuln-source trivy --vuln-option severity=CRITICAL,HIGH
```

The report's `FIXCRIT` column shows fix-available critical CVEs; the JSON adds
`fixable_critical` and the full `vulns` array. Example rule:
`when: "vulns.exists(v, v.severity == 'critical' && v.fix_available)"`.

**Exploitability** — layer `--exploit-source public` on top to annotate each CVE
with its [EPSS](https://www.first.org/epss/) score (predicted exploitation
probability) and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
membership (exploited in the wild), from public feeds. Rules can then require a
CVE that is *both fixable and being/likely exploited* before paging:

```sh
patchwright assess -i export.csv -c config/ \
  --vuln-source trivy --exploit-source public
```

The `KEV` column and JSON `known_exploited` / `vulns[].epss` / `vulns[].kev`
surface it; e.g. `when: "vulns.exists(v, v.fix_available && (v.kev || v.epss > 0.5))"`.

### Remediation — is a newer version available?

Knowing a CVE has a fix is only half the story; the other half is *can you ship
the fix given how this is deployed*. With `--remediation` (requires
`--live-source kube`), patchwright reads **Flux `HelmRelease`s**, resolves each
chart's repository, and checks the repo index for a **newer chart version** —
the concrete remediation, and the input to later GitOps auto-PRs.

```sh
patchwright assess -i export.csv -c config/ \
  --live-source kube --live-option contexts=aks-prod --remediation
```

The `UPGRADE` column shows `current->latest`; the JSON adds an `upgrade` object
(`kind`, `current`, `latest`, `available`, `source`); and rules can gate on
`upgrade_available`, e.g. prioritise fixable, exploited CVEs that also have an
upgrade ready to ship. Git/OCI source revisions and direct image tags are the
next remediation kinds — see
[docs/design/remediation-availability.md](docs/design/remediation-availability.md).

## Writing rules

Rules are YAML with [CEL](https://github.com/google/cel-go) expressions.
Ownership rules match per-workload; policy rules match per finding
(one image, one owner, aggregated across its workloads). First match wins;
suppression beats actionability. See [`config/`](config/) for a documented,
editable starting point.

```yaml
# ownership.yaml — first match wins
owners:
  - name: cloud-provider-managed-images
    match: "image.registry in ['mcr.microsoft.com', 'registry.k8s.io']"
    class: cloud-provider
    team: aks
  - name: platform-system-namespaces
    match: "dimensions['namespace'] in ['kube-system', 'flux-system', 'cert-manager']"
    class: platform
    team: platform-engineering
  - name: engineering-by-label          # preferred once live labels are available
    match: "'team' in labels"
    class: engineering
    teamFrom: "labels['team']"
  - name: engineering-by-namespace      # fallback
    match: "true"
    class: engineering
    teamFrom: "dimensions['namespace']"
```

```yaml
# policy.yaml
suppress:
  - name: cloud-provider-managed
    when: "owner['class'] == 'cloud-provider'"   # can't patch these directly
actionable:
  - name: production-critical
    when: "counts['critical'] > 0 && dimensions['account'].exists(a, a.startsWith('Production'))"
    priority: high
  - name: any-critical
    when: "counts['critical'] > 0"
    priority: low
```

### How "actionable" is decided

Actionability is **purely the policy rules above, evaluated over the data
patchwright already has** — severity counts, environment (`dimensions`),
ownership, and liveness. There is **no live registry or CVE lookup today**: a
finding is "actionable" because it matched an `actionable` rule and no
`suppress` rule, not because a fix has been confirmed to exist.

The missing signal — *is there a patched image to move to?* — is planned via
Trivy (or the Rapid7 API), which populates the `vulns` list with `fix_available`
/ `fixed_version` so rules can require a fix before paging anyone. See
[docs/design/trivy-integration.md](docs/design/trivy-integration.md).

### Variables available to rules

**Ownership** (per occurrence): `image` `{registry, repository, tag, digest, ref}`,
`dimensions` `map<string,string>`, `labels` `map<string,string>`,
`counts` `map<string,int>` (standard severities always present),
`resource` `{id, type, name}`.

**Policy** (per finding): `image`, `counts`, `risk` (double),
`owner` `{class, team}`, `dimensions` `map<string,list<string>>` (union across
workloads), `labels` `map<string,list<string>>`, `vulns` `list` of
`{id, severity, cvss, fix_available, fixed_version}` (when the provider supplies
per-CVE detail).

## Deploying

patchwright ships as a container ([`Dockerfile`](Dockerfile)) and a Helm chart
([`deploy/helm/patchwright`](deploy/helm/patchwright)) that runs it as a CronJob.

**Auth is just RBAC.** For the cluster patchwright runs in, the chart creates a
ServiceAccount and a minimal read-only ClusterRole — `get`/`list` on `pods` and
`namespaces`, nothing else, no secrets, no writes. That is all reconciliation of
the local cluster needs; there are no credentials to manage.

```sh
# 1. make the scanner export available as a Secret (csv mode)
kubectl create secret generic patchwright-export --from-file=export.csv=./export.csv

# 2. install
helm install pw deploy/helm/patchwright \
  --set provider.input.secretName=patchwright-export

# 3. run it now instead of waiting for the schedule
kubectl create job --from=cronjob/pw-patchwright pw-manual && kubectl logs -f job/pw-manual
```

**Multi-cluster.** patchwright deploys to one cluster but reconciles many. Read
the local cluster via its ServiceAccount, and remote clusters via a kubeconfig
Secret of read-only contexts. In each remote cluster, apply
[`deploy/rbac/readonly-clusterrole.yaml`](deploy/rbac/readonly-clusterrole.yaml)
and bind it to the identity your kubeconfig authenticates as:

```sh
helm install pw deploy/helm/patchwright \
  --set provider.input.secretName=patchwright-export \
  --set reconcile.remote.kubeconfigSecret=pw-kubeconfig \
  --set 'reconcile.remote.contexts={aks-prod-uk,aks-prod-us,gke-analytics}'
```

**Scanning (Trivy) & private registries.** Trivy is bundled in the image; set
`scan.enabled=true` (and `scan.exploitSource=public` for EPSS/KEV) to scan images
in-cluster. Trivy pulls the images itself, so it needs credentials for **private
registries** — patchwright delegates to Trivy's standard auth. Two ways:

```sh
# Workload identity is provider-scoped (registryAuth.azure|gcp|aws) — no secrets.
# Azure (AKS + ACR): grant the managed identity AcrPull; the chart adds the SA
# client-id annotation AND the pod's `azure.workload.identity/use: "true"` label.
helm install pw deploy/helm/patchwright \
  --set provider.input.secretName=patchwright-export \
  --set scan.enabled=true \
  --set registryAuth.azure.workloadIdentity.enabled=true \
  --set registryAuth.azure.workloadIdentity.clientId=<managed-identity-client-id>

# GKE (Artifact Registry): --set registryAuth.gcp.workloadIdentity.enabled=true \
#                          --set registryAuth.gcp.workloadIdentity.serviceAccount=<gsa-email>
# EKS (ECR, IRSA):         --set registryAuth.aws.irsa.enabled=true \
#                          --set registryAuth.aws.irsa.roleArn=<role-arn>
# Any registry:            --set registryAuth.dockerConfigSecret=acr-pull  # a docker-config Secret
```

A per-image scan failure (e.g. a private image with no creds) is **tolerated** —
that finding is reported unscanned (`err` in the report) and the run continues.
Trivy also needs egress for its vuln DB (`ghcr.io/aquasecurity/trivy-db`) and, for
`exploitSource: public`, the CISA/FIRST feeds.

**Required inputs:** (1) the scanner export as a Secret (csv mode — refresh it
out-of-band until the Rapid7 API provider lands); (2) ownership + policy rules
(the chart ships editable examples in a ConfigMap via `config.ownership` /
`config.policy`); (3) optionally, a kubeconfig Secret for remote clusters, and
registry credentials if scanning private images. See
[`values.yaml`](deploy/helm/patchwright/values.yaml).

## Architecture & design

- [`docs/architecture`](docs/architecture) — C4 diagrams (LikeC4): system
  landscape, containers, the pipeline components, the assess flow, and the
  deployment topology. `likec4 start docs/architecture` to browse.
- [`docs/design`](docs/design) — design notes:
  [Trivy / fix-availability & exploitability](docs/design/trivy-integration.md),
  [remediation availability / upgrade path](docs/design/remediation-availability.md),
  and the [MCP server](docs/design/mcp-server.md).

## Roadmap

- **Phase 1** ✅ — noise-killer: CSV in, deduplicated, owner-attributed,
  actionable owner-split report out.
- **Phase 2** — in progress. ✅ multi-cluster live reconciliation (client-go
  `kube` + offline `file` live sources; drop not-running findings); ✅ ownership
  enrichment from live namespace labels like `team`; ✅ Helm chart + Docker
  image (CronJob, read-only RBAC, multi-cluster); ✅ kind-based e2e suite.
  Remaining: Rapid7 API provider.
- **Phase 3** — vulnerability intelligence.
  ✅ [fix availability](docs/design/trivy-integration.md) (`--vuln-source trivy`):
  scan each image once, populate `vulns` with `fix_available` / `fixed_version`.
  ✅ **exploitability** (`--exploit-source public`): annotate CVEs with EPSS +
  CISA KEV so rules require a fixable *and* exploited/likely CVE. Remaining:
  digest cache, VEX, `govulncheck`-style reachability, Rapid7-API vuln source.
- **Phase 4** — [remediation availability / upgrade path](docs/design/remediation-availability.md):
  detect deployment mechanism (Helm/Flux/Argo/manifest) and whether a newer
  version is available — the bridge to auto-remediation.
- **Phase 5** — [MCP server](docs/design/mcp-server.md) for less-technical users
  (natural-language queries over findings).
- **Phase 6** — Jira sink, then GitOps/Flux PR automation to roll fixes out.

## Development

```sh
make check             # fmt + vet (incl. e2e build tag) + unit/golden tests
make test              # unit + golden tests (no cluster required)
make deps              # install kind + ginkgo for integration tests
make test-integration  # kind-based e2e suite (requires docker + kind)

# refresh the golden file after an intended output change
go test ./pkg/pipeline -run TestAssessGolden -update
```

The e2e suite (`test/e2e`, `//go:build e2e`) stands up a real kind cluster,
deploys a running Deployment and a completed Job, and asserts that the
client-go live source and full pipeline mark running images live and
completed/absent ones as not-running.
