# Design: remediation availability / upgrade path

Status: **in progress** — Helm-chart upgrade detection is implemented
(`--remediation`): patchwright reads Flux `HelmRelease`s, resolves each chart's
`HelmRepository`, and checks the repo index for a newer chart version, attaching
`Upgrade{current,latest,available,source}` to the images that release produced.
Surfaced via the `UPGRADE` column, the JSON `upgrade` object, and the
`upgrade_available` policy variable. **Remaining:** Flux Git/OCI source revisions,
direct-image tag checks, direct (non-Flux) Helm releases, and the deployment-
mechanism labelling described below (helm/flux/argo/manifest).

## Why this is its own feature

Fix availability (Trivy) answers *"is there a patched version of this package?"*.
It does **not** answer the question that actually decides whether a human can do
something today:

> *Given the way this workload is deployed, is a newer version available, and
> what exactly do I change to get it?*

That's a different question, with different data sources, and it's the direct
input to auto-remediation (GitOps PRs). So it belongs as its own capability that
**feeds actionability and prioritisation** — not as another vuln field.

## What it determines

For each finding, two things:

### 1. Deployment mechanism — *how is this deployed?*

Read from the cluster (an extension of the reconciliation we already do), via
owner references and well-known labels/annotations:

| Mechanism | How we detect it | How it's fixed |
|---|---|---|
| Helm release | `app.kubernetes.io/managed-by=Helm`, `meta.helm.sh/release-name` | bump chart or image in values |
| Flux | `kustomize.toolkit.fluxcd.io/*`, `helm.toolkit.fluxcd.io/*` labels | PR to the Flux source repo |
| Argo CD | `argocd.argoproj.io/instance` | PR to the app repo |
| Operator-managed | `ownerReferences` to a CRD | bump the operator / CR |
| Plain manifest | none of the above | bump the image in the manifest |
| Cloud-provider managed | image registry (already classified) | node image upgrade / wait |

This maps cleanly onto the existing owner *class* but is more granular: it's the
**remediation path**, and it tells you *who and what repo* the change lands in.

### 2. Upgrade availability — *is a newer version out?*

Per mechanism:

- **App image (your registry):** is there a newer tag/digest than the running
  one? (registry tag list; needs a sane tag ordering — semver where possible.)
- **Third-party Helm chart:** is there a newer chart version in the repo index
  whose `appVersion`/image carries the fix? (query the Helm repo `index.yaml`.)
- **Base image:** is a newer base tag available (feeds a rebuild)?

## How it surfaces (signals, not a separate verdict)

Consistent with liveness and fix-availability: add finding-level signals, expose
them to CEL, show them compactly — but keep `actionable` as the single verdict.

Proposed finding fields:

- `deployment_mechanism` — helm | flux | argo | operator | manifest | managed | unknown
- `upgrade_available` — bool
- `remediation` — a short structured action (e.g. `bump chart flux2 2.12→2.14`,
  `bump image acme/orders 1.0.381→1.0.400`)

Then policy can express, e.g.:

```yaml
actionable:
  # Do-now queue: exploited & fixable & an upgrade is actually available.
  - name: exploited-fixable-upgradable
    when: "upgrade_available && vulns.exists(v, v.fix_available && (v.kev || v.epss > 0.5))"
    priority: high
suppress:
  # Blocked: fixable in theory, but no packaged upgrade for this deployment yet.
  - name: no-upgrade-path
    when: "vulns.exists(v, v.fix_available) && reconciled && !upgrade_available"
```

## Architecture

A `RemediationEnricher` (finding/image-level, after scanning) composed of:

- a **deployment resolver** — reuses the kube client-go reader to fetch
  owner refs + labels for each workload and classify the mechanism;
- one or more **upgrade resolvers** — a registry-tag resolver and a Helm-repo
  resolver, behind a small interface (like `VulnSource` / `LiveSource`).

Model additions: `DeploymentMechanism`, `UpgradeAvailable`, `Remediation` on the
finding (or a nested `Remediation` struct).

## Bridge to GitOps PR automation

Once `remediation` is a structured action and the deployment mechanism points at
a repo/path, the later GitOps phase is mechanical: locate the file, apply the
bump, open a PR. This feature is the prerequisite — it turns "there's a fix" into
"here is the exact one-line change and where it goes".

## Open questions

- **Tag ordering / "newer".** Arbitrary tags (`918319`, `1.0.381-rc`) don't sort
  cleanly. Prefer digest + build metadata, or require semver for the "newer tag"
  check; fall back to "unknown".
- **Repo mapping.** Connecting a Helm release / Flux Kustomization to the actual
  Git repo+path may need a small config map or Flux/Argo CRD introspection.
- **Cost.** Registry tag lists + Helm index fetches — cache by repo, refresh
  periodically.

## Phasing

1. Deployment-mechanism detection (cluster read) → `deployment_mechanism` field.
2. Registry-tag upgrade resolver → `upgrade_available` for app images.
3. Helm-repo upgrade resolver → chart upgrades for third-party charts.
4. Structured `remediation` action → hand-off to GitOps PR automation.
