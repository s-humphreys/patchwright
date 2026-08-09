# Architecture

C4 diagrams for patchwright, written in [LikeC4](https://likec4.dev). The model
is the source of truth — keep it in step with the code.

## Viewing

```sh
likec4 start docs/architecture          # interactive browser, live reload
likec4 validate docs/architecture       # type-check the model
likec4 export png docs/architecture -o docs/architecture/images   # static images
```

## The model

| File | Contents |
|---|---|
| [`model.c4`](model.c4) | Logical architecture: people, external systems, the patchwright system, its assessment core, and the components/pipeline. |
| [`deployment.c4`](deployment.c4) | How it's deployed: Helm CronJob, read-only RBAC, and multi-cluster reconciliation. |

## Views

- **`index` — System Landscape.** Who uses patchwright, the external systems it
  talks to (Rapid7, clusters, and the future Trivy / Jira / GitOps integrations),
  and the flow between them.
- **`containers` — Containers.** The two containers inside patchwright: the
  declarative rule **config** (CEL) and the **assessment core**.
- **`core` — Components & Pipeline.** The pipeline stages —
  `provider → enrich → dedupe → vulnscan → exploit → attribute → policy → sink` —
  and how config feeds the CEL-driven attribute and policy stages.
- **`assessFlow` — Assess flow (dynamic).** A step-by-step trace of a single
  assessment: reconciliation against clusters, Trivy scan, EPSS/KEV enrichment,
  ownership, and policy.
- **`deployment` — Deployment.** The Helm CronJob in a hub cluster, its
  ServiceAccount/ClusterRole, config and secret mounts, and read-only reads of
  the local and remote clusters.

Elements tagged **`future`** (amber) are planned, not yet built: the Rapid7 API
provider, the Jira / GitOps sinks, and (see [`docs/design`](../design)) VEX /
reachability and remediation-availability.
