# Live reconciliation

Scanner exports are point-in-time: completed Jobs and removed workloads still
appear as findings. Reconciling against what is running drops that noise and
supplies namespace labels for ownership.

patchwright deploys to one cluster and can read many, via a kubeconfig with a
read-only context per cluster.

```sh
# live clusters
patchwright assess -i export.csv -c config/ \
  --live-source kube --live-option kubeconfig=$HOME/.kube/config \
  --live-option contexts=aks-prod-uk,aks-prod-us,gke-analytics

# in-cluster, using the pod's ServiceAccount
patchwright assess -i export.csv -c config/ \
  --live-source kube --live-option inCluster=true

# offline snapshot: one image reference per line
patchwright assess -i export.csv -c config/ \
  --live-source file --live-option path=live-images.txt
```

The `LIVE` column shows `yes` / `no`, or `?` when reconciliation did not run.
Rules can read `reconciled` and `live`; see the `not-running` rule in
[`config/policy.yaml`](../config/policy.yaml).

## What counts as running

An image is live when, in any cluster read, it is used by (containers or init
containers):

- a Pod in the `Running` or `Pending` phase, which covers bare pods and Jobs;
- a Deployment, StatefulSet or DaemonSet pod template, **including one scaled to
  zero**: it is still deployed, and scale-to-zero (KEDA, for example) brings it back
  on demand;
- a CronJob's job template, unless the CronJob is suspended.

Pods alone are not enough. A CronJob that runs for twenty seconds every two hours
has no pod almost all the time, and a workload whose pod is being recreated has
windows with none. Judged by pods, both look decommissioned, and "not running" is
what closes a ticket.

Everything else - a completed Job's image, a deleted workload's, a suspended
CronJob's - is not running.

Within a cluster, pods must be readable (a cluster that refuses them cannot be read;
see [When a cluster cannot be read](#when-a-cluster-cannot-be-read)), and workload
definitions are read where RBAC allows. A cluster that refuses one of those
lists (`403`, typically a remote cluster whose `patchwright-rbac` grant predates this)
logs a warning naming the missing grant, and the read is marked **partial**: images
that were seen are live, but an image that was not seen is left unreconciled
(`LIVE ?`) rather than marked not running, because without the workload definitions
"not deployed" cannot be told from "deployed with no pod right now". Unreconciled is
treated as live by policy and is never closed as not running, so a partial read
holds tickets rather than closing them.

## When a cluster cannot be read

One cluster failing does not fail the assessment. If any read of a cluster fails with
anything other than the `403` on a workload list above (a `401`, a timeout, a `5xx`, a
dropped connection, or the pod list itself being refused), that cluster is **left out
of this run whole**. Nothing it returned before the failure is kept: half a cluster
read as a whole one would call its CronJob images not running.

- A `401` or a transient fault (`5xx`, `429`, timeouts, connection resets) is retried
  once after two seconds first. With `authMode=azure`, a token an API server rejects
  is dropped from the cache, so the retry presents a freshly minted one. A `403` is
  not retried.
- The read is marked **partial**, exactly as for a refused workload list: images seen
  in another cluster are live, and an image seen nowhere else is left unreconciled
  (`LIVE ?`), so nothing is closed as not running on the unread cluster's account.
- A warning names the cluster and the error, the page's data gaps panel and every MCP
  report caveat say `cluster X could not be read` and what that leaves unknown, and
  `patchwright_cluster_read_failures_total{cluster,read}` counts it.
- The cluster is tried again on the next run.

The same applies to the other reads the kube source makes per cluster: namespace
labels (ownership there falls back to rules that do not use labels), deployment
context, and Flux chart upgrades. Each leaves an unreadable cluster out and carries on.

If **every** cluster fails, the read fails and so does the assessment, as before:
nothing was read, so nothing was reconciled. The previous assessment keeps being
served until a run succeeds.

## RBAC

`get`/`list` on `pods`, `namespaces`, `deployments`, `statefulsets`, `daemonsets`
and `cronjobs`. For remote clusters, install the
`patchwright-rbac` chart and bind it to the identity the kubeconfig authenticates as:

```sh
helm install patchwright-rbac oci://ghcr.io/s-humphreys/charts/patchwright-rbac \
  --kube-context aks-prod-uk --set subject.name=<the identity>
```

The subject is required and placeholder-shaped values are refused; see
[deploying](deploying.md#multi-cluster).
