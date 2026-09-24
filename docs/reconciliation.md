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

Pods must be readable; a cluster that refuses them fails the assessment, as before.
Workload definitions are read where RBAC allows. A cluster that refuses one of those
lists (`403`, typically a remote cluster whose `patchwright-rbac` grant predates this)
logs a warning naming the missing grant, and the read is marked **partial**: images
that were seen are live, but an image that was not seen is left unreconciled
(`LIVE ?`) rather than marked not running, because without the workload definitions
"not deployed" cannot be told from "deployed with no pod right now". Unreconciled is
treated as live by policy and is never closed as not running, so a partial read
holds tickets rather than closing them.

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
