# Live reconciliation

Scanner exports are point-in-time: completed Jobs and scaled-to-zero workloads
still appear as findings. Reconciling against what is running drops that noise and
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

RBAC is `get`/`list` on `pods` and `namespaces`. For remote clusters, apply
[`deploy/rbac/readonly-clusterrole.yaml`](../deploy/rbac/readonly-clusterrole.yaml)
and bind it to the identity the kubeconfig authenticates as.
