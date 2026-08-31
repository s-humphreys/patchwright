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

## Internet exposure

Whether a workload is reachable from outside is measured here rather than taken
from the scan provider, because a provider that reports the same value for every
workload makes an urgency rule mentioning exposure look configured and do nothing.
Worse, when its field is PRESENT the finding reads as "internal" - an assertion
rather than an absence.

A workload is reachable if something in front of it is: a LoadBalancer Service, or
a Gateway API HTTPRoute pointing at a Service whose selector matches its pods.

```sh
patchwright assess ... \
  --live-source kube \
  --live-option publicHostnames=example.com \
  --live-option internalHostnames=internal.example.com
```

Hostnames decide it when you name them, and they usually have to. A gateway is not
necessarily internet-facing - a proxy can sit in front of it that Kubernetes knows
nothing about - and on a real estate the same service answers on both an internal
name and a public one. The most specific suffix wins, so `example.com` can be
public while `internal.example.com` beneath it is not, and a suffix named in both
lists resolves to NOT public: the safe reading of a contradiction about exposure is
the one that does not escalate.

Without hostnames every routed service counts as exposed, which over-reports. That
is the safe direction to be wrong in and a poor substitute for stating the domains.
An internal Azure load balancer is excluded regardless, since that one is stated by
the platform rather than guessed.

Two deliberate limits. A Service with no selector exposes nothing, because matching
every pod in its namespace would mark the namespace public. And exposed anywhere
wins: the same image behind a route in one namespace and nothing in another is
reachable, and the finding is about the image.

A failure here is logged rather than fatal, unlike liveness and labels. It needs
permissions the others do not, and the result is all-or-nothing by design - reading
one cluster and being refused another would mark workloads internal that are
exposed via the cluster that refused, which is the false negative this removes. So
either every cluster answers or the provider's own value stands.

Ingresses are deliberately not read.

## RBAC

`get`/`list` on `pods` and `namespaces`, plus `services` and Gateway API
`httproutes` when exposure is enabled. For remote clusters, install the
`patchwright-rbac` chart and bind it to the identity the kubeconfig authenticates as:

```sh
helm install patchwright-rbac oci://ghcr.io/s-humphreys/charts/patchwright-rbac \
  --kube-context aks-prod-uk --set subject.name=<the identity>
```

The subject is required and placeholder-shaped values are refused; see
[deploying](deploying.md#multi-cluster).
