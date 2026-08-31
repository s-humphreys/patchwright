# The RBAC that used to live here

`readonly-clusterrole.yaml` and `azure-workload-identity-reader.yaml` were removed in
**2.0**. They are replaced by the
[`patchwright-rbac`](../helm/patchwright-rbac) chart, published beside the image as
`oci://ghcr.io/s-humphreys/charts/patchwright-rbac`.

Removed rather than deprecated, because leaving them was the greater risk: two files
defining the same ClusterRole are two grants that can be applied in either order, and
whichever went last decided what patchwright could read.

## Why they went

**They had already drifted.** Both defined a ClusterRole called `patchwright-reader`
with different rules - the readonly one granted pods, namespaces, services and
httproutes; the Azure one granted those plus workloads and Flux resources. Nothing said
which was current, and applying the smaller one over the larger one silently removed
the reads that remediation needs.

**The substitution step was dangerous.** The Azure file carried a `${OBJECT_ID}`
placeholder for `envsubst`, and had once carried a bare `OBJECT_ID`, which envsubst
leaves untouched because it has no dollar sign. The applied result bound the ClusterRole
to a user literally called "OBJECT_ID", and every cluster refused the real identity on
the next run - a working grant replaced by one that granted nobody anything, which is
worse than no grant because nothing looks missing until the next assessment fails
everywhere at once.

The chart makes every one of those a render-time failure: an empty subject, `${VAR}`,
`$VAR`, `<placeholder>`, anything reading as "changeme", and a `User` named in
SCREAMING_SNAKE_CASE.

## What to run instead

```sh
helm install patchwright-rbac oci://ghcr.io/s-humphreys/charts/patchwright-rbac \
  --kube-context <remote-cluster> \
  --set subject.name="$(kubectl -n patchwright get managedidentity patchwright \
      -o jsonpath='{.status.principalId}')"
```

Or render it and apply the YAML yourself, which is the same review step the `envsubst`
pipeline never had:

```sh
helm template patchwright-rbac oci://ghcr.io/s-humphreys/charts/patchwright-rbac \
  --set subject.name=<the identity> > rbac.yaml

# Read rbac.yaml, then:
kubectl --context <remote-cluster> apply -f rbac.yaml
```

Nothing needs Helm installed in the remote cluster; the chart is only a renderer here.

See [docs/deploying.md](../../docs/deploying.md) for the read set, what each part of it
is for, and the values that turn each part on.
