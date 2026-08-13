# Deploying

A container ([`Dockerfile`](../Dockerfile)) and a Helm chart
([`deploy/helm/patchwright`](../deploy/helm/patchwright)) that runs it as a
Deployment serving the [API](api.md). All values:
[`values.yaml`](../deploy/helm/patchwright/values.yaml).

## Required inputs

1. **Scan data** — either `provider.mode: api` with your tenant URL and an API-key
   Secret (preferred), or `provider.mode: csv` with the export as a Secret you
   refresh out-of-band.
2. **Ownership and policy rules** — the chart ships editable examples in a ConfigMap
   via `config.ownership` / `config.policy`.
3. Optionally a kubeconfig Secret for remote clusters, and registry credentials for
   scanning private images.

## API mode

```sh
kubectl create secret generic patchwright-rapid7 --from-literal=apiKey="$RAPID7_API_KEY"
kubectl create secret generic patchwright-api --from-literal=token="$(openssl rand -hex 32)"

helm install pw deploy/helm/patchwright \
  --set provider.mode=api \
  --set provider.api.baseURL=https://example.customer.divvycloud.com \
  --set provider.api.credentialsSecretName=patchwright-rapid7 \
  --set server.auth.secretName=patchwright-api

kubectl port-forward svc/pw-patchwright 8080:8080 &
curl -su :"$TOKEN" localhost:8080/api/v1/summary
```

Rendering fails if a mode's inputs are missing, rather than deploying something that
cannot work.

## RBAC

For the cluster patchwright runs in, the chart creates a ServiceAccount and a minimal
read-only ClusterRole: `get`/`list` on `pods` and `namespaces`. No Secrets, no write
verbs, no credentials to manage.

## Multi-cluster

Read the local cluster via its ServiceAccount and remote clusters via a kubeconfig
Secret. In each remote cluster apply
[`deploy/rbac/readonly-clusterrole.yaml`](../deploy/rbac/readonly-clusterrole.yaml)
and bind it to the identity the kubeconfig authenticates as.

```sh
helm install pw deploy/helm/patchwright \
  --set provider.input.secretName=patchwright-export \
  --set reconcile.remote.kubeconfigSecret=pw-kubeconfig \
  --set 'reconcile.remote.contexts={aks-prod-uk,aks-prod-us,gke-analytics}'
```

## Scanning and private registries

Trivy is bundled in the image. `scan.enabled=true` (plus
`scan.exploitSource=public` for EPSS/KEV) scans in-cluster. Trivy pulls the images
itself, so private registries need credentials — patchwright delegates to Trivy's
standard auth.

```sh
# Workload identity, no secrets. Azure: grant the managed identity AcrPull.
helm install pw deploy/helm/patchwright \
  --set scan.enabled=true \
  --set registryAuth.azure.workloadIdentity.enabled=true \
  --set registryAuth.azure.workloadIdentity.clientId=<client-id>

# GKE:  --set registryAuth.gcp.workloadIdentity.enabled=true \
#       --set registryAuth.gcp.workloadIdentity.serviceAccount=<gsa-email>
# EKS:  --set registryAuth.aws.irsa.enabled=true \
#       --set registryAuth.aws.irsa.roleArn=<role-arn>
# Any:  --set registryAuth.dockerConfigSecret=acr-pull
```

Trivy needs egress to its vuln DB (`ghcr.io/aquasecurity/trivy-db`) and, for
`exploitSource: public`, to the CISA and FIRST feeds.

## Ticketing and metrics

```sh
kubectl create secret generic patchwright-jira \
  --from-literal=baseUrl=https://your-site.atlassian.net \
  --from-literal=email=you@example.com \
  --from-literal=apiToken="$JIRA_API_TOKEN"

helm upgrade pw deploy/helm/patchwright \
  --set ticketing.enabled=true \
  --set ticketing.credentialsSecretName=patchwright-jira \
  --set ticketing.autoTicket=false \
  --set metrics.serviceMonitor.enabled=true
```

`autoTicket` is off by default: a service that starts raising tickets the moment it
deploys is not a good surprise. Metrics scraping requires `server.enabled` — a
CronJob has exited by the time anything scrapes it.

`networkPolicy.enabled=true` restricts ingress to the API port and egress to HTTPS;
the defaults are coarse and meant to be overridden.
