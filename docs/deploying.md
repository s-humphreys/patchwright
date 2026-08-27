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

## Deploying with a platform-managed identity

Where something else creates the ServiceAccount — a platform's identity CRD, Terraform,
a cloud operator — let it, and point the chart at it:

```yaml
serviceAccount:
  create: false
  name: patchwright        # the ServiceAccount that already exists
registryAuth:
  azure:
    workloadIdentity:
      enabled: true        # adds the pod label; the annotation is on the existing SA
```

`enabled: true` with `create: false` adds `azure.workload.identity/use` to the pod and
nothing else. The `client-id` annotation belongs to whoever owns the ServiceAccount, so
`clientId` is only required when the chart creates it.

## Provider-backed CVE detail and in-flight detection

A source named after the provider inherits the provider's options, so the base URL is
given once:

```yaml
provider:
  mode: api
  api:
    baseURL: https://example.customer.divvycloud.com
credentialsSecretName: patchwright     # RAPID7_API_KEY, AZURE_DEVOPS_PAT, ...
scan:
  enabled: true
  vulnSource: rapid7
  exploitSource: public,rapid7
age:
  source: rapid7
```

`vulnSource: rapid7` takes per-CVE detail from the platform rather than pulling images,
which is the only way to get it for a private registry the scanner has no credentials
for. It supplies no EPSS or KEV, so keep `public` in the exploit source list — `public`
is not the provider, so it inherits nothing.

Set `vulnOptions`, `exploitOptions` or `age.options` only to point a source somewhere
else. On the command line the same rule applies: `--vuln-source rapid7` with
`--provider rapid7 -o base-url=…` needs no `--vuln-option`.

## One Secret for every credential

Its keys are the environment variables the binary reads, so there is nothing to keep in
step between chart values and key names:

```sh
kubectl create secret generic patchwright \
  --from-literal=RAPID7_API_KEY="$RAPID7_API_KEY" \
  --from-literal=AZURE_DEVOPS_PAT="$AZURE_DEVOPS_PAT" \
  --from-literal=PATCHWRIGHT_API_TOKEN="$(openssl rand -base64 32)"
```

| Key | Enables |
| --- | --- |
| `RAPID7_API_KEY` | the scan provider in api mode |
| `AZURE_DEVOPS_PAT` | in-flight detection (pull requests) |
| `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` | ticketing |
| `PATCHWRIGHT_API_TOKEN` | requires a token on the API and page; open without it |

Include only what you use. An absent key is not a failure: patchwright reports what it
could not do rather than pretending it did, so a Secret holding only `RAPID7_API_KEY`
gives an assessment with ticket state shown as unknown and in-flight detection reported
as not run.

## Reading private registries

Patchwright reads registries to list tags and to read the image config that names an
image's base. It never pulls a layer, pushes or deletes, so read access is all it needs.

Credentials come from, in order:

1. **The docker config** — what `docker login` or `az acr login` leaves behind. First,
   deliberately: an explicit login must win over an ambient cloud identity, because
   surprising somebody with a different account than the one they logged into is worse
   than failing.
2. **A cloud provider**, for the registries it serves. Azure (`*.azurecr.io`) exchanges
   whatever Azure identity the process has — a workload identity's projected federated
   token, a managed identity, a service principal — for an ACR token. Google
   (`gcr.io`, `*.pkg.dev`) uses application default credentials.

In a cluster there is no docker config, only a projected token, which is why the second
exists. On AKS with `registryAuth.azure.workloadIdentity.enabled`, the pod gets
`AZURE_FEDERATED_TOKEN_FILE` and the Azure provider uses it: grant that identity
`AcrPull` and nothing else.

Each provider declares the hosts it serves and is asked about nothing else. That is not
tidiness — a credential helper asked about a foreign host goes looking rather than
declining, and the ACR helper spends thirty seconds on instance metadata before giving
up. Consulting it for `mcr.microsoft.com`, the base registry for every .NET image, cost
half a minute per read.

The Azure exchange is implemented here rather than taken from the obvious credential
helper, which carries GO-2026-6225 — credential leakage to untrusted hosts — with no
fixed version. It is the documented ACR flow on Microsoft's own SDK: get an AAD token
for whatever identity the process has, exchange it at the registry's `/oauth2/exchange`,
and present the result as the password with the null GUID as the username. It talks to
the registry it was asked about and nowhere else.

Adding AWS ECR is one file: register the hosts it serves and a keychain, as
`pkg/registryauth/google.go` does in seven lines.

## Rollouts take as long as an assessment

Readiness means "an assessment is cached". A new pod serves nothing until its first run
finishes, which is deliberate — a Service endpoint answering with an empty page is worse
than one that does not answer — but on a large estate that is fifteen to twenty minutes,
and every tool involved defaults to less:

| | Default | Needs to be |
| --- | --- | --- |
| Deployment `progressDeadlineSeconds` | 600s | `server.startupBudgetSeconds` (1800) |
| `helm install/upgrade --wait` | 5m | `--timeout 30m` |
| Flux HelmRelease | 5m | `spec.timeout: 30m` |

Leave any of them short and the install times out while the first assessment is still
running. With Flux that then fails twice over: the upgrade is marked failed, and the
rollback it attempts has no previously-successful release to return to, so the
HelmRelease stalls with `MissingRollbackTarget` while the pod it deployed sits there
perfectly healthy.

If fast rollouts matter more, make readiness mean "serving" instead — the page already
states plainly that no assessment has completed yet, so the cost is a route that briefly
answers with an empty queue rather than a misleading one.

## CronJob mode

`server.enabled: false` runs one assessment per schedule instead of a long-lived
server, writing findings to the log:

```yaml
server:
  enabled: false
cronjob:
  schedule: "0 7 * * *"
  format: ndjson       # one finding per line for a log pipeline
```

No API, no status page and no metrics: a CronJob has exited by the time anything
scrapes it, and the chart refuses to render a monitor alongside one. Auto ticketing is
refused too, since `--auto-ticket` is a server flag and a CronJob would report a ticket
plan it never applies.

This is also where persisting the Trivy database earns its keep, because every run
starts a fresh pod.

## Persisting the Trivy database

Trivy's vulnerability DB is several hundred MB and is downloaded on every pod start.
`scan.cache.persistence.enabled` mounts a PVC at the cache directory so a reschedule
or an upgrade does not pay for it again:

```yaml
scan:
  enabled: true
  cache:
    persistence:
      enabled: true
      size: 2Gi
      storageClass: managed-csi
```

The claim is kept when the release is uninstalled (`helm.sh/resource-policy: keep`),
since a reinstall that starts empty defeats the point. `existingClaim` uses one you
manage instead.

Only the DB is persisted. Tag listings and digests are re-read every run on purpose:
detecting that a floating tag moved is the whole basis of the base-image comparison,
and a cached answer there would report "unchanged" indefinitely. Scan results are left
to Trivy's own cache, which is keyed on the DB version, so a result can never outlive
the data that produced it.

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
