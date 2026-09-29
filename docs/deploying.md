# Deploying

A container and two Helm charts, all published to GHCR and versioned together:

| Artefact | What it is |
|---|---|
| `ghcr.io/s-humphreys/patchwright` | the image |
| `oci://ghcr.io/s-humphreys/charts/patchwright` | runs it as a Deployment serving the [API](api.md) |
| `oci://ghcr.io/s-humphreys/charts/patchwright-rbac` | read-only grant for each cluster it reads but does not run in |

```sh
helm install pw oci://ghcr.io/s-humphreys/charts/patchwright --version 2.0.0
```

One version across all three, stamped at release. The chart's `appVersion` IS the image
tag, so there is no tag to pin and nothing to go stale - which is worth stating because
the previous arrangement had three separate workarounds for exactly that (see
[Consuming it with Flux](#consuming-it-with-flux)).

The charts are signed with cosign, keylessly, so the signature is bound to the release
workflow's identity rather than to a key somebody holds:

```sh
cosign verify oci://ghcr.io/s-humphreys/charts/patchwright:2.0.0 \
  --certificate-identity-regexp '^https://github.com/s-humphreys/patchwright/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

All values: [`values.yaml`](../deploy/helm/patchwright/values.yaml). The charts are in
the repository too ([`deploy/helm`](../deploy/helm)), where their versions read
`0.0.0-dev`: a chart installed from a checkout is deliberately not a released one.

## Required inputs

1. **Scan data** — either `provider.mode: api` with your tenant URL and an API-key
   Secret (preferred), or `provider.mode: csv` with the export as a Secret you
   refresh out-of-band.
2. **Ownership and policy rules** — the chart ships editable examples in a ConfigMap
   via `config.ownership` / `config.policy`.
3. Optionally a kubeconfig Secret for remote clusters, and registry credentials for
   scanning private images.

**Rules and templates are read once, at startup.** Editing `config.policy`,
`config.ownership` or `ticketing.templates` updates the ConfigMap, and the running
pod carries on with what it parsed when it started — so a corrected rule or a
reworded ticket template quietly does nothing until the pod restarts. Parsing at
startup is deliberate: a template that does not parse should fail the deployment
rather than one team's first ticket of the month.

Nothing in the chart restarts the pod for you. Where config changes often, point a
controller that watches ConfigMaps at it:

```yaml
annotations:
  reloader.stakater.com/auto: "true"
```

Otherwise `kubectl rollout restart deploy/patchwright` after a config change.

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
read-only ClusterRole: `get`/`list` on `pods`, `namespaces`, `deployments`,
`statefulsets`, `daemonsets` and `cronjobs` (liveness counts deployed workloads, not
only live pods; see [reconciliation](reconciliation.md#what-counts-as-running)), and
`get` on `customresourcedefinitions`, whose install labels name an operator its custom
resources do not (see [remediation](remediation.md#operator-chosen-images)); a CRD is a
schema and holds no workload data. No Secrets, no write verbs, no credentials to manage.

## Multi-cluster

Read the local cluster via its ServiceAccount and remote clusters via a kubeconfig
Secret. In each remote cluster install the `patchwright-rbac` chart, bound to the
identity that cluster authenticates patchwright as:

```sh
helm install patchwright-rbac oci://ghcr.io/s-humphreys/charts/patchwright-rbac \
  --kube-context aks-prod-uk \
  --set subject.name=<the identity>
```

The subject is required, and the chart refuses anything that reads as a placeholder -
an empty value, `${VAR}`, `<object-id>`, `changeme`, or a `User` named in
SCREAMING_SNAKE_CASE. That last one is not hypothetical: the hand-applied file this
replaces once carried a bare `OBJECT_ID`, which `envsubst` leaves untouched because it
has no dollar sign. The binding it produced authenticated a user called "OBJECT_ID" in
every cluster, and replaced the grant that had been working - so nothing looked missing
until the next assessment failed everywhere at once.

With `authMode=azure` the subject is the managed identity's **object (principal) ID**,
not its client ID: different GUIDs for the same identity, and the wrong one
authenticates as nobody.

```sh
kubectl -n patchwright get managedidentity patchwright -o jsonpath='{.status.principalId}'
```

The read set follows the features in use. Pods, namespaces, workloads and cronjobs are
always granted, for liveness, as is `get` on `customresourcedefinitions`, for naming
operators; `rbac.remediation` adds Flux resources so an image deployed by a chart or operator can
be traced to the resource that sets its version. For
operator-owned custom resources, name their API groups in
`rbac.customResourceGroups`; `*` is refused, because `get` on every resource includes
Secrets in every namespace. The same key exists in both charts: `patchwright` for the
cluster it runs in, `patchwright-rbac` for each remote cluster. Without it, an image an
operator deploys shows as unknown and raises no ticket, because only its owning
resource says whether it sets the image and which operator picks the version. The main
chart's older `reconcile.remediationReadCRs` grants `get` on everything and is
deprecated in favour of it.

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
| `JIRA_EMAIL`, `JIRA_API_TOKEN` | ticketing, with an Atlassian API token |
| `JIRA_OAUTH_CLIENT_ID`, `JIRA_OAUTH_CLIENT_SECRET` | ticketing, with an OAuth app instead |
| `JIRA_OAUTH_REFRESH_TOKEN` | switches that app from client credentials to 3LO |

`JIRA_BASE_URL` and `JIRA_CLOUD_ID` are not credentials: they name the site, and the
base URL is what the status page builds issue links from. Set them in
`ticketing.jira`, not in the Secret.
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

## Reading more than one cluster

Reconciliation attributes ownership from namespace labels and drops workloads that are not
running, so a fleet reconciled in part is a fleet reported in part: images in the clusters
you did not read look unowned and not-live, and the `not-running` suppression would
quietly remove most of the estate.

```yaml
reconcile:
  enabled: true
  local: true                    # this cluster, via the pod's ServiceAccount
  remote:
    kubeconfigSecret: patchwright-clusters
    authMode: azure
    contexts: [aks-a, aks-b, aks-c]
```

With `authMode: azure` the kubeconfig holds NO credentials — only each cluster's API
server URL and CA certificate. Patchwright presents an AAD token for the identity it
already runs as, so there is nothing in that Secret worth stealing and nothing in it to
rotate. The alternative, a ServiceAccount token per cluster, means minting a long-lived
credential for every cluster and storing them together, which is the practice this tool
exists to argue against.

Each cluster then needs the reader role and a binding for the identity, from the
`patchwright-rbac` chart. The subject is the identity's OBJECT id, not its client id:
they are different GUIDs for the same identity, and the wrong one authenticates as
nobody. Read it from the ManagedIdentity status:

```sh
kubectl -n patchwright get managedidentity patchwright -o jsonpath='{.status.principalId}'
```

Pass it as `subject.name`, in each cluster:

```sh
helm install patchwright-rbac oci://ghcr.io/s-humphreys/charts/patchwright-rbac \
  --kube-context <remote-cluster> --set subject.name="$PRINCIPAL_ID"
```

There is no file to substitute into any more, which is the point: the chart refuses a
subject that still looks like a placeholder rather than applying it.

The kubeconfig itself is cluster and context stanzas only, with an empty users list.

A cluster that cannot be read fails the run rather than being skipped: partial liveness is
indistinguishable from workloads having stopped, and the queue would shrink for the wrong
reason.

## Base-image scanning and memory

`remediation.baseDiff` scans each distinct base tag rather than each image, so its
cost is fixed in the number of bases. On a real estate that was about 110 tags
against several thousand images: roughly eighteen minutes on the first run after a
restart, and close to nothing afterwards, because results are cached per digest for
the life of the process.

Give it memory before turning it on. Each scan is a Trivy process holding its
analysis in memory - the on-disk cache is deliberately off, since concurrent
processes deadlock on its lock - and eight at once over full language base images is
a peak the pod does not otherwise reach. A 2Gi limit that was ample before is not
necessarily ample now, and an OOM kill costs the whole assessment rather than the
scan that caused it.

If it does get OOM-killed, drop `remediation.baseDiff.concurrency` to 4 before
lowering the limit. Halving the concurrency roughly doubles that phase, which is the
slower outcome but not the one that loses data.

`remediation.baseDiff.scanExploited` adds a pull per image that carries an exploited
CVE its base does not explain - a few dozen on an estate of several hundred - through
the same bounded, cached resolver. Those are first-party application images, so the
pod's registry identity needs read access to them, not only to the bases.

## Consuming it with Flux

An `OCIRepository` for the chart and a `HelmRelease` that references it:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: patchwright
  namespace: flux-system
spec:
  interval: 60m
  url: oci://ghcr.io/s-humphreys/charts/patchwright
  ref:
    tag: 2.0.0
  # The cluster refuses a chart this workflow did not sign. A git tag can be moved by
  # anyone with write access to the repository; this cannot be forged by them.
  verify:
    provider: cosign
    matchOIDCIdentity:
      - issuer: "^https://token\\.actions\\.githubusercontent\\.com$"
        subject: "^https://github\\.com/s-humphreys/patchwright/"
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: patchwright
  namespace: flux-system
spec:
  targetNamespace: patchwright
  interval: 60m
  releaseName: patchwright
  chartRef:
    kind: OCIRepository
    name: patchwright
    namespace: flux-system
  # A first assessment takes longer than every default; see below.
  timeout: 45m
```

Needs helm-controller v1.1 or newer for `chartRef`.

### Upgrading from 1.x

Breaking, and deliberately so: 1.x had no chart artefact to upgrade *from*.

1. **Swap the source.** Replace the `GitRepository` with the `OCIRepository` above, and
   `spec.chart` with `spec.chartRef`. Same release name, so it is an in-place Helm
   upgrade rather than a reinstall - the release history and the PersistentVolumeClaim
   carry over.
2. **Delete three workarounds** from the HelmRelease: `reconcileStrategy: Revision`, the
   pinned `image.tag`, and the GitRepository's `ignore:` filter. Each existed only
   because the chart had no meaningful version; leaving `image.tag` behind is harmless
   but will pin you to an old image on the next chart bump.
3. **Reinstall the remote-cluster RBAC** with the `patchwright-rbac` chart. The two YAML
   files under `deploy/rbac` are gone; see
   [`deploy/rbac/README.md`](../deploy/rbac/README.md). The ClusterRole keeps its name,
   so installing the chart adopts the existing grant rather than creating a second one -
   Helm will refuse until you either delete the old objects or annotate them for
   adoption:

   ```sh
   for kind in clusterrole clusterrolebinding; do
     kubectl --context <remote> annotate "$kind" patchwright-reader \
       meta.helm.sh/release-name=patchwright-rbac \
       meta.helm.sh/release-namespace=default --overwrite
     kubectl --context <remote> label "$kind" patchwright-reader \
       app.kubernetes.io/managed-by=Helm --overwrite
   done
   ```

   Check the rendered rules against what the cluster has before applying. The Azure file
   granted more than the readonly one, so whichever you applied last is what you
   currently have.
4. **Nothing changes about the image**, the values, or the config. Values that worked on
   1.x work here.

### What this replaces, and why

The chart used to be consumed from git: a `GitRepository` pinned to a tag, with an
`ignore` filter stripping everything that was not the chart. That needed three
workarounds, all of them symptoms of a chart with no meaningful version:

- **`reconcileStrategy: Revision`**, because the chart's own version never moved.
  Advancing the GitRepository tag installed the OLD chart: the tag changed, `Chart.yaml`
  still said `0.2.0`, and Flux reused its cached artefact - so a fix that had already
  been released kept failing exactly as before.
- **`image.tag` pinned by hand**, because `appVersion` sat at `0.1.0` while the image
  was at `v1.29`, so the chart's own default pointed at a tag that did not exist.
- **The `ignore` filter**, because the chart shared a repository with the source, the
  tests and the docs.

None of them are needed now. The chart version is the release version, so a new tag is
a new artefact by definition; `appVersion` is the image tag; and the artefact contains
only the chart. A digest can be pinned as well (`ref.digest`), which a mutable git tag
could never offer.

## Rollouts take as long as an assessment

Readiness means "an assessment is cached". A new pod serves nothing until its first run
finishes, which is deliberate — a Service endpoint answering with an empty page is worse
than one that does not answer — but on a large estate that is fifteen to twenty minutes,
or closer to half an hour with base-image scanning on a cold cache, and every tool
involved defaults to less:

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

With [history](history.md) enabled most of this goes away after the first install:
a new pod serves the assessment the previous one stored, and is ready as soon as it
has read it, while its own first run proceeds in the background. The page says the
data is from before the restart and how old it is, and nothing is ticketed or
recorded from it. The budgets above still matter for a first install, for a database
that is unreachable at start, and for an upgrade that changes the stored payload's
schema, when the pod waits for its own run as before.

Without history, if fast rollouts matter more, make readiness mean "serving" instead — the page already
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

## History

[History](history.md) needs a PostgreSQL database. Describe the connection in values
and point at the Secret key holding the password:

```yaml
history:
  enabled: true
  retention: 400d
  connection:
    host: db.example.internal
    database: patchwright
    user: patchwright
  passwordSecretRef:
    name: patchwright-history
    key: password
```

The chart renders `PATCHWRIGHT_HISTORY_DSN` from the connection and injects the
password as `PATCHWRIGHT_HISTORY_PASSWORD`, so the HelmRelease shows the host and
nothing else. Alternatively leave `connection.host` empty and put a complete DSN in
the credentials Secret yourself. With `auth: azure` no password is used at all.

`enabled: false` with the key present in the Secret is history **off**: the chart
renders nothing for it and the binary is not told. `enabled: true` with no retention
fails at render, since a record with no retention is one nobody decided to keep.

With `auth: azure` the pod's workload identity must exist as a database user
(`pgaadauth_create_principal` on Azure) and the DSN names it with no password. The
NetworkPolicy, when enabled, opens TCP 5432 to anywhere; narrow it to the server's
address with `networkPolicy.egress` once you know it.

The role needs to own or have `CREATE` on the schema it connects to, because the
tables are created at startup. On PostgreSQL 15 and later `public` no longer grants
that to every role, and on Azure Database for PostgreSQL making the role the database
owner is not always enough either, so run this **connected to the history database**,
since schema privileges are per database:

```sql
\c patchwright
grant all on schema public to patchwright;
```

Without it the pod logs `history: store unavailable; will retry` with `permission
denied for schema public`, the assessment carries on unaffected, and the next use
after the grant connects and migrates.

With history on, each assessment is also stored whole so a restarted pod serves it at
once rather than waiting out a fresh run; see
[history.md](history.md#restarts-serve-the-last-assessment). It needs nothing extra
from the database: a few megabytes per row, three rows kept.

The record cannot be rebuilt if lost, so the database's backup is what stands between
the estate and a blank history. That is the point of choosing an operated database
over a volume.

## Splitting the worker from the page

By default one pod assesses and serves. That stays the default and needs no database.
With [history](#history) enabled, the chart can instead run two Deployments:

```yaml
history:
  enabled: true
  # ...as above
split:
  enabled: true
  web:
    replicas: 2
    resources: {}
    podDisruptionBudget:
      enabled: true
      maxUnavailable: 1
```

**When to use it.** When the page, the API and MCP must stay up while the assessment
restarts: a worker evicted mid-scan, killed for memory on a large estate, or rolled out
to pick up a config change no longer takes the page with it. And when more than one
replica should serve it, or the serving pods should not hold cluster read access. For a
small estate where a restart costs a few minutes and a stored assessment already covers
the gap (see [Rollouts](#rollouts-take-as-long-as-an-assessment)), one pod is simpler.

**What it deploys.** `split.enabled: false` renders exactly what it always has, byte for
byte. `true` renders instead:

| | Worker (`<release>-worker`) | Web (`<release>-web`) |
|---|---|---|
| Runs | `serve --role=worker`: the schedule, assessments, ticket reconciliation, history, tracker sync; stores each assessment | `serve --role=web`: the page, the API and MCP from the stored assessment and the record |
| Replicas | 1, `strategy: Recreate` | `split.web.replicas`, with a PodDisruptionBudget (`maxUnavailable: 1`, so a single replica never blocks a node drain) |
| Serves | `/healthz`, `/readyz`, `/metrics` only | everything, behind the release's Service |
| Kubernetes API | the ServiceAccount bound to the cluster-read ClusterRole | a ServiceAccount of its own (`<release>-web`), bound to nothing, token not mounted |
| Mounts | rules, Trivy cache, kubeconfig and docker config as configured | rules only |
| Writes | Jira, the history record, the stored assessment | only a refresh request |

The Service keeps its name and points at the web replicas, so an Ingress or HTTPRoute
you manage in front of it needs no change; the chart itself renders neither. The
worker gets a second Service, `<release>-worker`, for its metrics only, and the
ServiceMonitor or PodMonitor select the worker: its metrics describe the runs, and a
web replica makes none.

The web ServiceAccount is created by the chart whatever `serviceAccount.create` says:
with `create: false` the account you name is the one the cluster-read role is bound to
(by this chart or by patchwright-rbac), and the web replicas must not share it. Set
`split.web.serviceAccountName` to use an account you manage instead; the chart then
creates none, and that account should be bound to nothing.

Rendering refuses `split.enabled` without `history.enabled`, without `server.enabled`,
with no web replicas, and with `auth.oidc` but no source for `PATCHWRIGHT_SESSION_KEY`
(`auth.oidc.sessionKeyRef` or the credentials Secret). The binary makes the same checks:
`--role=web` or `--role=worker` without `PATCHWRIGHT_HISTORY_DSN` refuses to start, as
does `--role=web` with `--auto-ticket`, or with sign-in and no session key.

**How the halves talk.** Only through the database. The worker writes one row, every
ten seconds and at the start and end of each run: a heartbeat, whether it is running and
since when, how its last run ended, and its history status. A web replica reads it
every five seconds, which is where `/api/v1/summary`'s `running` and `started_at` come
from; a worker silent for a minute is not believed, and `error` says since when. The
Refresh button (`POST /api/v1/assessments`) on a web replica records a request time in
the same row, and the worker's next poll starts a run. A request while one is running
is answered by that run, as it is in a single pod. Web replicas look for a newer stored
assessment whenever the worker reports a run finished, and every thirty seconds besides.

A request row rather than an HTTP call to the worker because it survives the worker
restarting: a request made while the worker is down is waiting when it comes back,
rather than failing against a Service with no endpoints. It also needs no Service, no
credential and no NetworkPolicy rule between the two, and the database is already
there.

**What a web replica serves, and from where.**

| Endpoint or tool | In web mode |
|---|---|
| `/`, `/tickets`, `/analytics`, static assets | the embedded page, as ever |
| `/api/v1/findings`, `finding`, `items`, `service`, `cves`, `cve`, `owners`, `summary`, `analytics`, `policy`, `exploitability` | the stored assessment, which carries the open-ticket index the worker read when it ran |
| every MCP tool (`estate_summary`, `fix_plan`, `service_report`, `worst_first`, `team_report`, `explain_cve`, `list_facets`, `policy_report`, `exploitability_report`) | the stored assessment and the rules the replica loaded |
| MCP `trend_report`, `/api/v1/history`, `/api/v1/history/item`, `/api/v1/history/tickets` | the history record (the tracker's tickets are synced into it by the worker); read-only |
| `/api/v1/config` | the rules the replica loaded; mount the same config on both |
| `GET /api/v1/tickets` | by default 503, saying the plan is the worker's: a web replica holds no Jira credentials, and the worker logs every plan it makes. With `split.web.jiraCredentials: true`, planned from the stored assessment against Jira's open tickets read live: a search, safe on any number of replicas, with items in their grace period read from the record so the preview matches the worker's plan |
| `POST /api/v1/tickets` | 409: a web replica never writes to a tracker. The worker applies tickets with `--auto-ticket` (`ticketing.autoTicket`) |
| `POST /api/v1/assessments` | records a request the worker picks up |
| history status (`status` in `/api/v1/history`) | the worker's, from its row |
| `/metrics` | served, but describes nothing: scrape the worker |
| `/healthz`, `/readyz` | ready once a stored assessment is loaded |

**Sign-in and tokens across replicas.** Both are stateless: `PATCHWRIGHT_API_TOKEN` is
compared per request, and OIDC keeps its sign-in state and its session in cookies
signed with `PATCHWRIGHT_SESSION_KEY`. Nothing is held per process, which is why the
key is required: without it each replica signs with its own random key, and a sign-in
completed on one is not recognised by the next.

**Identity.** With `history.auth: azure` the web replicas need the workload identity to
reach the database, so the ServiceAccount the chart creates for them carries the
client-id annotation, and `registryAuth.azure.workloadIdentity.clientId` is required
even when `serviceAccount.create` is false. The managed identity needs a second
federated credential for the subject
`system:serviceaccount:<namespace>:<release>-web` (or the account named in
`split.web.serviceAccountName`), beside the worker's. With password authentication the
web replicas need no cloud identity at all and carry none.

**Credentials.** The web replicas do not take the whole `credentialsSecretName`. They
get named keys from it, each optional: `PATCHWRIGHT_API_TOKEN`,
`PATCHWRIGHT_SESSION_KEY` and `PATCHWRIGHT_OIDC_CLIENT_SECRET` (unless
`auth.oidc.sessionKeyRef` or `clientSecretRef` name them elsewhere), and
`PATCHWRIGHT_HISTORY_DSN` and `PATCHWRIGHT_HISTORY_PASSWORD` (unless
`history.connection` and `history.passwordSecretRef` supply them). The scan provider
key, registry and Azure DevOps credentials and the Jira credentials stay with the
worker.

`split.web.jiraCredentials: true` adds the `JIRA_*` keys, so the web replicas can show
the ticket plan preview. They only ever search Jira, so give them a read-only token if
your Jira allows one: the same Secret key serves both halves, so that means a Secret of
the web replicas' own, or accepting that they hold the worker's write-capable token.

**Switching.** Enabling the split on an existing release deletes the single Deployment
and creates the two, whose selectors differ; the Service stays. With a stored assessment
already in the database the web replicas are ready within seconds, so the page is down
only for the moments the Service has no ready endpoint.
