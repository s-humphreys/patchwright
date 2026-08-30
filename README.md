<p align="center">
  <img src="./docs/images/patchwright.png" alt="Logo" width="200" height="auto" />
</p>
<h1 align="center">patchwright</h1>

Turn noisy container-vulnerability scanner output into a **deduplicated,
owner-attributed, actionable** list.

Scanners tell you *"this is a problem"* — thousands of rows of it. patchwright
answers the harder questions: which problems, who can fix them, and what is worth
acting on now. It reasons over vendor-neutral primitives (images, CVEs, counts) and
pushes organization-specific judgement into declarative CEL rules you own.

In practice it collapses thousands of scanner rows into a few dozen actionable
findings: deduplicating by image, splitting work between teams, routing
cloud-provider-managed images out of the queue, and dropping workloads that are not
running.

It is equally deliberate about what it does *not* claim. An image the scanner never
assessed reports `?`, never `0` — absent data and a clean result are different
answers, and rendering the first as the second is the most misleading thing a
vulnerability report can do.

---

## Quickstart

Requires Go 1.27+.

```sh
go build ./cmd/patchwright

# what does the raw data look like?
patchwright profile -i export.csv

# the actionable queue, grouped by owner
patchwright assess -i export.csv -c config/

# with live clusters, fix availability, and upgrade detection
patchwright assess -i export.csv -c config/ \
  --live-source kube --live-option contexts=aks-prod \
  --vuln-source trivy --exploit-source public --remediation
```

[`config/`](config/) is a documented, editable starting point for the rules.

## How it works

```
provider → dedupe (by image) → attribute (owner) → policy (actionable?) → sink
```

| Layer | Responsibility | Coupling |
|---|---|---|
| **Provider** | Ingest scan data, translate to the model | Scanner-specific |
| **Model** | Images, CVEs, counts, resources with free-form dimensions and labels | Nothing vendor- or org-specific |
| **Rules (CEL)** | Ownership attribution and actionability policy | Yours |
| **Sink** | Render findings: table, JSON, tickets, API | Output-specific |

- **Dedupe** is the primary noise reducer: the same image runs in dozens of places
  and is assessed and remediated once.
- **Attribution** assigns each workload an owner via your rules. Cloud-provider
  images are routed differently because you cannot patch them directly.
- **Policy** decides what is actionable, at what priority, and what to suppress.

Two things it measures rather than assumes, because the alternative is a number
somebody acts on:

- **What a base rebuild would clear.** Scanning the base image and the one being
  recommended turns "a newer base exists" into "this clears 3,664 of your 4,890,
  and 93 of them are actually yours".
- **Whether a workload is reachable from the internet**, read from the clusters. A
  scan provider that reports the same value for every workload makes an urgency
  rule mentioning exposure look configured and do nothing.

## Documentation

| | |
|---|---|
| [CLI](docs/cli.md) | Commands, flags, and how to read the report |
| [Providers](docs/providers.md) | Rapid7 CSV export vs the API |
| [Live reconciliation](docs/reconciliation.md) | Drop what is not running; multi-cluster; internet exposure |
| [Scanning](docs/scanning.md) | Fix availability, EPSS and KEV, and what a base rebuild would clear |
| [Remediation](docs/remediation.md) | Is there a newer version, and can you apply it? |
| [Rules](docs/rules.md) | Writing ownership and policy rules |
| [Ticketing](docs/ticketing.md) | Raising, routing, updating and closing Jira tickets |
| [API](docs/api.md) · [reference](https://patchwright.shumphreys.com) | `serve`, endpoints, the status page |
| [Authentication](docs/authentication.md) | Sign-in with OIDC, and tokens for scripts |
| [Metrics](docs/metrics.md) | Prometheus metrics and what to alert on |
| [Deploying](docs/deploying.md) | Helm chart, RBAC, registry credentials |
| [Development](docs/development.md) | Build, test, run against your own data |
| [Security](SECURITY.md) | What it touches, and what it deliberately cannot do |

Design notes live in [`docs/design`](docs/design); C4 diagrams in
[`docs/architecture`](docs/architecture) (`likec4 start docs/architecture`).

## Roadmap

- **Phase 1** ✅ Noise-killer: CSV in, deduplicated owner-attributed queue out.
- **Phase 2** ✅ Multi-cluster live reconciliation, ownership from namespace labels,
  Helm chart and image, kind-based e2e, Rapid7 API provider.
- **Phase 3** ✅ Fix availability (`--vuln-source trivy`) and exploitability
  (`--exploit-source public`). ✅ Per-CVE detail from the Rapid7 API. Remaining: VEX,
  reachability.
- **Phase 4** ✅ [Remediation availability](docs/design/remediation-availability.md):
  Flux charts and registry tags. ✅
  [Base-image upgrades for first-party images](docs/design/base-image-remediation.md),
  with support-window checking. Remaining: git/OCI source revisions.
- **Phase 5** ✅ Jira ticketing with routing, reconciliation and evidence-based
  closing. ✅ API, status page and metrics.
- **Phase 6** ✅ [Remediation already in flight](docs/design/remediation-in-flight.md)
  so a fix sitting in an open PR is not ticketed again. ✅ Base-image differential
  and measured internet exposure. ✅ Analytics: what to fix first, and what nobody is
  acting on. Remaining: an [MCP server](docs/design/mcp-server.md) for
  natural-language queries.

  Rolling fixes out is deliberately **not** here. An update bot already opens those
  pull requests, and a second thing computing versions would be two answers to one
  question. What is missing is knowing which repositories it covers, which is a read
  rather than an automation.
- **Next** Persistence. Every assessment is a snapshot, so nothing the tool says is
  about movement: it cannot report time to remediate, whether a queue is shrinking,
  or whether a change actually helped. That needs storage, which the design has so
  far deliberately avoided — a decision worth making explicitly rather than by
  accident.

## Licence

[MIT](LICENSE).
