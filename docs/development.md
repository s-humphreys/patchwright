# Development

Requires Go 1.26+.

```sh
make build             # packages + bin/patchwright
make check             # fmt + vet (incl. e2e build tag) + unit/golden tests
make test              # unit + golden tests, no cluster
make deps              # install kind + ginkgo
make test-integration  # kind-based e2e suite (needs docker + kind)

# refresh the golden file after an intended output change
go test ./pkg/pipeline -run TestAssessGolden -update
```

## Running against your own data

Put your export and rules in `local/` — the whole directory is gitignored.

```sh
make report       # assess local/*.csv with local/config, to stdout
make report-live  # + reconcile every kubeconfig context, + remediation,
                  #   into local/out/{findings.json,actionable.txt,run.log}

make report-live CONTEXTS=aks-prod-uk,aks-prod-us OUT=local/prod-only
make report-live SCAN=1          # add Trivy + EPSS/KEV
```

`report-live` defaults `CONTEXTS` to every kubeconfig context except local `kind-*`
clusters.

## e2e suite

`npm run test:ui` runs the pages in a real Chromium with Playwright, against a
fixture server (`test/ui/server.js`) that serves the embedded HTML and modules and
answers the API from `test/ui/fixtures`. It covers what jsdom cannot: a chart drawn
to a canvas and reacting to the cursor, a details element opening, a select that
changes the URL. A test that needs a different estate overrides a route in the
browser rather than editing the fixtures. First run needs
`npx playwright install chromium`.

`internal/server/static/app/vendor/` holds the one third-party browser library,
[uPlot](https://github.com/leeoniya/uPlot) (MIT, its licence beside it), vendored
rather than fetched so the page works with no outbound calls. To update it, copy
`dist/uPlot.iife.min.js` and `dist/uPlot.min.css` from the npm package. It is
excluded from the type check and from the tests that assert on our own modules.

The history store's tests run against a real PostgreSQL named by
`PATCHWRIGHT_TEST_POSTGRES_DSN` and skip without one:

```sh
docker run -d --rm -e POSTGRES_PASSWORD=pw -p 55432:5432 postgres:17-alpine
PATCHWRIGHT_TEST_POSTGRES_DSN=postgres://postgres:pw@localhost:55432/postgres go test ./pkg/history/postgres
```

`test/e2e` (`//go:build e2e`) stands up a real kind cluster, deploys a running
Deployment and a completed Job, and asserts the client-go live source and the full
pipeline mark running images live and completed or absent ones not-running.

## Layout

| Path | Contents |
|---|---|
| `pkg/provider` | Scan-data ingestion, per vendor |
| `pkg/model` | The vendor-neutral model |
| `pkg/dedupe`, `pkg/attribute`, `pkg/policy` | Pipeline stages |
| `pkg/enrich` | Live reconciliation, vuln scanning, exploit intel |
| `pkg/upgrade` | Remediation availability |
| `pkg/ticket` | Ticket planning, reconciliation, Jira client |
| `pkg/sink` | Table and JSON rendering |
| `internal/server` | HTTP API, status page |
| `internal/metrics` | Prometheus metrics |
| `internal/cli` | Commands |

## The status page

The page is plain ES modules under `internal/server/static/app/`, served from the Go
binary's embedded tree. There is no build step and nothing is bundled: browsers load
modules natively, so the single-binary deploy stays intact and a security tool ships no
npm dependencies.

The tooling in `package.json` is dev-only:

```sh
npm ci
npm run check   # tsc --noEmit --checkJs over the modules
npm test        # node --test + jsdom over the rendering
```

Both run in CI. They exist because two bugs shipped invisibly: a duplicate `title` key
that silently overrode a column's hover text, and a CSS class used before it existed.
Type-checking catches both, and the tests assert the thing this project keeps getting
wrong — that absent data never renders as good news (`?` not `-`, unknown not
internal).

Modules must not touch the DOM at import time. Listeners live in `init*()` functions
called from `main.js`, so a module can be imported by a test without standing up the
whole page.
