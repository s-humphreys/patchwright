# Rapid7 InsightCloudSec API

Notes on the API as it actually behaves, gathered by probing a live tenant. The
published reference describes a request body this deployment rejects, so
everything below was verified against real responses rather than the docs.

## Contract

Authentication is an `Api-Key` header. The base URL is per tenant
(`https://<tenant>.customer.divvycloud.com`) and is configuration, never a
default in code.

The list endpoints are `POST`-as-query: the method is POST, the body is `{}`, and
paging goes in the query string.

```
POST /v3/cvm/resource/vulnerabilities?page=1&page_size=100
{}
→ {"data": [...], "page": 1, "page_size": 100, "total_count": 4243, "total_pages": 43}
```

Things worth knowing, each of which cost a probe to establish:

- `limit`, `offset`, `filters` and `order_by` **in the body are rejected** as
  unknown fields. Paging is `page` / `page_size` in the query string.
- `page_size` is capped at 100. Asking for more is a 400, not a silent clamp.
- Rows are ordered by `id`, and paging genuinely advances, so a sweep does not
  re-read or skip rows. Worth re-checking if the provider ever adds sorting: an
  unstable order across pages would silently drop rows from a sweep.
- Errors are explained in the body (`{"messages": {"json": {...}}}`), so the body
  has to reach the user; the status line alone is unactionable.

## Endpoints

| Endpoint | Returns | Used for |
|---|---|---|
| `POST /v3/cvm/resource/vulnerabilities` | One row per image per resource: severity counts, risk score, account, cluster, digest, and `assessment_info` | The provider's `Fetch`. Equivalent to the CSV export, plus assessment status and cluster |
| `POST /v3/cvm/vulnerabilities` | One row per CVE across the estate: CVSS, `has_exploits`, `has_threats`, `resource_count`, title, URI | Not used yet. Exploit signals could complement EPSS/KEV |
| `POST /v3/cvm/resource/{resource_id}/vulnerabilities` | Per-CVE detail for one image | Not used yet. The basis for replacing Trivy |
| `GET /private/vulnerabilities/{cve_id}/packages` | Affected packages with `fixed_version`, current `version`, and `solutions` carrying literal upgrade commands | Not used yet. The fix data |

## Why the API rather than the export

The export drops the field that turns a coverage statistic into a work list.

`assessment_info` reports a `status` and, on failure, an `error_reason` in the
platform's own words. The export leaves `last_assessment` empty and says nothing
more, so an image behind an unusable registry credential is indistinguishable
from one that is merely queued.

Measured on a real estate of 4,243 rows across 872 images:

| Status | Rows | Share |
|---|---|---|
| `FAILED` | 3,579 | 84.4% |
| `COMPLETED` | 659 | 15.5% |
| `QUEUED` / absent | 5 | 0.1% |

And the failures were not diffuse. 3,215 of 3,579 were one cause, a registry
credential the platform could not use, which accounted for the entire coverage
gap on one owner class. That is a fixable problem that no amount of reporting
"unassessed" would have surfaced.

`COMPLETED` is the only status whose zero counts are a measurement. Every other
value means the counts are zero because nothing looked, which must never render
as a clean result.

## Not done yet: per-CVE detail

**Correction, later.** The conclusion below is about the estate-wide packages endpoint
and remains true of it - but it was allowed to stand as though no package data were
available at all, and that was wrong. The PER-RESOURCE endpoint embeds
`vuln_meta.Solutions[]`, carrying `package_name`, `package_type` and `fix` for the image
being asked about. That is now decoded, and it is where package data comes from. The
matching problem described here applies only to the estate-wide endpoint.

The two endpoints needed to replace `--vuln-source trivy` both work, but they do
not compose as neatly as they first appear, and the gap is worth writing down
before someone assumes it is a small job.

`POST /v3/cvm/resource/{id}/vulnerabilities` gives per-CVE detail for one image
but **no fixed version**. Fix data lives in
`GET /private/vulnerabilities/{cve}/packages`, which is keyed per CVE across the
whole estate, not per image. It returns affected packages with `fixed_version`,
a `version`, and `solutions` including literal commands (`go get stdlib@v1.23.10`).

The unresolved question is matching. The packages endpoint lists affected package
instances globally; nothing in it states which of those versions is the one in
*our* image. Concluding "a fix exists for this image" from a global list would be
a guess dressed as a fact, which is exactly the class of error the rest of this
tool exists to avoid. Resolving it needs either a per-image package list from the
platform or a documented statement of what that `version` field is scoped to.

Cost is the second problem. One image had 465 CVEs, so per-CVE fix lookups need a
cache keyed by CVE (they are estate-wide, so the cache is shared across images)
and a bound on how many are resolved per run.

Two smaller notes for whoever picks this up:

- `has_exploits` / `has_threats` are Rapid7's own exploitation signals. They
  overlap with CISA KEV but are not identical, so they belong alongside the
  existing exploit source rather than replacing it, and disagreement between them
  should be visible rather than resolved silently.
- `affected_packages` on a CVE row is a count, not a list, and it counts across
  the estate. It is not the number of packages affected in the image you are
  looking at.
