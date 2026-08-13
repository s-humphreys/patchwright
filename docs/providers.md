# Providers

A provider ingests scan data and translates it to the generic model. Rapid7
InsightCloudSec is the only one today, in two modes.

## csv

Reads an exported InsightCloudSec "Resources" CSV.

```sh
patchwright assess -i export.csv -c config/
```

## api

Queries InsightCloudSec directly. The key comes from `RAPID7_API_KEY`, never an
option — options are populated from config files and Helm values, which live in
git.

```sh
export RAPID7_API_KEY=...
patchwright assess --mode api \
  -o base-url=https://example.customer.divvycloud.com -c config/
```

Prefer it over the export for two reasons.

**It is current.** An export ages from the moment it is written, and a server
refreshing hourly over a mounted file reports a fresh assessment of stale data
indefinitely.

**It says why an image was not assessed.** The export leaves `last_assessment`
empty and stops there, so every uncovered image looks alike. The API returns
`assessment_info`, which patchwright surfaces as `assessment_issues` per finding,
`unassessed_reasons` on the API summary, on the status page, and in the coverage
warning:

```
WARN provider never assessed some images — their zero counts are absence of data,
     not a clean result  unassessed_images=773 total_images=854
     top_reason="Can't authenticate to registry. Unable to obtain refresh token..."
     images_affected=734
```

On the estate this was built against, 734 of 773 uncovered images came back to one
registry credential. A percentage invites resignation; a named cause is a job.

Also from the API: `dimensions["cluster"]`, the image platform, and the digest the
assessment read — so a result is pinned to an image rather than a mutable tag. The
digest is taken only from a completed assessment.

Per-CVE detail (`fix_available` / `fixed_version`) is **not** in this mode yet, so
[`--vuln-source trivy`](scanning.md) is still what populates `vulns`. Endpoint
notes: [design/rapid7-api.md](design/rapid7-api.md).
