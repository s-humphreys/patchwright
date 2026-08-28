# Design: which package, and whose fix is it

Status: **built.** The provider data that looked like it answered this does not; base
images are scanned instead. What follows is the measurement, and the design it produced.

Measured on the live estate after building it: on an application image with 6,746 CVEs,
6,736 came from the base and every one of them carries a package named by a scanner -
`debian libssl-dev`, fixed in `3.0.16-1~deb12u1`. The 10 the application introduced carry
no package at all, because nothing scanned that layer, and inventing one is the failure
this document exists to record.

## The question

The Fix column shows a version with no subject - `3.3.5-2.azl3`. A reader cannot act
on that without knowing three things:

1. **which package** the version refers to, out of an image's several hundred;
2. **who owns it** - did the base image ship it, or did our Dockerfile install it;
3. **whether the upgrade we are recommending actually fixes it.**

(3) is the one that decides whether the queue is worth working. Today we can say a
newer base tag exists. We cannot say what moving to it buys, so every row asks the
team to do an upgrade of unknown value.

## The provider data does not answer (1), and cannot answer (2)

`POST /v3/cvm/resource/{id}/vulnerabilities` embeds, on every CVE row:

```
vuln_meta.Solutions[].package_name   github.com/Azure/go-ntlmssp
vuln_meta.Solutions[].package_type   gobinary
vuln_meta.Solutions[].fix            0.1.1
```

This reads as per-image package attribution. It is not. It is the CVE's **generic
remediation record** - how you would fix that CVE in whichever ecosystem you met it -
carried along on a row that happens to be image-scoped.

Measured against Trivy on six public images from the estate, chosen across ecosystems
and including digest-pinned ones so image drift is not a factor:

| image | image OS (Trivy) | Solutions entries naming an ecosystem the image does not contain |
|---|---|---|
| `ghcr.io/fluxcd/source-controller` (digest-pinned) | alpine | 34/97 (35%) |
| `natsio/prometheus-nats-exporter:0.14.0` | alpine | 31/165 (19%) |
| `bagetter/bagetter:1.6.5` | alpine | 68/110 (62%) |
| `wiremock/wiremock:3.10.0` | ubuntu | 336/499 (67%) |
| `mongo:8` | ubuntu | 346/483 (72%) |
| `quay.io/kiali/kiali-operator:v2.27.0` | redhat 9.8 | 842/1155 (73%) |
| **total** | | **1,657/2,509 (66%)** |

The clearest case is `kiali-operator`. It is a Red Hat UBI 9.8 image. Its CVE rows name
**688 Debian packages**, 87 Ubuntu and 6 Alpine. Those packages are not in that image
and never were. Each row carries exactly one `package_type`, so this is not a list to be
filtered per row - it is one guess per CVE, right about a third of the time.

**The CVE set itself is excellent**, and that distinction matters: 472 of 473 CVEs on
`kiali-operator` were also found by Trivy. The provider knows precisely which CVEs are
in the image. It just does not record which package carried each one in.

And when the named ecosystem *is* one the image contains, the package name is almost
always right:

| ecosystem | name matches Trivy |
|---|---|
| redhat | 213/213 (100%) |
| node-pkg | 4/4 (100%) |
| gobinary | 399/407 (98%) |
| alpine | 55/57 (97%) |
| python-pkg | 24/27 (89%) |
| ubuntu | 32/51 (63%) |
| dotnet-core | 0/14 (0%) - see below |
| **overall** | **727/773 (94%)** |

The one apparent exception, `dotnet-core` at 0/14, turned out not to be one. It is a
musl/glibc suffix: on an Alpine image Trivy reports
`Microsoft.AspNetCore.App.Runtime.linux-musl-x64` where the provider reports the generic
`linux-x64`. Same package. On the azurelinux ACR base the two agree exactly, so
`dotnet-core` needs suffix normalisation rather than exclusion.

So the data is accurate as a *fact about the CVE* and wrong as a *fact about the image*.
That is the whole problem in one line, and it is why the error was easy to make: every
individual record looks correct.

### What that cost

This was shipped on `fix/kev-column-suffix` as `91ab924`, claiming "a named package for
130,171 of 130,171 CVE rows", with a `base`/`app`/`either` origin badge inferred from
`package_type`. Coverage was real; correctness was not, and the origin badge inherited
the same 66% error while presenting it as an answer. That commit has been reverted. It
was never merged or released.

The check that would have caught it is the one that eventually did: ask a *second*
source about the same image and see whether the two describe the same thing. Counting
non-empty fields only ever proves the field is populated.

## Design: differential base scanning

Certainty about (2) and (3) does not require layer attribution. It requires scanning the
base image, and it falls out of set arithmetic over three scans:

| scan | source | tells us |
|---|---|---|
| the app image | provider (as today) | the full CVE set |
| **its current base tag** | Trivy | everything here is the base's - certain |
| **the candidate base tag** | Trivy | everything that disappears is fixed by the upgrade |

Three verdicts per CVE, none of them inferred:

- present in the current base → **the base image's**, not the team's;
- in the app image, absent from its base → **the Dockerfile installed it**, the team owns it;
- absent from the candidate tag → **this upgrade fixes it**.

The third yields the sentence the queue is missing: *upgrading to `node:24-alpine` clears
47 of these 61, and leaves 14 to patch yourself.*

It also repairs (1) for free. The base scan establishes the image's real ecosystem, and
filtering the provider's `Solutions` to that ecosystem recovers the 94% accuracy measured
above, for the app image, without scanning the app image.

### Why the cost stays small

Trivy scans **base tags only** - on the order of 30-50 distinct tags across the estate,
plus one per candidate upgrade target - not the ~4,300 app images. The cost is fixed in
the number of base images and does not grow with the estate, and results cache per tag.
The provider keeps doing what it is good at: knowing which CVEs are in which image.

The enricher already exists (`pkg/enrich/trivy`), with DB pre-download, retry and the
concurrent-cache problem solved. This is a new scan target, not a new integration.

### Where it stops, and what must be said on the page

- **Only where the base image is known**, which comes from the upgrade rules. Elsewhere
  there is no base to diff against and no verdict.
- **`FROM scratch` and multi-stage builds** that copy binaries out of a builder have no
  meaningful base, so those stay unattributed.
- **Distroless and self-contained .NET** publish the app and its runtime into one layer,
  so those stay unattributed.
- A guess labelled as a guess is useful. A guess labelled as certainty is what `91ab924`
  did. Where the differential has not run, the page must say so rather than fall back to
  an inference that looks identical.

## Reproducing the measurement

`docs/design/probe/` is not committed; the measurement above is six Trivy scans against
six provider fetches, compared on (CVE, package name, ecosystem). Re-run it before
trusting the percentages against a changed estate - particularly the per-ecosystem table,
which is drawn from small samples for `dotnet-core`, `node-pkg` and `python-pkg`.
