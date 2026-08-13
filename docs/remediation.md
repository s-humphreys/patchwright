# Remediation

Knowing a CVE has a fix is half the answer; the other half is whether you can ship
it given how the workload is deployed. `--remediation` composes ordered upgrade
sources, deployment-aware first.

1. **Flux Helm chart** (needs `--live-source kube`) — reads `HelmRelease`s,
   resolves each chart's repository, checks the index for a newer chart version.
2. **Registry image tag** — for images on a strict-semver tag, checks the registry
   for a newer tag. Auth via the docker/cloud keychain.

```sh
# charts and image tags
patchwright assess -i export.csv -c config/ \
  --live-source kube --live-option contexts=aks-prod --remediation

# image tags only, no cluster needed
patchwright assess -i export.csv -c config/ --remediation
```

## Actionability

An upgrade is *directly actionable* only if you can apply it at that level. A newer
image tag for a workload controlled by a Helm chart or an operator is reported as
available but not actionable — bumping the tag would be reverted. The
`upgrade_available` rule variable is true only for actionable upgrades; JSON carries
`available`, `actionable`, `managed`, `resolved` and `source`.

## Columns

`UPGRADE`:

| Shown | Meaning |
|---|---|
| `current->latest` | a newer version applicable directly |
| `chart current->latest` | a newer chart version, not the image tag |
| `current->latest (helm\|operator)` | newer version exists but is controlled elsewhere |
| `-` | on the latest version |
| `?` | detection did not run |

`FIX` condenses that into the remediation path:

| Shown | Meaning |
|---|---|
| `direct` | can move now |
| `managed` | a chart or operator owns the tag; fix it there |
| `none` | already on the latest version |
| `unknown` | detection ran but no version could be resolved |
| `?` | detection did not run |

`none` stays visible: criticals with nowhere to go need a human decision, which is
a different conversation from bumping a tag. `unknown` and `?` are kept apart
because they demand opposite responses. Anything skipping findings without an
upgrade must check `remediation_checked`, or it silently skips images whose
versions merely could not be resolved.

Group headers repeat the split, since "32 actionable" of which 9 are `direct` is a
different day's work from 32 direct bumps:

```
== owner class: platform (32 findings, 32 actionable: 9 direct, 20 managed, 3 none) ==
```

Git/OCI source revisions are next:
[design/remediation-availability.md](design/remediation-availability.md).
