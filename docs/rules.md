# Writing rules

YAML with [CEL](https://github.com/google/cel-go) expressions. Ownership rules match
per workload; policy rules match per finding (one image, one owner, aggregated across
its workloads). First match wins; suppression beats actionability.

[`config/`](../config/) is a documented, editable starting point.

```yaml
# ownership.yaml
owners:
  - name: cloud-provider-managed-images
    match: "image.registry in ['mcr.microsoft.com', 'registry.k8s.io']"
    class: cloud-provider
    team: aks
  - name: platform-system-namespaces
    match: "dimensions['namespace'] in ['kube-system', 'flux-system', 'cert-manager']"
    class: platform
    team: platform-engineering
  - name: engineering-by-label          # preferred, needs live labels
    match: "'team' in labels"
    class: engineering
    teamFrom: "labels['team']"
```

```yaml
# policy.yaml
suppress:
  - name: cloud-provider-managed
    when: "owner['class'] == 'cloud-provider'"
actionable:
  - name: exploited-fixable-critical
    when: "vulns.exists(v, v.severity == 'critical' && v.fix_available && (v.kev || v.epss > 0.5))"
    priority: urgent
  - name: production-critical
    when: "counts['critical'] > 0 && dimensions['account'].exists(a, a.startsWith('Production'))"
    priority: high
  - name: any-critical
    when: "counts['critical'] > 0"
    priority: low
```

`priority` is free-form, but only `urgent` > `high` > `medium` > `low` are ranked for
report ordering; any other label sorts after all of them. Add a tier to
`model.PriorityRank` rather than inventing one in config alone.

## Variables

**Ownership**, per occurrence: `image` `{registry, repository, tag, digest, ref}`,
`dimensions` `map<string,string>`, `labels` `map<string,string>`, `counts`
`map<string,int>` (standard severities always present), `resource` `{id, type, name}`.

**Policy**, per finding: `image`, `counts`, `risk`, `owner` `{class, team}`,
`dimensions` `map<string,list<string>>` (union across workloads), `labels`
`map<string,list<string>>`, `vulns` list of
`{id, severity, cvss, fix_available, fixed_version, epss, kev}`, plus `reconciled`,
`live`, `upgrade_available`, `remediation_checked`.

## What "actionable" means

A finding is actionable because it matched an `actionable` rule and no `suppress`
rule — over the data patchwright has. Without a vuln source that is severity counts,
dimensions, ownership and liveness; there is no implicit registry or CVE lookup. Add
[`--vuln-source`](scanning.md) to gate on a fix actually existing.
