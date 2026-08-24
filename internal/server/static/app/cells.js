import { KIND_BADGES, MANAGED_BADGES, SIGNAL_BADGES, badge } from './badges.js';
import { S } from './state.js';
import { UNKNOWN, esc } from './util.js';

export function fixPath(f) {
  const u = f.upgrade;
  if (!u) return f.remediation_checked ? "unknown" : "?";
  if (!u.resolved) return "unknown";
  if (!u.available) return "none";
  return u.actionable ? "direct" : "managed";
}

// One glyph per kind of change. Helm's wheel for a chart, layers for a base image,
// a cog for a controller that owns the version, a hexagon for a plain image tag.

export function upgradeCell(f) {
  const u = f.upgrade;
  if (!u || !u.resolved || !u.available) return esc(upgradeText(f));
  // When something else owns the version, that badge leads: "who applies this" is
  // the more useful answer than "what did we compare", and an image badge in front
  // of a chart-owned upgrade reads as though the tag were the place to change it.
  const parts = [];
  if (!u.actionable) {
    parts.push(badge(MANAGED_BADGES[(u.managed || "").toLowerCase()], u.managed || "managed"));
  }
  parts.push(badge(KIND_BADGES[u.kind], u.kind));
  let detail = `${u.current} → ${u.latest}`;
  if (u.kind === "base") {
    detail = u.comparison === "digest" && u.source
      ? `${u.source} moved ${u.current} → ${u.latest}`
      : `${u.name} ${u.current} → ${u.latest}`;
  }
  parts.push(esc(detail));
  // Name the thing that owns it where we know it: "helm" says the tag is the wrong
  // place to look, "flux-operator-0.33.0" says where to look instead.
  if (!u.actionable && (u.manager || u.source)) {
    parts.push(`<span class="ticket-status">${esc(u.manager || u.source)}</span>`);
  }
  return parts.join(" ");
}

export function upgradeText(f) {
  const u = f.upgrade;
  if (!u || !u.resolved) return "?";
  if (!u.available) return "-";
  let s = `${u.current} → ${u.latest}`;
  if (u.kind === "chart") s = "chart " + s;
  // Named for a base upgrade: a bare version range on a first-party image reads as
  // the application's own version moving, which is the confusion this exists to
  // remove. What moved is the base, and which base is what the rebuild points at.
  if (u.kind === "base") {
    // A digest comparison names the tag: two opaque hashes say nothing, whereas
    // "…/dotnet/aspnet:10.0-alpine moved" points at the line in the Dockerfile.
    s = u.comparison === "digest" && u.source
      ? `base ${u.source} moved ${u.current} → ${u.latest}`
      : `base ${u.name} ${u.current} → ${u.latest}`;
  }
  if (!u.actionable) s += ` (${u.managed || "managed"})`;
  return s;
}

// upgradeTitle puts the detail behind a hover: the full base reference, or the reason
// a lookup could not answer. "?" with no explanation is the least useful thing a
// column can say, and the reason is usually the actionable part — "this image records
// no base" is a build-system fix somebody can make today.
export function upgradeTitle(f) {
  const u = f.upgrade;
  if (!u) {
    return f.remediation_checked
      ? "No upgrade information for this image."
      : "Upgrade detection did not run (no --remediation).";
  }
  if (!u.resolved) {
    return u.reason
      ? `Could not determine an upgrade: ${u.reason}`
      : "Could not determine an upgrade, and no reason was given.";
  }
  const parts = [];
  if (u.kind === "base") {
    parts.push(`The base image ${u.source || u.name} is what carries these CVEs;` +
      " the fix is to rebuild on a newer one.");
    if (u.comparison === "digest") {
      parts.push("That base is a floating tag, so there is no version to compare:" +
        " the digest it resolves to has changed since this image was built, and a" +
        " rebuild would pick it up.");
    }
  }
  if (!u.available) parts.push("Already on the latest available version.");
  if (u.managed) parts.push(`Version owned by ${u.manager || u.managed}.`);
  // Where the change lands. This used to be a second `title` on the column, which
  // silently overrode this whole function, so the explanation never showed.
  if (u.source) {
    parts.push(`Change in ${u.source}${u.source_path ? ` path ${u.source_path}` : ""}.`);
  }
  return parts.join(" ");
}

// Signals: one column of badges rather than a column per attribute. The table cannot
// grow a column for every fact worth knowing, and a signal that is also a filter and a
// rule input changes the ordering rather than merely being readable.
//
// Every badge is a positive statement. Nothing here means "internal" or "no pull
// request" — absence of a badge asserts nothing, which is why exposure has its own
// three-valued cell in the hover rather than a missing globe standing for "safe".

export function maxRisk(f) {
  let top = 0;
  for (const v of f.vulns || []) {
    if ((v.risk_score || 0) > top) top = v.risk_score;
  }
  return top;
}

// Three states, kept apart: a score, "-" for checked but unscored by this provider,
// and "?" for no exploit source at all.
export function riskCell(f) {
  if (!f.exploit_checked) {
    return '<span class="unknown" title="No exploit source ran, so no risk score was gathered.">?</span>';
  }
  const top = maxRisk(f);
  if (!top) {
    return '<span class="muted" title="The scan provider returned no risk score for this image\u2019s CVEs \u2014 either it does not score them, or it has never seen them.">-</span>';
  }
  return esc(Math.round(top).toString());
}
export const live = (f) => (f.liveness ? (f.liveness.live ? "yes" : "no") : "?");
// cell renders a multi-value dimension compactly: the first value, then how many
// more, with the full list on hover and one click to expand. Joining seven
// namespaces inline pushed every other column off the screen.

export const FIX_RANK = { direct: 4, managed: 3, none: 2, unknown: 1, "?": 0 };
export const FIX_CLASS = { direct: "act-direct", managed: "act-managed", none: "act-none",
                    unknown: "act-unknown", "?": "act-unknown" };
export const fixClass = (f) => FIX_CLASS[fixPath(f)] || "act-unknown";

// Every state that could be read as "fine" gets an explanation, because the ones
// that mean "we do not know" are the ones most easily mistaken for good news.
export const FIX_HELP = {
  direct: "A newer version this image can move to now.",
  managed: "A newer version exists, but a chart or operator owns the tag, so the bump is applied there. Still real work.",
  none: "Already on the latest available version. Nothing to upgrade to, so criticals here need a decision (wait for upstream, rebuild, or accept) rather than a bump.",
  unknown: "Detection ran but could not resolve the available versions, e.g. a private registry whose tags cannot be listed. NOT a statement that it is up to date.",
  "?": "Upgrade detection did not run for this assessment.",
};
export const PRI_RANK = { urgent: 4, high: 3, medium: 2, low: 1 };

export function ticketsFor(f) {
  return S.ticketsByRepo ? S.ticketsByRepo[f.repository] || [] : [];
}

// "-" means no open ticket; "?" means we were not able to look. Conflating them
// would be the same mistake as printing an unscanned image's counts as zero.
export function ticketCell(f) {
  if (!S.ticketsByRepo) return '<span class="unknown" title="Jira is not configured, so ticket state is unknown">?</span>';
  const refs = ticketsFor(f);
  if (!refs.length) return "-";
  return refs.map((t) => {
    const title = esc(t.summary || t.status);
    const key = t.url
      ? `<a href="${esc(t.url)}" target="_blank" rel="noreferrer" title="${title}">${esc(t.key)}</a>`
      : `<span title="${title}">${esc(t.key)}</span>`;
    // "indeterminate" is Jira's category for in-flight work. Status NAMES are
    // per-project ("NEEDS REFINEMENT"), so the category is what can be relied on
    // to say whether anyone has actually picked it up.
    const cls = t.category === "indeterminate" ? "ticket-active" : "ticket-status";
    const status = t.status ? ` <span class="${cls}">${esc(t.status.toLowerCase())}</span>` : "";
    return key + status;
  }).join(", ");
}

// Sort so findings with a ticket group together, then by key.
export function ticketSort(f) {
  const refs = ticketsFor(f);
  return refs.length ? refs[0].key : "";
}

export const isScanned = (f) => f.scanned || (f.vulns || []).length > 0;
export const fixcrit = (f) => (isScanned(f) ? f.fixable_critical ?? 0 : "-");
export const maxEPSS = (f) => (f.vulns || []).reduce((m, v) => Math.max(m, v.epss || 0), 0);
export const priorityText = (f) => (f.suppressed ? "supp" : f.priority || "-");
export const priorityClass = (f) => {
  const p = priorityText(f);
  return PRI_RANK[p] ? p : "unknown";
};

// One sort state per table. Null means the server's own order, which is already
// the queue order someone works top-down, so it stays the default.
export const sortState = { findings: null };


export const SEVERITIES = ["critical", "high", "medium", "low"];
export const SEVERITY_LABELS = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW" };

// cveTotal only counts the severities we name, so an odd bucket from some future
// provider cannot inflate a total whose breakdown does not account for it.
export function cveTotal(r) {
  return SEVERITIES.reduce((n, sev) => n + (r.cves?.[sev] || 0), 0);
}

// cveCell renders a count, or "?" when nothing in the row was assessed. Zero
// CVEs and no CVE data look identical otherwise, and on a real estate the
// second is far more common than the first.
export function cveCell(r, n) {
  if (!r.cvesFrom) {
    return `<span class="unknown" title="Nothing in this row was assessed by the scan provider, so there is no CVE data. Not the same as no CVEs.">?</span>`;
  }
  // The coverage stays in the tooltip rather than beside the number. Rendered
  // inline it read as a fraction of the CVE count, which is a worse error than
  // the one it was guarding against, and the Assessed column already states the
  // same denominator two columns to the left.
  const cov = r.cvesFrom < r.total
    ? ` Drawn from the ${r.cvesFrom} of ${r.total} findings the provider assessed, so it is a floor, not a total.`
    : "";
  return `<span title="Provider counts across this row.${cov}">${n.toLocaleString()}</span>`;
}

// cveColumns is the CVEs column, or the per-severity split when expanded. The
// header carries the toggle so it reads as one column that opens.
export function cveColumns() {
  if (!S.severityExpanded) {
    return [{ label: "CVEs", num: true, expandSeverity: true,
      get: (r) => cveCell(r, cveTotal(r)),
      help: "Total CVEs the scan provider counted across this row, from provider-assessed findings only. Click to split by severity. \"?\" means nothing here was assessed." }];
  }
  return SEVERITIES.map((sev, i) => ({
    label: SEVERITY_LABELS[sev], num: true, expandSeverity: i === 0,
    cls: () => `sev-${sev}`,
    get: (r) => cveCell(r, r.cves?.[sev] || 0),
    help: `${sev[0].toUpperCase()}${sev.slice(1)} CVEs the provider counted, from provider-assessed findings only. Click to collapse back to a total.`,
  }));
}

// The five queue cells. Each answers one question and defers the rest to the detail
// panel, so the table can be read across rather than studied.

// urgencyCell: the verdict, plus what makes it urgent. A KEV-listed or internet-facing
// finding reads differently from a quiet critical, and that difference belongs next to
// the verdict rather than eight columns away.
export function urgencyCell(f) {
  const marks = (f.signals || [])
    .filter((s) => s === "exposed" || s === "kev")
    .map((s) => badge(SIGNAL_BADGES[s], s))
    .join(" ");
  return `${priorityText(f)}${marks ? ` ${marks}` : ""}`;
}

// severityCell: criticals and highs, the two that drive decisions, as "3C/10H".
// "?" when the provider never assessed the image — absent data, not a clean result.
export function severityCell(f) {
  if (!f.provider_assessed) {
    return '<span class="unknown" title="The scan provider never assessed this image; its counts are absent, not zero.">?</span>';
  }
  const c = f.counts?.critical ?? 0, h = f.counts?.high ?? 0;
  if (!c && !h) return '<span class="muted">0</span>';
  const parts = [];
  if (c) parts.push(`<span class="urgent">${c}C</span>`);
  if (h) parts.push(`<span class="high">${h}H</span>`);
  return parts.join("/");
}

// sourceCell: what it is and whose it is, in one cell over two lines. Team and
// namespace were columns of their own; they are context for the image rather than
// things anybody scans down.
export function sourceCell(f) {
  const team = f.owner?.team
    ? esc(f.owner.team)
    : '<span class="unknown" title="No ownership rule matched this workload, usually a missing namespace label.">unattributed</span>';
  const ns = (f.dimensions?.namespace || []);
  const where = ns.length === 0 ? "" : ns.length === 1 ? esc(ns[0]) : `${esc(ns[0])} +${ns.length - 1}`;
  return `<code>${esc(f.image)}</code>` +
    `<div class="sub">${team}${where ? ` · ${where}` : ""}</div>`;
}

// fixCell: the fix path and the move itself. "none", "unknown" and "?" stay distinct —
// already latest, could not resolve, and never looked are three different answers.
export function fixCell(f) {
  const path = fixPath(f);
  if (path === "?" || path === "unknown" || path === "none") {
    return `<span class="${FIX_CLASS[path] || "act-unknown"}" title="${esc(FIX_HELP[path] || "")}">${esc(path)}</span>`;
  }
  return upgradeCell(f);
}

// actionCell: is anything already happening. A pull request that applies the upgrade,
// or an open ticket. Both, when both.
export function actionCell(f) {
  const parts = [];
  if (f.in_flight) {
    const p = f.in_flight;
    const label = `pr ${p.open_days}d`;
    const cls = p.stale ? "badge-stale" : p.exact ? "badge-inflight" : "badge-other";
    const why = `${p.title} — open ${p.open_days}d in ${p.repository}.` +
      (p.exact ? "" : " Bumps the same dependency to a different version, so it may not be this fix.") +
      (p.stale ? " Open past the staleness threshold: the fix exists and nobody has merged it." : "");
    parts.push(p.url
      ? `<a class="badge ${cls}" href="${esc(p.url)}" target="_blank" rel="noreferrer" title="${esc(why)}"><span class="g" aria-hidden="true">⇄</span>${esc(label)}</a>`
      : `<span class="badge ${cls}" title="${esc(why)}">${esc(label)}</span>`);
  }
  const tickets = ticketsFor(f);
  if (tickets.length) parts.push(ticketCell(f));
  if (parts.length) return parts.join(" ");
  // Nothing happening. Which "nothing" it is matters: Jira unconfigured and in-flight
  // detection not run are both "we did not look", and must not read as "nobody has
  // started".
  if (!S.ticketsByRepo && !f.in_flight_checked) {
    return '<span class="unknown" title="Neither the tracker nor pull requests were checked, so it is not known whether anything is happening.">?</span>';
  }
  if (f.in_flight_reason) {
    return `<span class="act-unknown" title="${esc(f.in_flight_reason)}">unmatchable</span>`;
  }
  if (!S.ticketsByRepo) {
    return '<span class="unknown" title="Jira is not configured, so ticket state is unknown. No open pull request applies this upgrade.">no pr, ticket ?</span>';
  }
  if (!f.in_flight_checked) {
    return '<span class="unknown" title="In-flight detection did not run, so it is not known whether a pull request exists. No open ticket.">no ticket, pr ?</span>';
  }
  return '<span class="muted" title="No open pull request and no open ticket.">-</span>';
}

// Ranks what is happening: a stale pull request first (somebody has to unblock it),
// then an open one, then a ticket, then nothing, with "we did not look" at the bottom.
export function actionSort(f) {
  if (f.in_flight) return f.in_flight.stale ? 5 : f.in_flight.exact ? 4 : 3;
  if (ticketsFor(f).length) return 2;
  if (!S.ticketsByRepo || !f.in_flight_checked) return UNKNOWN;
  return 1;
}
