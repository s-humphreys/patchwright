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
  if (!u || !u.resolved) return esc(upgradeText(f));
  if (!u.available) {
    // Not available AND end of life is a statement, not a blank: badge it so the row
    // reads as urgent-with-no-bump rather than as nothing to do.
    return endOfLifeStatus(u)
      ? `<span class="badge badge-eol" title="${esc(supportWhy(u))}">eol</span> ${esc(upgradeText(f))}`
      : esc(upgradeText(f));
  }
  // When something else owns the version, that badge leads: "who applies this" is
  // the more useful answer than "what did we compare", and an image badge in front
  // of a chart-owned upgrade reads as though the tag were the place to change it.
  const parts = [];
  if (!u.actionable) {
    parts.push(badge(MANAGED_BADGES[(u.managed || "").toLowerCase()], u.managed || "managed"));
  }
  parts.push(badge(KIND_BADGES[u.kind], u.kind));
  // An out-of-track move crosses a maintained-line boundary, which is a migration
  // somebody plans rather than a bump somebody merges. Labelling it as an ordinary
  // upgrade would understate the work and lose the reason it is the only option.
  if (u.out_of_track) {
    parts.push(`<span class="badge badge-eol" title="The current line is no longer maintained, so this move leaves it. A migration, not a version bump.">major</span>`);
  }
  let detail = `${u.current} → ${u.latest}`;
  if (u.kind === "base") {
    detail = u.comparison === "digest" && u.source
      ? `${u.source} moved ${u.current} → ${u.latest}`
      : `${u.name} ${u.current} → ${u.latest}`;
  }
  parts.push(esc(detail));
  // Both moves, when policy recommends the nearer one. A team told to jump a runtime
  // minor it cannot take does nothing at all, and the patch that would have closed
  // the same CVEs goes unmade — so the ticket offers the patch now and names the
  // migration as a separate decision.
  if (u.newest && u.newest !== u.latest) {
    parts.push(`<span class="muted" title="${esc(upgradeStrategyWhy(u))}">newest ${esc(u.newest)}</span>`);
  }
  // Name the thing that owns it where we know it: "helm" says the tag is the wrong
  // place to look, "flux-operator-0.33.0" says where to look instead.
  if (!u.actionable && (u.manager || u.source)) {
    parts.push(`<span class="ticket-status">${esc(u.manager || u.source)}</span>`);
  }
  return parts.join(" ");
}

// endOfLifeStatus returns the support block only when it carries a KNOWN unsupported
// verdict. An unchecked base returns nothing: silence about a line is not a claim that
// it is dead, any more than it is a claim that it is alive.
export function endOfLifeStatus(u) {
  const st = u && u.support;
  if (!st || !st.known || st.supported) return null;
  return st;
}

// supportWhy is the hover: who said so, when the line ends, and what the alternatives
// are. An unattributed claim that somebody's runtime is dead invites an argument; a
// dated one from a named source invites a rebuild.
export function supportWhy(u) {
  const st = endOfLifeStatus(u);
  if (!st) return "";
  const bits = [`${st.product} ${st.cycle} is no longer maintained`];
  if (st.eol) bits.push(`support ended ${st.eol}`);
  if (st.recommended) bits.push(`recommended: ${st.recommended} (maintained, and already long-term supported)`);
  if (st.nearest) bits.push(`smallest supported move: ${st.nearest}`);
  if (st.newest) bits.push(`newest line: ${st.newest}, not recommended yet`);
  if (st.source) bits.push(`source: ${st.source}`);
  return bits.join(". ") + ".";
}

export function upgradeText(f) {
  const u = f.upgrade;
  if (!u || !u.resolved) return "?";
  // A dead line with nowhere to go is the worst cell in the table to render as "-".
  // "-" means "you are current"; here it means "nothing will ever fix this", and the
  // two must not look the same. This is the whole reason support status is carried.
  if (!u.available && endOfLifeStatus(u)) {
    const st = u.support;
    return st.recommended
      ? `end of life: move to ${st.product} ${st.recommended}`
      : `end of life: no maintained line found`;
  }
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

// The whole-image worst of a per-CVE score.
//
// Read from the aggregate the API sends alongside the CVEs, falling back to the CVEs
// themselves. The queue is loaded WITHOUT them - they are 97% of the payload - so a
// column that could only compute this by walking vulns would render "-" for the whole
// estate until somebody opened a panel.
export function maxRisk(f) {
  if (f.top_risk_score != null) return f.top_risk_score;
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

export const isScanned = (f) => f.scanned || (f.vuln_count || 0) > 0 || (f.vulns || []).length > 0;
export const fixcrit = (f) => (isScanned(f) ? f.fixable_critical ?? 0 : "-");
export const maxEPSS = (f) => (f.top_epss != null
  ? f.top_epss
  : (f.vulns || []).reduce((m, v) => Math.max(m, v.epss || 0), 0));

// epssPercent renders an exploit-prediction score as what it actually is: a probability.
//
// EPSS is published as 0-1, and shown that way it reads as a rating out of one - "0.61"
// invites being compared to a CVSS of 6.1, which is a different scale measuring a
// different thing. As a percentage it says the sentence it means: a 61% chance of
// exploitation activity in the next thirty days.
//
// The small end matters more than the large one here, because most scores live there. A
// naive round sends everything below half a percent to "0%", which reads as "no chance"
// on a CVE that has some, so anything non-zero keeps a floor of "<0.1%".
export function epssPercent(v) {
  if (v === null || v === undefined || Number.isNaN(v)) return "-";
  if (v <= 0) return "0%";
  const pct = v * 100;
  if (pct < 0.1) return "<0.1%";
  if (pct < 10) return `${pct.toFixed(1)}%`;
  return `${Math.round(pct)}%`;
}
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
  // The rule that decided it, beneath the verdict. Without this the column is
  // unreadable in the case that matters most: four tags of one image, identical
  // counts, four different verdicts, because each runs in a different environment.
  // The verdict alone looks arbitrary; the rule name says what the difference was.
  return `${priorityText(f)}${marks ? ` ${marks}` : ""}` +
    `<div class="sub">${esc(ruleName(f))}</div>`;
}

// ruleName pulls the rule out of the reason a policy recorded. Reasons read
// `matched actionable rule "production-critical"`, and the quoted part is the half
// worth showing in a cell this narrow.
export function ruleName(f) {
  const reason = (f.reasons || [])[0] || "";
  const quoted = reason.match(/"([^"]+)"/);
  if (quoted) return quoted[1];
  if (reason) return reason;
  return f.suppressed ? "suppressed" : "no rule matched";
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
  const u = f.upgrade;
  // Held back is not "none": there IS a newer version and policy asked for none of
  // it, which somebody may want to revisit.
  if (u && u.held_back) return heldBackCell(u);
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

// upgradeStrategyWhy explains why the recommendation stops short of the newest
// version. A number nobody can explain is a number nobody trusts.
export function upgradeStrategyWhy(u) {
  const parts = [];
  if (u.ceiling) {
    // The rule is named because a scoped rule may apply to this service and not to the
    // one below it, so "held at 3.12" is no longer answerable from the config alone.
    const by = u.rule ? `by rule ${u.rule}` : "by policy";
    parts.push(`Held at ${u.ceiling} ${by}` + (u.ceiling_reason ? `: ${u.ceiling_reason}` : "."));
  } else if (u.strategy === "patch") {
    parts.push("Patch upgrades only for this image: the minor version is the compatibility boundary for a language runtime.");
  } else if (u.strategy === "minor") {
    parts.push("Minor upgrades only for this image.");
  }
  if (u.ceiling_expired) {
    parts.push("That ceiling's end date has passed, so it was NOT applied — the constraint is due a revisit.");
  }
  // A ceiling inside a line nobody maintains is not merely conservative, it is holding
  // this image somewhere no fix will ever arrive. Said plainly, because the two facts
  // are individually unremarkable and together they are the finding: the resolver will
  // not step past the constraint, so a person has to decide to lift it.
  if (u.ceiling && endOfLifeStatus(u)) {
    const st = u.support;
    parts.push(`That line is no longer maintained${st.eol ? ` (${st.product} ${st.cycle} ended ${st.eol})` : ""},` +
      ` so no fix will reach this image while the ceiling stands.` +
      (st.recommended ? ` Moving to ${st.recommended} needs the ceiling lifted first.` : ""));
  }
  parts.push(`The newest available is ${u.newest}, which is a separate decision.`);
  return parts.join(" ");
}

// heldBackCell reports an image with newer versions available and none recommended.
// "none" would say it is up to date, which is a different thing entirely.
export function heldBackCell(u) {
  return `<span class="act-managed" title="${esc(upgradeStrategyWhy(u))}">held at ${esc(u.ceiling || u.strategy || "policy")}</span>`;
}

/**
 * vulnFixCell renders the Fix column: what to upgrade, not just a version.
 *
 * The column used to read "3.3.5-2.azl3" — a version with no subject, which a
 * reader cannot act on without knowing which of an image's several hundred
 * packages it refers to, and could not find out from this page.
 *
 * The package is named only when a scan measured it in the base image. For an
 * application-introduced CVE nothing scanned that layer, so the version stands
 * alone rather than being attached to a guessed package: the provider's own
 * per-CVE package field names an ecosystem the image does not contain 66% of the
 * time, and a confidently wrong package name is worse than none.
 */
export function vulnFixCell(v) {
  const pkgs = v.packages || [];
  if (!pkgs.length) {
    if (!v.fix_available) return '<span class="muted">no fix</span>';
    return `<span class="act-direct">${esc(v.fixed_version || "fix available")}</span>`;
  }
  const first = pkgs[0];
  const more = pkgs.length > 1
    ? ` <span class="sub" title="${esc(pkgs.slice(1).map((p) => p.name).join(", "))}">+${pkgs.length - 1}</span>`
    : "";
  const fix = first.fixed_in
    ? ` → <span class="act-direct">${esc(first.fixed_in)}</span>`
    : ' <span class="muted">no fix</span>';
  return `<span class="pkg-origin" title="Measured in the base image, so this is the base's to fix.">base</span>
    <code>${esc(first.name)}</code>${more}${fix}`;
}
