import { SIGNAL_BADGES, badge } from './badges.js';
import { epssPercent, fixPath } from './cells.js';
import { S } from './state.js';
import { renderTable } from './table.js';
import { $, UNKNOWN, esc } from './util.js';

// The CVE view: the same data read the other way round.
//
// The queue answers "what should this team do about this image". Security asks the
// other question — "how far does this CVE reach, and what would fixing it cover" —
// and answering it from the queue means reading 500 rows and keeping a tally.
//
// Aggregated in the browser from the findings already loaded rather than added to the
// API: it is the same data, and a second endpoint would be a second thing that can
// disagree with the first.

/**
 * A CVE across the estate.
 * @typedef {{
 *   id: string, severity: string, cvss: number, epss: number, epss_percentile: number,
 *   risk: number, kev: boolean,
 *   fixable: number, images: {image: string, team: string, fixed: string, fix: string}[],
 *   teams: Set<string>,
 * }} CVEGroup
 */

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

// CVE_SIGNALS are the signals that describe a CVE rather than the finding carrying
// it. Everything else - exposed, in-flight, unassessed, end-of-life - is a property
// of the image or its deployment, and filtering individual CVEs by those would be
// meaningless.
const CVE_SIGNALS = {
  kev: (v) => !!v.kev,
};

/** cveMatches applies the CVE-level part of the filter state to one vulnerability. */
export function cveMatches(v, state) {
  const signal = state && state.signal;
  const pred = signal && CVE_SIGNALS[signal];
  return pred ? pred(v) : true;
}

/**
 * groupByCVE inverts findings into CVEs. Only scanned findings carry per-CVE detail,
 * so this reports what it aggregated over — a CVE list built from a third of the
 * estate is not the estate.
 *
 * `state` is the filter bar. Filtering the FINDINGS is not enough here: picking the
 * kev signal narrowed the queue to findings carrying a known-exploited CVE and then
 * listed every CVE on them, most of which are not known-exploited. The reader asked
 * for KEV and got 9,457 rows. Signals that describe a CVE are applied to the CVEs
 * as well; the rest describe a finding and are already handled upstream.
 * @returns {{groups: CVEGroup[], scanned: number, total: number}}
 */
export function groupByCVE(findings, state) {
  /** @type {Map<string, CVEGroup>} */
  const byID = new Map();
  let scanned = 0;
  for (const f of findings) {
    if (!f.scanned) continue;
    scanned++;
    for (const v of f.vulns || []) {
      if (!cveMatches(v, state)) continue;
      let g = byID.get(v.id);
      if (!g) {
        g = { id: v.id, severity: v.severity || "unknown", cvss: 0, epss: 0, epss_percentile: 0, risk: 0,
              kev: false, fixable: 0, images: [], teams: new Set() };
        byID.set(v.id, g);
      }
      // The worst of anything reported: a CVE is as urgent as its worst appearance,
      // and severity can differ between images by distro package.
      if ((SEVERITY_RANK[v.severity] || 0) > (SEVERITY_RANK[g.severity] || 0)) g.severity = v.severity;
      g.cvss = Math.max(g.cvss, v.cvss || 0);
      g.epss = Math.max(g.epss, v.epss || 0);
      // The same CVE carries the same percentile wherever it appears, so the max is
      // just "the one we have" rather than an aggregation of different values.
      g.epss_percentile = Math.max(g.epss_percentile || 0, v.epss_percentile || 0);
      g.risk = Math.max(g.risk, v.risk_score || 0);
      g.kev = g.kev || !!v.kev;
      if (v.fix_available) g.fixable++;
      g.images.push({
        image: f.image,
        team: f.owner?.team || "",
        fixed: v.fixed_version || "",
        fix: fixPath(f),
      });
      if (f.owner?.team) g.teams.add(f.owner.team);
    }
  }
  return { groups: [...byID.values()], scanned, total: findings.length };
}

/** Ranked by what should be dealt with first, not alphabetically. */
function urgency(g) {
  return (g.kev ? 1e9 : 0) + (SEVERITY_RANK[g.severity] || 0) * 1e6 +
    Math.round(g.epss * 1000) * 100 + g.images.length;
}

export const CVE_COLUMNS = [
  { label: "CVE", get: (g) => `<code>${esc(g.id)}</code>${g.kev ? " " + badge(SIGNAL_BADGES.kev, "kev") : ""}`,
    sort: (g) => urgency(g),
    help: "The CVE, ranked by what to deal with first: KEV-listed, then severity, then exploitation pressure, then how many images carry it. Select a row for every affected image." },
  { label: "Severity", get: (g) => `<span class="${esc(g.severity)}">${esc(g.severity)}</span>`,
    sort: (g) => SEVERITY_RANK[g.severity] || 0,
    help: "The worst severity reported for this CVE across the images carrying it. The same CVE can be rated differently by distro." },
  { label: "CVSS", num: true, get: (g) => (g.cvss ? g.cvss.toFixed(1) : "-"),
    sort: (g) => g.cvss || UNKNOWN, help: "Highest CVSS reported for this CVE." },
  { label: "EPSS", num: true, get: (g) => (g.epss ? epssPercent(g.epss) : "-"),
    sort: (g) => g.epss || UNKNOWN,
    help: "Probability of exploitation in the next 30 days. \"-\" means no exploit source ran, not a low score." },
  { label: "Images", num: true, get: (g) => String(g.images.length),
    sort: (g) => g.images.length,
    help: "How many images carry this CVE. This is the scope of fixing it." },
  { label: "Teams", num: true, get: (g) => String(g.teams.size || 0),
    sort: (g) => g.teams.size,
    help: "How many owning teams would be involved. A CVE in one base image can span every team at once." },
  { label: "Fixable", get: (g) => fixableCell(g), sort: (g) => g.fixable,
    help: "How many of those images have a fix available for this CVE. \"none\" means no upgrade published yet — waiting rather than neglected." },
];

function fixableCell(g) {
  if (!g.fixable) {
    return '<span class="muted" title="No image carrying this CVE has a fix available: there is nothing to upgrade to yet.">none</span>';
  }
  const all = g.fixable === g.images.length;
  return `<span class="${all ? "act-direct" : "act-managed"}" title="${
    all ? "Every affected image has a fix available." : "Some affected images have no fix available yet."
  }">${g.fixable}/${g.images.length}</span>`;
}

/** renderCVEs draws the CVE table, or says why it is empty. */
/**
 * renderCVEs draws the CVE view and returns what it drew, so the caller can say how much
 * of the estate this is. It renders whatever findings it is given: the filtering decision
 * belongs to the page, not to this view.
 */
export function renderCVEs(findings, state) {
  const { groups, scanned, total } = groupByCVE(findings, state);
  const note = $("#cveNote");
  if (scanned === 0) {
    // Absolutely not "no CVEs found": nothing was looked at.
    note.innerHTML = `<div class="banner">No image was scanned for per-CVE detail, so this
      view has nothing to aggregate. The queue's severity counts come from the scan
      provider, which reports totals rather than individual CVEs. Add
      <code>--vuln-source trivy</code> (chart: <code>scan.enabled</code>) to populate it.</div>`;
    renderTable("cves", CVE_COLUMNS, []);
    return { groups: [], scanned, total };
  }
  note.textContent = scanned === total
    ? `${groups.length} distinct CVEs across ${scanned} findings.`
    : `${groups.length} distinct CVEs across the ${scanned} of ${total} findings that were scanned. ` +
      `The rest were not scanned, so their CVEs are unknown rather than absent.`;
  renderTable("cves", CVE_COLUMNS, groups);
  return { groups, scanned, total };
}

// cveGroup finds one group again by id, for the detail panel.
//
// Looked up in the FILTERED set, so a panel opened from this view describes the same
// population the table does. Falls back to the whole estate for a deep link that names a
// CVE the current filters exclude - otherwise a shared link would open an empty panel
// and look broken.
export function cveGroup(id) {
  const inView = groupByCVE(S.filtered || []).groups.find((g) => g.id === id);
  return inView || groupByCVE(S.queueRows).groups.find((g) => g.id === id) || null;
}
