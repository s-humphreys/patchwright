import { maxEPSS } from './cells.js';
import { S } from './state.js';
import { current as currentView } from './tabs.js';

// Export what is on screen, not what is in the database.
//
// The point of the button is that somebody has already narrowed the estate to the
// thing they were asked about - one team, known-exploited only, above a threshold -
// and wants that in a spreadsheet or a ticket. An export that ignored the filters
// would hand them the whole estate back and make them do the narrowing twice.
//
// So it exports S.filtered, which is the same set the table is drawn from, in the
// view they are looking at.

/** cell escapes one value for CSV. */
export function cell(v) {
  if (v === null || v === undefined) return "";
  const s = String(v);
  // Quote anything that would otherwise split a field or a row. Doubling the quote
  // is the escape CSV defines; a backslash is not.
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** toCSV renders rows of values with a header line. */
export function toCSV(headers, rows) {
  return [headers, ...rows].map((r) => r.map(cell).join(",")).join("\r\n");
}

/** @type {[string, (f: any) => any][]} */
const FINDING_COLUMNS = [
  ["image", (f) => f.image],
  ["registry", (f) => f.registry],
  ["repository", (f) => f.repository],
  ["tag", (f) => f.tag],
  ["class", (f) => f.owner?.class],
  ["team", (f) => f.owner?.team],
  ["priority", (f) => f.priority],
  ["actionable", (f) => f.actionable],
  ["suppressed", (f) => f.suppressed],
  ["signals", (f) => (f.signals || []).join(" ")],
  ["exposure", (f) => f.exposure],
  ["critical", (f) => f.counts?.critical || 0],
  ["high", (f) => f.counts?.high || 0],
  ["medium", (f) => f.counts?.medium || 0],
  ["low", (f) => f.counts?.low || 0],
  // From the aggregates the API sends, so an export is complete whether or not the
  // per-CVE arrays have been loaded - the queue does not load them.
  ["kev", (f) => (f.known_exploited ?? (f.vulns || []).some((v) => v.kev))],
  ["max_epss", (f) => maxEPSS(f) || ""],
  ["max_epss_percentile", (f) => (f.top_epss_percentile
    ?? (f.vulns || []).reduce((m, v) => Math.max(m, v.epss_percentile || 0), 0)) || ""],
  ["oldest_cve_days", (f) => f.oldest_cve_days],
  ["upgrade_kind", (f) => f.upgrade?.kind],
  ["upgrade_current", (f) => f.upgrade?.current],
  ["upgrade_latest", (f) => f.upgrade?.latest],
  ["upgrade_available", (f) => f.upgrade?.available],
  ["base_clears", (f) => f.base_diff?.clears],
  ["base_total", (f) => f.base_diff?.total],
  ["namespaces", (f) => (f.dimensions?.namespace || []).join(" ")],
  ["accounts", (f) => (f.dimensions?.account || []).join(" ")],
  ["scanned", (f) => f.scanned],
];

/** @type {[string, (g: any) => any][]} */
const CVE_COLUMNS = [
  ["cve", (g) => g.id],
  ["severity", (g) => g.severity],
  ["cvss", (g) => g.cvss || ""],
  ["epss", (g) => g.epss || ""],
  ["epss_percentile", (g) => g.epss_percentile || ""],
  ["risk_score", (g) => g.risk || ""],
  ["kev", (g) => g.kev],
  ["images", (g) => g.images.length],
  ["teams", (g) => [...g.teams].sort().join(" ")],
  ["fixable_images", (g) => g.fixable],
];

/**
 * exportRows builds the file for the view currently on screen.
 *
 * Returns null when there is nothing to write, so the caller can say so rather than
 * handing somebody an empty file that looks like an answer.
 */
export async function exportRows(view, rows) {
  if (!rows || !rows.length) return null;
  if (view === "cves") {
    const { groupByCVE } = await import('./cves.js');
    const { filterState } = await import('./filters.js');
    // Wait for the per-CVE detail rather than exporting without it. The queue does not
    // load it, and an export that quietly wrote a header and no rows would be worse
    // than a pause: the reader would take it as an answer.
    //
    // Judged on the rows being exported rather than on whether the loader has run, so
    // a caller holding findings that already carry their CVEs never waits.
    if (rows.some((f) => f.vulns === undefined)) {
      const { awaitVulns } = await import('./vulns.js');
      if (await awaitVulns() !== "ready") return null;
    }
    const { groups } = groupByCVE(rows, filterState());
    if (!groups.length) return null;
    return {
      name: "patchwright-cves.csv",
      body: toCSV(CVE_COLUMNS.map((c) => c[0]), groups.map((g) => CVE_COLUMNS.map((c) => c[1](g)))),
    };
  }
  return {
    name: "patchwright-findings.csv",
    body: toCSV(FINDING_COLUMNS.map((c) => c[0]), rows.map((f) => FINDING_COLUMNS.map((c) => c[1](f)))),
  };
}

/** download hands the file to the browser. */
function download(name, body) {
  // A BOM so Excel opens UTF-8 correctly. Without it an image reference with any
  // non-ASCII character arrives mojibaked, and the file is mostly opened in Excel.
  const blob = new Blob(["﻿" + body], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/** initCSV wires the export button. */
export function initCSV() {
  const btn = document.querySelector("#exportCsv");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    const file = await exportRows(currentView(), S.filtered);
    if (!file) {
      btn.textContent = "nothing to export";
      setTimeout(() => { btn.textContent = "export CSV"; }, 2000);
      return;
    }
    download(file.name, file.body);
  });
}
