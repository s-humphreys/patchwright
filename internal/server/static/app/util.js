// The page deliberately mirrors the CLI's vocabulary. Anything the report shows as
// unknown must show as unknown here too: a dashboard that renders missing data as
// a zero is the failure mode this whole feature exists to prevent.
export const $ = (sel) => document.querySelector(sel);

export function cell(values) {
  const v = values || [];
  if (!v.length) return "-";
  const all = esc(v.join(", "));
  if (v.length === 1) return `<span title="${all}">${esc(v[0])}</span>`;
  return `<span class="more" title="${all}" data-all="${all}"
    onclick="this.textContent=this.dataset.all">${esc(v[0])} +${v.length - 1}</span>`;
}

export const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

export async function get(path) {
  const r = await fetch(path);
  if (!r.ok) {
    // The API explains its refusals ("ticketing is not configured"), and a bare status
    // code throws that away — leaving the page to report a deliberate configuration
    // choice as though it were a fault.
    let detail = "";
    try {
      const body = await r.json();
      detail = body?.error || "";
    } catch {
      // Not JSON: the status is all there is.
    }
    const err = new Error(detail || `${path}: ${r.status}`);
    /** @type {any} */ (err).status = r.status;
    /** @type {any} */ (err).detail = detail;
    throw err;
  }
  return r.json();
}

// hasAssessment distinguishes "no assessment yet" from a real, empty result. The
// API answers 200 with zeros before the first run completes, and a zero-value
// timestamp is the only way to tell them apart.
export function hasAssessment(a) {
  return !!(a && a.generated_at && !a.generated_at.startsWith("0001-01-01"));
}

// elapsed renders how long the in-flight assessment has been running. A full run
// crosses every cluster and scans every image, so minutes of apparent silence are
// normal and worth distinguishing from a hang.
export function elapsed(a) {
  if (!a || !a.started_at) return "";
  const secs = Math.max(0, Math.round((Date.now() - new Date(a.started_at).getTime()) / 1000));
  return secs < 60 ? ` (${secs}s)` : ` (${Math.floor(secs / 60)}m ${secs % 60}s)`;
}

export const UNKNOWN = Number.NEGATIVE_INFINITY;

export function pct(n, of) {
  if (!of) return '<span class="pct">-</span>';
  return `<span class="pct">${Math.round((n / of) * 100)}%</span>`;
}

// countPct puts the number first and the share second, so a row can be read either
// as "how many" or "how much of it", and a small absolute number cannot hide behind
// a large percentage.
export function countPct(n, of) {
  return `${n} ${pct(n, of)}`;
}

// Breakdown: one row per owner class, with its teams indented beneath.
//
// Every column is a share of something stated, because the raw counts alone
// mislead in both directions here: a team with two actionable findings out of six
// looks quiet next to one with twenty out of seven hundred, and a team with 100%
// coverage of four images is not in better shape than one with 40% of two hundred.
// S.severityExpanded splits the CVEs column into one column per severity. A column
// toggle rather than a per-row one: severity is a property of every row, so
// expanding it row by row would mean the same question asked repeatedly, and a
// second kind of expansion inside rows that already expand into teams.
