import { esc } from './util.js';

// Charts as inline SVG, hand-rolled.
//
// A charting library was the obvious choice and was considered. Three things
// argued against it here: the page ships as plain ES modules from a Go binary
// with no build step, so a library means vendoring a minified blob into the
// repository; that blob is third-party code shipped inside a tool whose whole
// purpose is telling people about third-party code they are shipping; and what
// these charts need is bars and a heat strip, which is a few dozen lines.
//
// If richer interaction is ever wanted - zoom, tooltips, time series - swap this
// module for uPlot or Chart.js. Everything else on the page talks to the two
// functions below and nothing else, so that swap is local to this file.

/** clamp keeps a bar inside its track when data is unexpected. */
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

/**
 * barChart renders a horizontal bar per row.
 *
 * Horizontal rather than vertical because the labels are team names, and team
 * names rotated 45 degrees is the single most common way a chart like this
 * becomes unreadable.
 *
 * @param {{label: string, value: number, title?: string, cls?: string}[]} rows
 * @param {{max?: number, unit?: string, empty?: string}} [opts]
 */
export function barChart(rows, opts = {}) {
  const data = (rows || []).filter((r) => r && Number.isFinite(r.value));
  if (!data.length) {
    return `<p class="muted">${esc(opts.empty || "Nothing to chart yet.")}</p>`;
  }
  const max = opts.max ?? Math.max(...data.map((r) => r.value), 1);
  const unit = opts.unit || "";
  const rowH = 22;
  const height = data.length * rowH;

  const bars = data.map((r, i) => {
    const w = max > 0 ? clamp((r.value / max) * 100, 0, 100) : 0;
    const y = i * rowH;
    return `<g>
      <title>${esc(r.title || `${r.label}: ${r.value}${unit}`)}</title>
      <rect class="chart-track" x="0" y="${y + 4}" width="100%" height="${rowH - 8}" rx="2"></rect>
      <rect class="chart-bar ${esc(r.cls || "")}" x="0" y="${y + 4}"
        width="${w}%" height="${rowH - 8}" rx="2"></rect>
      <text class="chart-label" x="6" y="${y + rowH / 2 + 4}">${esc(r.label)}</text>
      <text class="chart-value" x="100%" y="${y + rowH / 2 + 4}" text-anchor="end"
        dx="-6">${esc(String(r.value))}${esc(unit)}</text>
    </g>`;
  }).join("");

  return `<svg class="chart" viewBox="0 0 100 ${height}" preserveAspectRatio="none"
    height="${height}" role="img" width="100%">${bars}</svg>`;
}

/**
 * stackedBar renders one bar split into segments, for a composition that adds up
 * to a whole: age bands, fix paths.
 *
 * A segment with a zero value is dropped rather than rendered at zero width,
 * which would put an invisible node in the tab order and an empty tooltip target
 * on the page.
 *
 * @param {{label: string, value: number, cls: string}[]} segments
 */
export function stackedBar(segments, opts = {}) {
  const data = (segments || []).filter((s) => s && s.value > 0);
  const total = data.reduce((n, s) => n + s.value, 0);
  if (!total) {
    return `<p class="muted">${esc(opts.empty || "Nothing to chart yet.")}</p>`;
  }
  let x = 0;
  const parts = data.map((s) => {
    const w = (s.value / total) * 100;
    const seg = `<g><title>${esc(`${s.label}: ${s.value} (${Math.round(w)}%)`)}</title>
      <rect class="chart-seg ${esc(s.cls)}" x="${x}" y="0" width="${w}" height="14"></rect></g>`;
    x += w;
    return seg;
  }).join("");
  const key = data.map((s) =>
    `<span class="chart-key"><i class="chart-swatch ${esc(s.cls)}"></i>${esc(s.label)} ${s.value}</span>`
  ).join(" ");
  return `<svg class="chart" viewBox="0 0 100 14" preserveAspectRatio="none" height="14"
    width="100%" role="img">${parts}</svg><div class="chart-legend">${key}</div>`;
}
