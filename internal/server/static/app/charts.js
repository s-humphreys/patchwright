import { esc } from './util.js';

// Charts as HTML and CSS rather than SVG.
//
// The first version drew SVG with preserveAspectRatio="none" so bars could be
// sized in percent. That stretches everything inside the viewBox, text included,
// so every label rendered smeared horizontally. Percentage-width divs give the
// same layout with no coordinate system to distort: text is text, it wraps and
// scales like the rest of the page, and it stays legible at any width.
//
// A charting library was considered and is still the right answer the moment
// this needs zoom, a shared time axis or interaction. What is here is bars and a
// segmented strip. Everything on the page talks to the three functions below, so
// swapping in uPlot or Chart.js stays local to this file.

const pctWidth = (v, max) => (max > 0 ? Math.max(0.5, Math.min(100, (v / max) * 100)) : 0);

/**
 * barChart renders a labelled horizontal bar per row.
 *
 * Horizontal because the labels are names - images, teams, base tags - and names
 * rotated on a vertical axis is the commonest way a chart like this becomes
 * unreadable.
 *
 * @param {{label: string, value: number, display?: string, title?: string, cls?: string, sub?: string}[]} rows
 */
export function barChart(rows, opts = {}) {
  const data = (rows || []).filter((r) => r && Number.isFinite(r.value));
  if (!data.length) {
    return `<p class="muted">${esc(opts.empty || "Nothing to chart yet.")}</p>`;
  }
  const max = opts.max ?? Math.max(...data.map((r) => r.value), 1);
  const items = data.map((r) => `
    <li class="bar-row" title="${esc(r.title || `${r.label}: ${r.value}`)}">
      <span class="bar-name">${esc(r.label)}${
        r.sub ? `<span class="bar-sub">${esc(r.sub)}</span>` : ""
      }</span>
      <span class="bar-track">
        <span class="bar-fill ${esc(r.cls || "")}" style="width:${pctWidth(r.value, max).toFixed(2)}%"></span>
      </span>
      <span class="bar-num">${esc(r.display || String(r.value))}</span>
    </li>`).join("");
  return `<ul class="bar-chart">${items}</ul>`;
}

/**
 * stackedBar renders one bar split into segments, for a composition adding to a
 * whole: age bands, fix paths.
 *
 * Zero-value segments are dropped rather than rendered at zero width, which puts
 * an empty tooltip target on the page and a node in the tab order for nothing.
 */
export function stackedBar(segments, opts = {}) {
  const data = (segments || []).filter((s) => s && s.value > 0);
  const total = data.reduce((n, s) => n + s.value, 0);
  if (!total) {
    return `<p class="muted">${esc(opts.empty || "Nothing to chart yet.")}</p>`;
  }
  const parts = data.map((s) => {
    const w = (s.value / total) * 100;
    return `<span class="seg ${esc(s.cls)}" style="width:${w.toFixed(2)}%"
      title="${esc(`${s.label}: ${s.value} (${Math.round(w)}%)`)}"></span>`;
  }).join("");
  const key = data.map((s) =>
    `<span class="chart-key"><i class="chart-swatch ${esc(s.cls)}"></i>${esc(s.label)} ${s.value}</span>`
  ).join(" ");
  return `<div class="stacked">${parts}</div><div class="chart-legend">${key}</div>`;
}

/**
 * columnChart renders a value per time bucket, oldest on the left.
 *
 * For the one genuine time series available from a single assessment: when the
 * CVEs still sitting in the queue first appeared. A column per month reads as a
 * shape - a backlog that arrived in one bad quarter looks nothing like one
 * accumulating steadily, and they call for different responses.
 *
 * @param {{label: string, value: number, title?: string, cls?: string}[]} cols
 */
export function columnChart(cols, opts = {}) {
  const data = (cols || []).filter((c) => c && Number.isFinite(c.value));
  if (!data.length) {
    return `<p class="muted">${esc(opts.empty || "No dated findings, so there is no history to plot.")}</p>`;
  }
  const max = Math.max(...data.map((c) => c.value), 1);
  const bars = data.map((c) => `
    <li class="col" title="${esc(c.title || `${c.label}: ${c.value}`)}">
      <span class="col-fill ${esc(c.cls || "")}" style="height:${pctWidth(c.value, max).toFixed(2)}%"></span>
      <span class="col-label">${esc(c.label)}</span>
    </li>`).join("");
  return `<ul class="col-chart">${bars}</ul>
    <div class="chart-legend">${esc(opts.caption || "")} peak ${max}</div>`;
}
