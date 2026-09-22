import { columnChart, stackedBar } from './charts.js';
import { $, esc } from './util.js';

// Movement by period, from the event log, rendered at the top of the analytics
// page so that page reads as a story: how things are moving, then what to do next.
//
// Two rules shape everything here. Resolved and lapsed are never summed - a lapse
// is the tool losing sight of something, and adding it to remediation would produce
// a number that improves fastest when the scanner breaks. And ticketed resolutions
// are a SUBSET of resolved, never a separate column that could be added to it; the
// difference between the two is work that landed by another route, which is the
// figure the delineation exists to show.
//
// The page also leads with the record's caveats rather than burying them, because
// the first and most misleading thing a chart of this kind can do is show an empty
// month before the record began as a month in which nothing happened.

const SIGNALS = [
  { key: "kev", label: "Known exploited" },
  { key: "epss-high", label: "EPSS above 0.5" },
  { key: "fixable-critical", label: "Fixable critical" },
  { key: "end-of-life", label: "End-of-life base" },
  { key: "exposed", label: "Internet exposed" },
];

/** fmt renders a number with thousands separators, or "-" for nothing. */
function fmt(n) {
  if (n === undefined || n === null || Number.isNaN(n)) return "-";
  return Number(n).toLocaleString("en-GB");
}

/** pct renders a share, or "-" when the denominator is zero. */
function pct(n, d) {
  if (!d) return "-";
  return `${Math.round((n / d) * 100)}%`;
}

/** withMovement keeps the periods in which anything happened, plus the latest. */
function activePeriods(movement) {
  const rows = movement || [];
  return rows.filter((m, i) => i === rows.length - 1 || m.opened || m.resolved || m.lapsed || m.tickets_closed);
}

/** caveatsPanel puts the record's own caveats first, where they cannot be missed. */
function caveatsPanel(h, status) {
  const items = [];
  if (h.first_recorded) {
    items.push(`The record begins <strong>${esc(String(h.first_recorded).slice(0, 10))}</strong>. Periods before that are empty because nothing was watching.`);
  }
  if (status?.retention_days) {
    items.push(`Retention is ${status.retention_days} days, so the lookback can never exceed that.`);
  }
  if (status?.last_error) {
    items.push(`<span class="warn">The store reported an error on its last use: ${esc(status.last_error)}</span>`);
  }
  for (const c of h.caveats || []) items.push(esc(c));
  // Collapsed by default, with the one fact that changes how the charts read kept
  // on the summary line: when the record began.
  const begins = h.first_recorded ? ` · the record begins ${esc(String(h.first_recorded).slice(0, 10))}` : "";
  return `<details class="panel notes history-notes"><summary>Read this first${begins}</summary><ul>${
    items.map((c) => `<li>${c}</li>`).join("")
  }</ul></details>`;
}

/** directionPanel plots the estate's risk at the end of each period. */
function directionPanel(h) {
  const points = h.risk || [];
  if (!points.length) {
    return `<section class="panel"><h3>Direction</h3>
      <p class="muted">No assessment has been recorded in this range.</p></section>`;
  }
  const first = points[0], last = points[points.length - 1];
  const change = first.risk?.sum ? Math.round(((last.risk.sum - first.risk.sum) / first.risk.sum) * 100) : null;
  const verdict = points.length < 2
    ? `<span class="unknown">one period only: a point, not a direction</span>`
    : change === null ? "" : change < -5
      ? `<span class="ok">down ${Math.abs(change)}% since ${esc(first.period)}</span>`
      : change > 5
        ? `<span class="urgent">up ${change}% since ${esc(first.period)}</span>`
        : `flat since ${esc(first.period)}`;

  const cols = points.map((p) => ({
    label: p.period, value: Math.round(p.risk?.sum || 0),
    title: `${p.period}: risk sum ${fmt(Math.round(p.risk?.sum || 0))} across ${p.risk?.items} items, from ${p.assessments} assessment${p.assessments === 1 ? "" : "s"}`,
    cls: "bar-risk",
  }));
  const rows = points.map((p) => `<tr>
      <td>${esc(p.period)}</td><td>${fmt(p.risk?.items)}</td><td>${fmt(Math.round(p.risk?.sum || 0))}</td>
      <td>${fmt(p.risk?.urgent)}</td><td>${fmt(p.risk?.known_exploited)}</td>
      <td>${fmt(p.actionable)} of ${fmt(p.findings)}</td><td class="muted">${p.assessments}</td></tr>`).join("");
  return `<section class="panel"><h3>Direction</h3>
    <div class="dr"><dt>Risk score, sum of open items</dt><dd><strong>${fmt(Math.round(last.risk?.sum || 0))}</strong> ${verdict}</dd></div>
    ${columnChart(cols, { caption: "risk sum at the end of each period;" })}
    <table class="mini"><thead><tr><th>Period</th><th>Items</th><th>Risk sum</th><th>Urgent</th><th>KEV</th><th>Actionable findings</th><th>Runs</th></tr></thead>
    <tbody>${rows}</tbody></table>
    <p class="sub">Each row is the last assessment of its period. A period with one run is a point, not a trend.</p>
  </section>`;
}

/** movementPanel is opened against resolved against lapsed, per period. */
function movementPanel(h) {
  const periods = activePeriods(h.movement);
  if (!periods.length) {
    return `<section class="panel"><h3>Movement</h3><p class="muted">Nothing recorded in this range.</p></section>`;
  }
  const totals = periods.reduce((t, m) => ({
    opened: t.opened + m.opened, resolved: t.resolved + m.resolved, lapsed: t.lapsed + m.lapsed,
  }), { opened: 0, resolved: 0, lapsed: 0 });
  const rows = periods.map((m) => `<tr>
      <td>${esc(m.period)}</td><td>${fmt(m.opened)}</td>
      <td><strong class="ok">${fmt(m.resolved)}</strong></td>
      <td class="muted">${fmt(m.lapsed)}</td><td class="muted">${fmt(m.reassigned)}</td>
      <td>${m.median_days_to_resolve != null ? `${Math.round(m.median_days_to_resolve)}d` : "-"}</td></tr>`).join("");
  const reasons = {};
  for (const m of periods) for (const [k, v] of Object.entries(m.lapse_reasons || {})) reasons[k] = (reasons[k] || 0) + v;
  const reasonRows = Object.entries(reasons).sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<span class="chart-key">${esc(k)} ${v}</span>`).join(" ");
  return `<section class="panel"><h3>Movement</h3>
    <div class="dr"><dt>Across the range</dt>
      <dd>${fmt(totals.opened)} opened · <strong class="ok">${fmt(totals.resolved)}</strong> resolved with evidence · <span class="muted">${fmt(totals.lapsed)} lapsed</span></dd></div>
    ${columnChart(periods.map((m) => ({ label: m.period, value: m.resolved, cls: "bar-win", title: `${m.period}: ${m.resolved} resolved, ${m.lapsed} lapsed, ${m.opened} opened` })),
      { caption: "resolved with evidence per period;", empty: "Nothing has resolved yet." })}
    <table class="mini"><thead><tr><th>Period</th><th>Opened</th><th>Resolved</th><th>Lapsed</th><th>Reassigned</th><th>Median days to resolve</th></tr></thead>
    <tbody>${rows}</tbody></table>
    ${reasonRows ? `<p class="sub">Why lapses could not be called resolutions: ${reasonRows}</p>` : ""}
    <p class="sub">Lapsed is never remediation: it is the record losing sight of an item without evidence its work was done.</p>
  </section>`;
}

/** delineationPanel is the four buckets security asked to see apart. */
function delineationPanel(h) {
  const periods = activePeriods(h.movement);
  if (!periods.length) return "";
  const sum = (k) => periods.reduce((n, m) => n + (m[k] || 0), 0);
  const unticketed = sum("resolved_unticketed"), ticketed = sum("resolved_ticketed");
  const closedOpen = sum("tickets_closed_finding_open"), lapsed = sum("lapsed");
  const byTool = {};
  for (const m of periods) for (const [k, v] of Object.entries(m.tickets_closed_by_tool || {})) byTool[k] = (byTool[k] || 0) + v;
  const strip = stackedBar([
    { label: "resolved, never ticketed", value: unticketed, cls: "age-0" },
    { label: "resolved, ticketed", value: ticketed, cls: "age-1" },
    { label: "ticket closed, finding open", value: closedOpen, cls: "age-3" },
    { label: "lapsed", value: lapsed, cls: "age-4" },
  ], { empty: "Nothing has left the queue yet." });
  const rows = periods.map((m) => `<tr>
      <td>${esc(m.period)}</td><td>${fmt(m.resolved_unticketed)}</td><td>${fmt(m.resolved_ticketed)}</td>
      <td>${fmt(m.tickets_raised)}</td><td>${fmt(m.tickets_closed)}</td>
      <td class="${m.tickets_closed_finding_open ? "warn" : ""}">${fmt(m.tickets_closed_finding_open)}</td>
      <td class="muted">${fmt(m.lapsed)}</td></tr>`).join("");
  const toolRows = Object.entries(byTool).map(([k, v]) => `<span class="chart-key">${esc(k)} ${v}</span>`).join(" ");
  return `<section class="panel"><h3>Total remediation against ticketed work</h3>
    <div class="dr"><dt>Upgrades and patches landed</dt>
      <dd><strong class="ok">${fmt(unticketed + ticketed)}</strong> resolved with evidence, of which <strong>${fmt(ticketed)}</strong> (${pct(ticketed, unticketed + ticketed)}) were ticketed work</dd></div>
    ${strip}
    <table class="mini"><thead><tr><th>Period</th><th>Resolved, unticketed</th><th>Resolved, ticketed</th><th>Tickets raised</th><th>Tickets closed</th><th>Closed, finding open</th><th>Lapsed</th></tr></thead>
    <tbody>${rows}</tbody></table>
    ${toolRows ? `<p class="sub">Tickets patchwright closed itself, by reason: ${toolRows}. The rest were closed by people.</p>` : ""}
    <p class="sub">"Closed, finding open" is a ticket somebody closed while the image still ran. It is neither resolved nor lapsed.</p>
  </section>`;
}

/**
 * splitTable renders opened / resolved per period for one classification, keyed by
 * the item's OPENING state. Rows are the classification's values, columns the
 * periods, so a month-on-month comparison reads across.
 */
function splitTable(title, periods, field, rowsWanted, note) {
  const keys = rowsWanted
    ? rowsWanted.map((r) => r.key)
    : [...new Set(periods.flatMap((m) => Object.keys(m[field] || {})))].sort();
  const labels = Object.fromEntries((rowsWanted || []).map((r) => [r.key, r.label]));
  if (!keys.length) return "";
  const head = periods.map((m) => `<th>${esc(m.period)}</th>`).join("");
  const body = keys.map((k) => {
    const cells = periods.map((m) => {
      const c = (m[field] || {})[k] || { opened: 0, resolved: 0, lapsed: 0, resolved_ticketed: 0 };
      return `<td title="${esc(`${k} ${m.period}: ${c.opened} opened, ${c.resolved} resolved (${c.resolved_ticketed} ticketed), ${c.lapsed} lapsed`)}">
        ${fmt(c.opened)} / <strong class="ok">${fmt(c.resolved)}</strong>${c.lapsed ? ` <span class="muted">/ ${fmt(c.lapsed)}</span>` : ""}</td>`;
    }).join("");
    return `<tr><td>${esc(labels[k] || k)}</td>${cells}</tr>`;
  }).join("");
  return `<section class="panel"><h3>${esc(title)}</h3>
    <table class="mini"><thead><tr><th></th>${head}</tr></thead><tbody>${body}</tbody></table>
    <p class="sub">opened / <span class="ok">resolved</span> / lapsed, classified by how the item looked when the record first saw it. ${esc(note || "")}</p>
  </section>`;
}

/** signalsPanel adds the two movements that are not remediation but matter. */
function signalsPanel(h) {
  const periods = activePeriods(h.movement);
  if (!periods.length) return "";
  const decayed = periods.reduce((n, m) => n + (m.epss_decayed || 0), 0);
  const becameKEV = periods.reduce((n, m) => n + (m.became_known_exploited || 0), 0);
  const table = splitTable("By signal", periods, "by_signal", SIGNALS,
    "KEV is a fact that only grows; EPSS is a forecast, and an item that left the EPSS bucket by score decay still counts under it here.");
  return table.replace("</section>", `
    <div class="dr"><dt>EPSS decayed below 0.5 while open</dt><dd>${fmt(decayed)} <span class="sub">not remediation, not hidden</span></dd></div>
    <div class="dr"><dt>Became known-exploited while open</dt><dd>${fmt(becameKEV)}</dd></div>
  </section>`);
}

/** openPanel is the queue as the record holds it now. */
function openPanel(h) {
  const o = h.open || {};
  const order = ["0-7", "7-30", "30-90", "90-180", "180+"];
  const classes = ["age-0", "age-1", "age-2", "age-3", "age-4"];
  const segs = order.map((k, i) => ({ label: `${k}d`, value: o.age_days?.[k] || 0, cls: classes[i] }));
  const signals = SIGNALS.filter((s) => o.by_signal?.[s.key]).map((s) => `${esc(s.label)} ${o.by_signal[s.key]}`).join(" · ");
  return `<section class="panel"><h3>Open now, as the record holds it</h3>
    <div class="dr"><dt>Items</dt><dd>${fmt(o.items)} · ${fmt(o.ticketed)} ticketed${o.missing ? ` · <span class="muted">${fmt(o.missing)} absent from the latest run, inside the grace period</span>` : ""}</dd></div>
    ${signals ? `<div class="dr"><dt>Signals</dt><dd>${signals}</dd></div>` : ""}
    <div class="age-strip"><div class="sub">How long the record has held them</div>${stackedBar(segs, { empty: "Nothing open." })}</div>
  </section>`;
}

/** render builds the page from the /api/v1/history response body. */
export function render(body) {
  const h = body?.history || {};
  const status = body?.status || {};
  if (!h.enabled) {
    return `<section class="panel notes"><h3>History is not enabled</h3>
      <p>No history store is configured, so nothing is recorded and there is nothing to show here.
      The queue, analytics and ticket pages are unaffected. See <code>docs/history.md</code> for how to enable it.</p></section>`;
  }
  return `${caveatsPanel(h, status)}
    ${directionPanel(h)}
    ${movementPanel(h)}
    ${delineationPanel(h)}
    ${signalsPanel(h)}
    ${splitTable("By rule", activePeriods(h.movement), "by_rule", null, "Rule names are the policy's own; a rename shows as one row ending and another beginning.")}
    ${splitTable("By team", activePeriods(h.movement), "by_team", null, "")}
    ${openPanel(h)}`;
}

/** rangeFromURL reads ?since= and ?bucket= so a link can carry a view. */
export function rangeFromURL() {
  const q = new URLSearchParams(typeof location !== "undefined" ? location.search : "");
  return { since: q.get("since") || "90d", bucket: q.get("bucket") || "month" };
}

/** controls renders the lookback and bucket selectors for the current range. */
export function controls(range) {
  const opt = (v, label) => `<option value="${v}"${v === range.since ? " selected" : ""}>${label}</option>`;
  const b = (v, label) => `<option value="${v}"${v === range.bucket ? " selected" : ""}>${label}</option>`;
  return `<form class="history-range" id="historyRange">
    <label>Lookback <select name="since">${opt("30d", "30 days")}${opt("90d", "90 days")}${opt("180d", "180 days")}${opt("365d", "a year")}</select></label>
    <label>By <select name="bucket">${b("month", "month")}${b("week", "week")}</select></label>
  </form>`;
}

/**
 * loadHistory fetches the report for the range in the URL and renders it into el,
 * with the range controls above it. A failure is said plainly and never blocks
 * the rest of the page: the record being unavailable is not the queue being
 * unavailable.
 */
export async function loadHistory(el) {
  if (!el) return;
  const range = rangeFromURL();
  try {
    const res = await fetch(`/api/v1/history?since=${encodeURIComponent(range.since)}&bucket=${encodeURIComponent(range.bucket)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    el.innerHTML = controls(range) + render(body);
    const form = $("#historyRange");
    form?.addEventListener("change", () => {
      const data = new FormData(/** @type {HTMLFormElement} */ (form));
      const q = new URLSearchParams(location.search);
      q.set("since", String(data.get("since")));
      q.set("bucket", String(data.get("bucket")));
      location.search = q.toString();
    });
  } catch (err) {
    el.innerHTML = `<p class="unknown">Could not load history: ${esc(String(err))}</p>`;
  }
}
