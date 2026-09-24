import { mountBars, mountStackedBars, mountTimeSeries, stackedBar } from './charts.js';
import { $, esc, utcDay } from './util.js';

// Movement by period, from the event log, rendered at the top of the analytics
// page so that page reads as a story: how things are moving, then what to do next.
//
// Two rules shape everything here. Fixed (confirmed) and left without a fix (the
// resolved and lapsed fields) are never summed - leaving without a fix is the tool
// losing sight of something, and adding it to remediation would produce a number
// that improves fastest when the scanner breaks. And ticketed fixes are a SUBSET of
// fixed, never a separate column that could be added to it; the difference between
// the two is work that landed by another route, which is the figure the delineation
// exists to show.
//
// The page also leads with the record's caveats rather than burying them, because
// the first and most misleading thing a chart of this kind can do is show an empty
// month before the record began as a month in which nothing happened.

const SIGNALS = [
  { key: "kev", label: "Known exploited" },
  { key: "epss-high", label: "EPSS above 0.5" },
  { key: "fixable-critical", label: "Fixable critical" },
  { key: "end-of-life", label: "End-of-life base" },
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
  return rows.filter((m, i) => i === rows.length - 1 || m.baseline || m.opened || m.resolved || m.lapsed || m.tickets_closed);
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
  // The definitions live here rather than under each table, so the tables carry
  // data and this one note carries the reading of it.
  items.push("A <strong>work item</strong> is one service and the one upgrade that would fix it: the unit a queue row and a ticket share. Every count below is work items unless it says CVEs.");
  items.push("<strong>Fixed (confirmed)</strong> means the item left the queue with evidence the upgrade landed: every image still reported, checked, on the latest version, and running. <strong>Left without a fix</strong> is leaving without that evidence, and is never counted as remediation.");
  items.push("Each row of the direction table is the last assessment of its period. A period with one run is a point, not a trend.");
  items.push("Open work items by signal are counted at the last assessment of each period, each item once under its most severe signal. EPSS is a forecast, so an item whose score decays below 0.5 moves out of that band without anything being fixed; the count of those sits under the chart.");
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

  const rows = points.map((p) => `<tr>
      <td>${esc(p.period)}</td><td>${fmt(p.risk?.items)}</td><td>${fmt(Math.round(p.risk?.sum || 0))}</td>
      <td>${fmt(p.risk?.urgent)}</td><td>${fmt(p.risk?.known_exploited)}</td>
      <td>${fmt(p.actionable)} of ${fmt(p.findings)}</td><td class="muted">${p.assessments}</td></tr>`).join("");
  return `<section class="panel"><h3>Direction</h3>
    <div class="dr"><dt>Risk score, sum of open work items</dt><dd><strong>${fmt(Math.round(last.risk?.sum || 0))}</strong> ${verdict}</dd></div>
    ${points.length > 1 ? `<div class="chart-slot" data-chart="direction"></div>` : ""}
    <table class="mini"><thead><tr><th>Period</th><th title="Open work items at the last assessment of the period">Open items</th><th>Risk sum</th><th>Urgent</th><th title="Open items carrying a known-exploited CVE">KEV items</th><th>Actionable findings</th><th title="Assessments in the period">Runs</th></tr></thead>
    <tbody>${rows}</tbody></table>
  </section>`;
}

/** movementPanel is opened against fixed against left without a fix, per period. */
function movementPanel(h) {
  const periods = activePeriods(h.movement);
  if (!periods.length) {
    return `<section class="panel"><h3>Movement</h3><p class="muted">Nothing recorded in this range.</p></section>`;
  }
  const totals = periods.reduce((t, m) => ({
    baseline: t.baseline + (m.baseline || 0), opened: t.opened + m.opened, resolved: t.resolved + m.resolved,
    lapsed: t.lapsed + m.lapsed, cves: t.cves + (m.cves_resolved || 0), kev: t.kev + (m.kev_cves_resolved || 0),
  }), { baseline: 0, opened: 0, resolved: 0, lapsed: 0, cves: 0, kev: 0 });
  const rows = periods.map((m) => `<tr>
      <td>${esc(m.period)}</td>${totals.baseline ? `<td class="muted">${fmt(m.baseline)}</td>` : ""}<td>${fmt(m.opened)}</td>
      <td><strong class="ok">${fmt(m.resolved)}</strong></td>
      <td>${fmt(m.cves_resolved)}${m.kev_cves_resolved ? ` <span class="sub">(${fmt(m.kev_cves_resolved)} KEV)</span>` : ""}</td>
      <td class="muted" title="${esc(Object.entries(m.lapse_reasons || {}).map(([k, v]) => `${k}: ${v}`).join(", ") || "none left without a fix")}">${fmt(m.lapsed)}</td>
      <td class="muted">${fmt(m.reassigned)}</td>
      <td>${m.median_days_to_resolve != null ? `${Math.round(m.median_days_to_resolve)}d` : "-"}</td></tr>`).join("");
  return `<section class="panel"><h3>Movement, in work items</h3>
    <p class="sub unit">A work item is one service and the one upgrade that would fix it. <strong>Fixed (confirmed)</strong> means it left the queue with evidence the upgrade landed; <strong>left without a fix</strong> is everything else that left the queue: it stopped running, dropped below the rules, or is no longer reported.</p>
    ${totals.baseline ? `<div class="dr"><dt>Already open when the record began</dt><dd class="muted">${fmt(totals.baseline)}</dd></div>` : ""}
    <div class="dr"><dt>Across the range</dt>
      <dd>${fmt(totals.opened)} opened · <strong class="ok">${fmt(totals.resolved)}</strong> fixed (confirmed), clearing ${fmt(totals.cves)} CVEs${totals.kev ? ` (${fmt(totals.kev)} known-exploited)` : ""} · <span class="muted">${fmt(totals.lapsed)} left without a fix</span></dd></div>
    ${periods.length > 1 ? `<div class="chart-slot" data-chart="movement"></div>` : ""}
    <table class="mini"><thead><tr><th>Period</th>${totals.baseline ? `<th title="Already open when the record began">Baseline</th>` : ""}<th title="Work items that entered the queue">Opened</th><th title="Left the queue with evidence the upgrade landed">Fixed (confirmed)</th><th title="Distinct CVEs carried by the fixed items">CVEs cleared</th><th title="Left the queue without evidence the upgrade landed; hover a cell for why">Left without a fix</th><th title="Owner changed">Reassigned</th><th>Median days to fix</th></tr></thead>
    <tbody>${rows}</tbody></table>
  </section>`;
}

/** delineationPanel is the four buckets security asked to see apart. */
function delineationPanel(h, tickets) {
  const periods = activePeriods(h.movement);
  if (!periods.length) return "";
  const sum = (k) => periods.reduce((n, m) => n + (m[k] || 0), 0);
  const unticketed = sum("resolved_unticketed"), ticketed = sum("resolved_ticketed");
  const closedOpen = sum("tickets_closed_finding_open"), lapsed = sum("lapsed");
  // Only once some ticket carried a due date: before that the column would be all
  // zeros that read as "nothing was late" rather than "nothing was measured".
  const onTime = sum("tickets_closed_on_time"), overdue = sum("tickets_closed_overdue");
  const measured = onTime + overdue;
  const byTool = {};
  for (const m of periods) for (const [k, v] of Object.entries(m.tickets_closed_by_tool || {})) byTool[k] = (byTool[k] || 0) + v;
  const strip = stackedBar([
    { label: "fixed (confirmed), never ticketed", value: unticketed, cls: "age-0" },
    { label: "fixed (confirmed), ticketed", value: ticketed, cls: "age-1" },
    { label: "ticket closed, finding open", value: closedOpen, cls: "age-3" },
    { label: "left without a fix", value: lapsed, cls: "age-4" },
  ], { empty: "Nothing has left the queue yet." });
  const rows = periods.map((m) => `<tr>
      <td>${esc(m.period)}</td><td>${fmt(m.resolved_unticketed)}</td><td>${fmt(m.resolved_ticketed)}</td>
      <td>${fmt(m.tickets_raised)}</td><td>${fmt(m.tickets_closed)}</td>
      <td class="${m.tickets_closed_finding_open ? "warn" : ""}">${fmt(m.tickets_closed_finding_open)}</td>
      ${measured ? `<td class="${m.tickets_closed_overdue ? "warn" : ""}">${fmt(m.tickets_closed_on_time)} / ${fmt(m.tickets_closed_overdue)}</td>` : ""}
      <td class="muted">${fmt(m.lapsed)}</td></tr>`).join("");
  const toolRows = Object.entries(byTool).map(([k, v]) => `<span class="chart-key">${esc(k)} ${v}</span>`).join(" ");
  return `<section class="panel"><h3>Total remediation against ticketed work, in work items</h3>
    <div class="dr"><dt>Upgrades and patches landed</dt>
      <dd><strong class="ok">${fmt(unticketed + ticketed)}</strong> fixed (confirmed), of which <strong>${fmt(ticketed)}</strong> (${pct(ticketed, unticketed + ticketed)}) were ticketed work</dd></div>
    ${strip}
    <table class="mini"><thead><tr><th>Period</th><th title="Landed by another route: an update bot, a Flux automation, a rebuild done in passing">Fixed, unticketed</th><th title="Ticketed work completed; a subset of fixed (confirmed)">Fixed, ticketed</th><th>Tickets raised</th><th>Tickets closed</th><th title="A ticket somebody closed while the image still ran: neither fixed nor left without a fix">Closed, finding open</th>${measured ? `<th title="Closed against the due date set when the ticket was raised; tickets without one are in neither">Closed on time / overdue</th>` : ""}<th>Left without a fix</th></tr></thead>
    <tbody>${rows}</tbody></table>
    ${toolRows ? `<p class="sub">Closed by patchwright, by reason: ${toolRows}. The rest were closed by people.</p>` : ""}
    ${measured ? `<p class="sub">Against the due date: ${fmt(onTime)} of ${fmt(measured)} (${pct(onTime, measured)}) closed on time.${meanDaysToDue(periods)}</p>` : ""}
    ${cycleTimeTable(h)}
    ${ticketsPerDay(tickets)}
  </section>`;
}

/** dayLabel renders a UTC calendar date, "2026-09-01", as "1 Sep 2026". */
function dayLabel(date, year = true) {
  return utcDay(new Date(`${date}T00:00:00Z`), year) || String(date);
}

/**
 * ticketsPerDay is the slot for the per-day chart, and the keyboard's way into the
 * same drill-down: a button per day that had tickets, since a canvas cannot take
 * focus. Nothing when the range holds no tickets, including when the tracker was
 * never read or the tickets endpoint failed.
 */
function ticketsPerDay(body) {
  const t = body?.tickets;
  if (!t?.total || !(t.days || []).length) return "";
  const picks = t.days.filter((d) => d.created).map((d) => `<li><button type="button" class="day-pick"
      data-day="${esc(d.date)}" aria-pressed="false" aria-controls="ticketDayList"
      title="${esc(`${d.created} created ${dayLabel(d.date)}`)}">${esc(dayLabel(d.date, false))} <span class="n">${fmt(d.created)}</span></button></li>`).join("");
  return `<h4>Tickets created, per day</h4>
    <p class="sub">Per day whatever the period above, by the tracker's created date: ${fmt(t.total)} in the range. Click a day, or choose one below, for its tickets.</p>
    <div class="chart-slot" data-chart="tickets-per-day"></div>
    <ul class="day-picks" aria-label="Days with tickets created">${picks}</ul>
    <div class="ticket-day-list" id="ticketDayList" hidden></div>`;
}

/** safeURL keeps a link only if it is http(s), so a stray value is never a script. */
function safeURL(u) {
  return typeof u === "string" && /^https?:\/\//i.test(u) ? u : "";
}

/** dayList renders the tickets created on one day, with a control to close it. */
export function dayList(day) {
  const head = `<div class="ticket-day-head"><strong>${day.created
    ? `${fmt(day.created)} ticket${day.created === 1 ? "" : "s"} created ${esc(dayLabel(day.date))}`
    : `No tickets were created ${esc(dayLabel(day.date))}`}</strong>
    <button type="button" class="linkish" data-close-day>Close</button></div>`;
  if (!day.created) return head;
  const rows = (day.tickets || []).map((t) => {
    const url = safeURL(t.url);
    const key = url ? `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(t.key)}</a>` : esc(t.key);
    return `<tr><td>${key}</td><td>${esc(t.project)}</td><td class="wrap">${t.summary ? esc(t.summary) : `<span class="muted">-</span>`}</td>
      <td title="${esc(t.status_category || "")}">${esc(t.status || "-")}</td>
      <td class="item">${t.item ? `<code>${esc(t.item).split("|").join("|<wbr>")}</code>` : `<span class="muted">-</span>`}</td></tr>`;
  }).join("");
  return `${head}<table class="mini ticket-day"><thead><tr><th>Key</th><th>Project</th><th>Summary</th>
    <th title="Its status now, not when it was raised">Status</th>
    <th title="The work item it was matched to by image, best effort">Work item</th></tr></thead><tbody>${rows}</tbody></table>`;
}

/**
 * cycleTimeTable reads the tracker's own dates rather than the record: tickets
 * raised and closed, and the three intervals kept apart because each blames
 * something different. Its periods can reach back before the record began, which
 * is the backfill, so it chooses its own rows instead of the active periods: any
 * period the tracker has something for, and no other.
 */
function cycleTimeTable(h) {
  if (!h.tracker) return "";
  const rows = (h.movement || []).filter((m) => m.tracker_tickets_raised || m.tracker_tickets_closed
    || m.median_days_told_n || m.median_days_to_start_n || m.median_days_worked_n);
  if (!rows.length) return "";
  const medians = rows.some((m) => m.median_days_told_n || m.median_days_to_start_n || m.median_days_worked_n);
  const days = (m, key) => {
    const d = m[key], n = m[`${key}_n`];
    if (d == null || !n) return `<td class="muted">-</td>`;
    return `<td title="${esc(`median over ${n} ticket${n === 1 ? "" : "s"} resolved in ${m.period}`)}">${fmt(d)} <span class="sub">n=${fmt(n)}</span></td>`;
  };
  const body = rows.map((m) => `<tr>
      <td>${esc(m.period)}</td><td>${fmt(m.tracker_tickets_raised)}</td><td>${fmt(m.tracker_tickets_closed)}</td>
      ${medians ? days(m, "median_days_told") + days(m, "median_days_to_start") + days(m, "median_days_worked") : ""}</tr>`).join("");
  return `<h4>Cycle time, from the tracker</h4>
    <table class="mini cycle-time"><thead><tr><th>Period</th>
      <th title="Every ticket on the configured projects, by the tracker's created date: tickets, not resolutions">Tickets raised</th>
      <th title="By the tracker's resolution date">Tickets closed</th>
      ${medians ? `<th title="Work item first seen to ticket raised: long means nobody was told">Finding to ticket, median days</th>
      <th title="Ticket raised to its first In Progress status: long means told, not prioritised">Ticket to In Progress, median days</th>
      <th title="First In Progress to resolved: long means being worked, slowly">In Progress to resolved, median days</th>` : ""}
    </tr></thead><tbody>${body}</tbody></table>`;
}

/**
 * meanDaysToDue weights each period's mean by the closes it covers, since a mean of
 * means would let a quiet month count as much as a busy one.
 */
function meanDaysToDue(periods) {
  let total = 0, n = 0;
  for (const m of periods) {
    const k = (m.tickets_closed_on_time || 0) + (m.tickets_closed_overdue || 0);
    if (m.mean_days_to_due_at_close == null || !k) continue;
    total += m.mean_days_to_due_at_close * k;
    n += k;
  }
  if (!n) return "";
  const d = Math.round((total / n) * 10) / 10;
  const days = (x) => `${fmt(x)} day${x === 1 ? "" : "s"}`;
  return d < 0 ? ` On average ${days(-d)} late.` : ` On average ${days(d)} to spare.`;
}

/**
 * signalsPanel is the open queue by signal at the end of each period, from the last
 * assessment's work-item list, followed by the two movements that change a band
 * without anything being fixed. Each item sits in one band only, its most severe,
 * so the bands stack to the open items carrying any signal rather than double
 * counting an item that is both known-exploited and end-of-life.
 */
function signalsPanel(h) {
  const points = (h.risk || []).filter((p) => p.open_by_signal);
  const periods = activePeriods(h.movement);
  if (!points.length && !periods.length) return "";
  const total = (p) => SIGNALS.reduce((n, s) => n + (p.open_by_signal[s.key] || 0), 0);
  const split = (p) => SIGNALS.map((s) => `${esc(s.label)} ${fmt(p.open_by_signal[s.key] || 0)}`).join(" · ");
  let body;
  if (!points.length) {
    body = `<p class="muted">No work-item list was recorded for this range, so the open queue cannot be split by signal.</p>`;
  } else if (points.length === 1) {
    const p = points[0];
    body = `<p>At the end of ${esc(p.period)}: ${split(p)}, ${fmt(total(p))} in all. One period is a count, not a chart.</p>`;
  } else {
    const head = SIGNALS.map((s) => `<th>${esc(s.label)}</th>`).join("");
    const rows = points.map((p) => `<tr><td>${esc(p.period)}</td>${
      SIGNALS.map((s) => `<td>${fmt(p.open_by_signal[s.key] || 0)}</td>`).join("")}<td>${fmt(total(p))}</td></tr>`).join("");
    body = `<p class="sub">Open at the end of each period. Each work item is counted once, under its most severe signal: known exploited, then EPSS above 0.5, then fixable critical, then end-of-life. A bar is every open item carrying any of them; items with none are left out.</p>
    <div class="chart-slot" data-chart="signals"></div>
    <details class="chart-numbers"><summary>The numbers</summary>
      <table class="mini"><thead><tr><th>Period</th>${head}<th>Total</th></tr></thead><tbody>${rows}</tbody></table></details>`;
  }
  const decayed = periods.reduce((n, m) => n + (m.epss_decayed || 0), 0);
  const becameKEV = periods.reduce((n, m) => n + (m.became_known_exploited || 0), 0);
  const figures = periods.length ? `
    <div class="dr"><dt title="Left the EPSS band by score decay while open: not remediation">EPSS decayed below 0.5</dt><dd>${fmt(decayed)}</dd></div>
    <div class="dr"><dt>Became known-exploited while open</dt><dd>${fmt(becameKEV)}</dd></div>` : "";
  return `<section class="panel"><h3>Open work items by signal</h3>
    ${body}${figures}
  </section>`;
}

/** openPanel is the queue as the record holds it now. */
function openPanel(h) {
  const o = h.open || {};
  const order = ["0-7", "7-30", "30-90", "90-180", "180+"];
  const classes = ["age-0", "age-1", "age-2", "age-3", "age-4"];
  const segs = order.map((k, i) => ({ label: `${k}d`, value: o.age_days?.[k] || 0, cls: classes[i] }));
  const signals = SIGNALS.filter((s) => o.by_signal?.[s.key]).map((s) => `${esc(s.label)} ${o.by_signal[s.key]}`).join(" · ");
  return `<section class="panel"><h3>Open now, as the record holds it</h3>
    <div class="dr"><dt>Work items</dt><dd>${fmt(o.items)} · ${fmt(o.ticketed)} ticketed${o.missing ? ` · <span class="muted">${fmt(o.missing)} absent from the latest run, inside the grace period</span>` : ""}${o.tickets_overdue_open ? ` · <span class="warn">${fmt(o.tickets_overdue_open)} tickets past their due date</span>` : ""}</dd></div>
    ${signals ? `<div class="dr"><dt>Signals</dt><dd>${signals}</dd></div>` : ""}
    ${closedTicketAges(o)}
    <div class="age-strip"><div class="sub">How long the record has held them</div>${stackedBar(segs, { empty: "Nothing open." })}</div>
  </section>`;
}

/**
 * closedTicketAges dates the "ticket closed, finding open" bucket from the tracker:
 * items still open whose ticket somebody closed, by days since the close. Nothing
 * when there are none, or when the tracker has never been read.
 */
function closedTicketAges(o) {
  if (!o.closed_ticket_finding_open) return "";
  const order = ["0-7", "7-30", "30-90", "90-180", "180+"];
  const ages = order.filter((k) => o.closed_ticket_age_days?.[k])
    .map((k) => `${k} days ${fmt(o.closed_ticket_age_days[k])}`).join(" · ");
  return `<div class="dr"><dt title="Open items whose latest ticket was closed while the finding stayed open, with no ticket now">Ticket closed, finding open</dt>
    <dd><span class="warn">${fmt(o.closed_ticket_finding_open)}</span>${ages ? ` · since the close: ${ages}` : ""}</dd></div>`;
}

/**
 * render builds the page from the /api/v1/history response body, and tickets from
 * the /api/v1/history/tickets one when it loaded.
 */
export function render(body, tickets) {
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
    ${delineationPanel(h, tickets)}
    ${signalsPanel(h)}
    ${openPanel(h)}`;
}

/** epoch turns a period start into seconds for the chart's time axis. */
function epoch(iso) { return Math.floor(new Date(iso).getTime() / 1000); }

/** cssVar reads a theme colour so the charts follow light and dark mode. */
function cssVar(name, fallback) {
  if (typeof getComputedStyle === "undefined" || typeof document === "undefined") return fallback;
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

/**
 * mountCharts draws the interactive charts into the slots render left, once the
 * HTML is in the document. Separate from render because a chart needs a live
 * element and render returns a string; and guarded, so a page without the chart
 * library still shows every table.
 */
export function mountCharts(root, body, tickets) {
  const h = body?.history || {};
  mountTicketsPerDay(root, tickets);
  const direction = root?.querySelector?.('[data-chart="direction"]');
  if (direction && (h.risk || []).length > 1) {
    const idx = Object.fromEntries((h.movement || []).map((m) => [m.period, m.start]));
    mountTimeSeries(direction, {
      x: h.risk.map((p) => epoch(idx[p.period] || p.at)),
      series: [
        { label: "risk sum", values: h.risk.map((p) => Math.round(p.risk?.sum || 0)), color: cssVar("--accent", "#4a6b8a") },
        { label: "KEV items", values: h.risk.map((p) => p.risk?.known_exploited ?? null), color: cssVar("--urgent", "#a4262c") },
      ],
    });
  }
  const movement = root?.querySelector?.('[data-chart="movement"]');
  const periods = activePeriods(h.movement);
  if (movement && periods.length > 1) {
    mountTimeSeries(movement, {
      x: periods.map((m) => epoch(m.start)),
      series: [
        { label: "opened", values: periods.map((m) => m.opened), color: cssVar("--muted", "#6b6b66") },
        { label: "fixed (confirmed)", values: periods.map((m) => m.resolved), color: cssVar("--ok", "#1f6b3a") },
        { label: "left without a fix", values: periods.map((m) => m.lapsed), color: cssVar("--high", "#b8590a") },
      ],
    });
  }
  const signals = root?.querySelector?.('[data-chart="signals"]');
  const points = (h.risk || []).filter((p) => p.open_by_signal);
  if (signals && points.length > 1) {
    const colours = {
      kev: cssVar("--urgent", "#a4262c"), "epss-high": cssVar("--high", "#b8590a"),
      "fixable-critical": cssVar("--medium", "#6b6b00"), "end-of-life": cssVar("--accent", "#4a6b8a"),
    };
    mountStackedBars(signals, {
      labels: points.map((p) => p.period),
      totalLabel: "open with a signal",
      series: SIGNALS.map((s) => ({ label: s.label, values: points.map((p) => p.open_by_signal[s.key] || 0), color: colours[s.key] })),
    });
  }
}

/**
 * mountTicketsPerDay wires the per-day drill-down: a bar or a day button opens that
 * day's tickets under the chart, the same day again or Close hides them. The
 * buttons work without the chart library, so the list never depends on a canvas.
 */
export function mountTicketsPerDay(root, body) {
  const days = body?.tickets?.days || [];
  const list = root?.querySelector?.("#ticketDayList");
  if (!list || !days.length) return;
  const picks = [...root.querySelectorAll(".day-pick")];
  let open = "";
  const select = (date) => {
    open = open === date ? "" : date;
    const day = days.find((d) => d.date === open);
    list.hidden = !day;
    list.innerHTML = day ? dayList(day) : "";
    for (const b of picks) b.setAttribute("aria-pressed", String(b.dataset.day === open));
  };
  for (const b of picks) b.addEventListener("click", () => select(b.dataset.day || ""));
  list.addEventListener("click", (e) => {
    if (!/** @type {Element} */ (e.target).closest?.("[data-close-day]")) return;
    const from = picks.find((b) => b.dataset.day === open);
    select(open);
    from?.focus();
  });
  mountBars(root.querySelector('[data-chart="tickets-per-day"]'), {
    x: days.map((d) => epoch(`${d.date}T00:00:00Z`)),
    values: days.map((d) => d.created),
    label: "tickets created",
    color: cssVar("--accent", "#4a6b8a"),
    onSelect: (i) => select(days[i].date),
  });
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
    const since = encodeURIComponent(range.since);
    // The per-day tickets are an extra: if they fail, the report still renders.
    const [res, tickets] = await Promise.all([
      fetch(`/api/v1/history?since=${since}&bucket=${encodeURIComponent(range.bucket)}`),
      fetch(`/api/v1/history/tickets?since=${since}`).then((r) => (r.ok ? r.json() : null)).catch(() => null),
    ]);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    el.innerHTML = controls(range) + render(body, tickets);
    mountCharts(el, body, tickets);
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
