import { barChart, stackedBar } from './charts.js';
import { $, esc } from './util.js';

// Per-team responsiveness, for the question the queue cannot answer: is this team
// working through its findings or sitting on them.
//
// The ordering principle throughout is that a number is only worth showing if a
// reader could act differently because of it. "Findings: 412" changes nothing.
// "Nine fixes have been available for over a month and nobody has started any of
// them" is a conversation.

const num = (v) => (v === null || v === undefined ? "-" : String(v));

/** pct renders a share, or "-" when the denominator is zero. */
function pct(n, d) {
  if (!d) return "-";
  return `${Math.round((n / d) * 100)}%`;
}

/**
 * headline picks the sentence for a team, worst thing first.
 *
 * A row of numbers makes a reader do the interpreting, and different readers
 * reach different conclusions from the same row. Saying the finding out loud is
 * the point of the page.
 */
function headline(t, staleDays) {
  if (t.stale_unstarted > 0) {
    return `<strong class="urgent">${t.stale_unstarted}</strong> fixes available for over
      ${staleDays} days that nobody has started`;
  }
  if (t.kev > t.kev_fixable) {
    return `<span class="warn">${t.kev - t.kev_fixable}</span> known-exploited findings with no upgrade available`;
  }
  if (t.in_flight_stale > 0) {
    return `<span class="warn">${t.in_flight_stale}</span> pull requests open past the stale threshold — a review bottleneck, not an engagement one`;
  }
  if (t.unstarted > 0) {
    return `${t.unstarted} available fixes not yet started`;
  }
  if (t.actionable === 0) {
    return `<span class="ok">nothing actionable</span>`;
  }
  return `<span class="ok">everything actionable is started or tracked</span>`;
}

/** ageStrip renders the age distribution of a team's actionable findings. */
function ageStrip(t, order) {
  const classes = ["age-0", "age-1", "age-2", "age-3", "age-4"];
  const segs = (order || []).map((label, i) => ({
    label, value: t.age_buckets?.[label] || 0, cls: classes[i] || "age-4",
  }));
  return stackedBar(segs, { empty: "No dated findings: no age source ran." });
}

function teamCard(t, view) {
  const rows = [
    ["Actionable", `${t.actionable} of ${t.findings}`],
    ["Age of actionable", t.median_age_days === null
      ? `<span class="unknown" title="No age source ran, so these findings carry no dates. Not the same as new.">not dated</span>`
      : `median <strong>${num(t.median_age_days)}d</strong> · 90th percentile ${num(t.p90_age_days)}d`],
    ["Fix available", `${t.fixable}${t.actionable ? ` <span class="sub">(${pct(t.fixable, t.actionable)} of actionable)</span>` : ""}`],
    ["Not started", t.unstarted
      ? `<strong>${t.unstarted}</strong> with no pull request and no ticket` +
        (t.stale_unstarted ? ` · <span class="urgent">${t.stale_unstarted} over ${view.stale_fix_days}d</span>` : "")
      : `<span class="ok">none</span>`],
    ["In progress", t.in_flight
      ? `${t.in_flight} open pull requests · median ${num(t.in_flight_median_days)}d open` +
        (t.in_flight_stale ? ` · <span class="warn">${t.in_flight_stale} stale</span>` : "")
      : `<span class="muted">none open</span>`],
    ["Tickets", t.tickets_open
      ? `${t.tickets_open} open · ${t.tickets_untouched} not picked up`
      : `<span class="muted">none</span>`],
    ["Known exploited", t.kev
      ? `${t.kev} · ${t.kev_fixable} with an upgrade available`
      : `<span class="ok">none</span>`],
    ["Base image leverage", t.base_total
      ? `a rebuild clears <strong>${t.base_clears}</strong> of ${t.base_total} CVEs
         <span class="sub">(${pct(t.base_clears, t.base_total)})</span>`
      : `<span class="unknown" title="No base differential ran for this team's images.">not measured</span>`],
    ["Unassessed", t.unassessed
      ? `<span class="warn">${t.unassessed}</span> findings the provider never looked at`
      : `<span class="ok">none</span>`],
  ];
  const dl = rows.map(([k, v]) => `<div class="dr"><dt>${esc(k)}</dt><dd>${v}</dd></div>`).join("");
  const name = t.team ? `${t.class} · ${t.team}` : `${t.class || "unattributed"}`;
  return `<section class="team-card">
    <h3>${esc(name)}</h3>
    <p class="headline">${headline(t, view.stale_fix_days)}</p>
    <div class="age-strip">${ageStrip(t, view.age_bucket_order)}</div>
    <dl>${dl}</dl>
  </section>`;
}

/** render draws the whole page from one payload. */
export function render(view) {
  const teams = view.teams || [];
  if (!teams.length) {
    return `<p class="muted">No findings in the latest assessment.</p>`;
  }

  // Two charts at the top, both answering "who should I talk to first". Unstarted
  // work is the actionable one; age is the context that says how long it has been
  // that way.
  const stale = teams.filter((t) => t.stale_unstarted > 0)
    .map((t) => ({ label: t.team || t.class || "unattributed", value: t.stale_unstarted,
      cls: "bar-urgent",
      title: `${t.team || t.class}: ${t.stale_unstarted} fixes available over ${view.stale_fix_days} days, not started` }));
  const ages = teams.filter((t) => t.median_age_days !== null && t.actionable > 0)
    .sort((a, b) => b.median_age_days - a.median_age_days)
    .slice(0, 12)
    .map((t) => ({ label: t.team || t.class || "unattributed", value: t.median_age_days,
      cls: "bar-age", title: `${t.team || t.class}: median ${t.median_age_days} days` }));

  const e = view.estate;
  const estate = `<section class="estate">
    <h3>Across the estate</h3>
    <div class="dr"><dt>Actionable</dt><dd>${e.actionable} of ${e.findings}</dd></div>
    <div class="dr"><dt>Fixes not started</dt>
      <dd><strong>${e.unstarted}</strong> · <span class="urgent">${e.stale_unstarted}</span>
      of them older than ${view.stale_fix_days} days</dd></div>
    <div class="dr"><dt>Known exploited</dt><dd>${e.kev} · ${e.kev_fixable} with an upgrade available</dd></div>
    <div class="dr"><dt>Base image leverage</dt>
      <dd>${e.base_total
        ? `a rebuild clears <strong>${e.base_clears}</strong> of ${e.base_total} CVEs
           <span class="sub">(${pct(e.base_clears, e.base_total)})</span>`
        : '<span class="unknown">not measured</span>'}</dd></div>
    <div class="age-strip"><div class="sub">Age of everything actionable</div>
      ${ageStrip(e, view.age_bucket_order)}</div>
  </section>`;

  const notes = (view.notes || []).length
    ? `<section class="notes"><h3>What this page cannot tell you</h3><ul>${
        (view.notes || []).map((n) => `<li>${esc(n)}</li>`).join("")
      }</ul></section>`
    : "";

  return `${estate}
    <section class="charts">
      <div class="chart-box"><h3>Available fixes nobody has started</h3>
        ${barChart(stale, { empty: "Nothing has been sitting unstarted past the threshold." })}</div>
      <div class="chart-box"><h3>Median age of actionable findings</h3>
        ${barChart(ages, { unit: "d", empty: "No dated findings: no age source ran." })}</div>
    </section>
    <div class="team-grid">${teams.map((t) => teamCard(t, view)).join("")}</div>
    ${notes}`;
}

async function load() {
  const el = $("#analytics");
  if (!el) return;
  try {
    const res = await fetch("/api/v1/analytics");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    el.innerHTML = render(body.analytics || {});
  } catch (err) {
    // Said plainly. A blank page is indistinguishable from an estate with no
    // findings, and the two need completely different responses.
    el.innerHTML = `<p class="unknown">Could not load analytics: ${esc(String(err))}</p>`;
  }
}

if (typeof document !== "undefined" && $("#analytics")) load();
