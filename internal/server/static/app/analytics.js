import { barChart, columnChart, stackedBar } from './charts.js';
import { $, esc } from './util.js';

// What to do next, and what nobody is doing.
//
// An earlier version of this page ranked teams by how slow they were. That is a
// league table: it tells a security engineer who to blame, which is rarely the
// question, and it reads as an accusation to the team on top of it. Most of the
// leverage here is not per-team anyway - a handful of base images carry most of
// the CVE mass, and one rebuild clears them for everything built on that base.
//
// So the page leads with the biggest wins, then the classes of problem nobody is
// acting on, then the shape of the backlog over time. Teams appear as context on
// each - how many owners a rebuild spans, how wide an issue reaches - rather than
// as a ranking.
//
// The ordering principle throughout: a number is only worth showing if a reader
// could act differently because of it.

/** pct renders a share, or "-" when the denominator is zero. */
function pct(n, d) {
  if (!d) return "-";
  return `${Math.round((n / d) * 100)}%`;
}

/** ageStrip renders the age distribution of a team's actionable findings. */
function ageStrip(t, order) {
  const classes = ["age-0", "age-1", "age-2", "age-3", "age-4"];
  const segs = (order || []).map((label, i) => ({
    label, value: t.age_buckets?.[label] || 0, cls: classes[i] || "age-4",
  }));
  return stackedBar(segs, { empty: "No dated findings: no age source ran." });
}

/** shortRef trims a digest reference to something readable in a label. */
function shortRef(ref) {
  if (!ref) return "";
  const at = ref.indexOf("@sha256:");
  if (at < 0) return ref;
  return `${ref.slice(0, at)}@${ref.slice(at + 8, at + 20)}`;
}

/** winsSection ranks the base upgrades that clear the most. */
function winsSection(wins) {
  if (!wins || !wins.length) {
    return `<section class="panel"><h3>Biggest wins</h3>
      <p class="muted">No base differential has run, so there is nothing to rank.
      Enable <code>remediation.baseDiff</code> to see what a rebuild would clear.</p></section>`;
  }
  const rows = wins.map((w) => ({
    label: shortRef(w.from_ref),
    value: w.clears,
    display: `${w.clears}`,
    cls: "bar-win",
    sub: `${w.images} image${w.images === 1 ? "" : "s"} · ${w.teams} team${w.teams === 1 ? "" : "s"}`,
    title: `${shortRef(w.from_ref)} → ${shortRef(w.to_ref)}: clears ${w.clears} of ${w.total}` +
      (w.introduces ? `, introduces ${w.introduces}` : ", introduces none"),
  }));
  const detail = wins.map((w) => `<li>
      <code>${esc(shortRef(w.from_ref))}</code> → <code>${esc(shortRef(w.to_ref))}</code>
      <div class="sub">clears <strong class="ok">${w.clears}</strong> of ${w.total} CVEs
        across ${w.images} image${w.images === 1 ? "" : "s"}${w.teams > 1 ? ` in ${w.teams} teams` : ""}
        ${w.kev_cleared ? ` · <span class="ok">${w.kev_cleared} known-exploited</span>` : ""}
        ${w.introduces ? ` · <span class="warn">introduces ${w.introduces}</span>` : " · introduces none"}</div>
    </li>`).join("");
  return `<section class="panel"><h3>Biggest wins</h3>
    <p class="sub">One rebuild each. Ranked by the CVEs it removes across every image on that base.</p>
    ${barChart(rows, { empty: "Nothing to rank." })}
    <ul class="win-list">${detail}</ul></section>`;
}

/** issuesSection lists what nobody is acting on, by the nature of the problem. */
function issuesSection(issues) {
  if (!issues || !issues.length) {
    return `<section class="panel"><h3>Not being addressed</h3>
      <p class="ok">Nothing outstanding in any of the tracked categories.</p></section>`;
  }
  const items = issues.map((i) => `<li class="issue">
      <div class="issue-head"><strong>${i.count}</strong> ${esc(i.title)}
        ${i.teams > 1 ? `<span class="sub">across ${i.teams} teams</span>` : ""}</div>
      <div class="sub">${esc(i.why)}</div>
      ${(i.examples || []).length
        ? `<div class="issue-eg">${(i.examples || []).map((e) => `<code>${esc(e)}</code>`).join(" ")}</div>`
        : ""}
    </li>`).join("");
  return `<section class="panel"><h3>Not being addressed</h3>
    <p class="sub">Grouped by what the problem is, because each needs a different response.</p>
    <ul class="issue-list">${items}</ul></section>`;
}

/** trendSection plots when the CVEs still in the queue first appeared. */
function trendSection(trend) {
  if (!trend || !trend.length) {
    return `<section class="panel"><h3>How the backlog accumulated</h3>
      <p class="muted">No dated findings: this needs an age source
      (<code>--age-source</code>), without which nothing carries a first-seen date.</p></section>`;
  }
  const cols = trend.map((t) => ({
    label: t.month.slice(2),
    value: t.first,
    cls: t.still_no_fix > t.first / 2 ? "col-nofix" : "col-normal",
    title: `${t.month}: ${t.first} CVEs still present first appeared this month` +
      (t.still_no_fix ? `, ${t.still_no_fix} of them with no upgrade available anywhere` : ""),
  }));
  const oldest = trend[0];
  const noFix = trend.reduce((n, t) => n + t.still_no_fix, 0);
  const total = trend.reduce((n, t) => n + t.first, 0);
  return `<section class="panel"><h3>How the backlog accumulated</h3>
    <p class="sub">CVEs still in the queue, by the month they were first seen. Anything already
      fixed has left the data, so a tall old column is a CVE that has survived every release since.</p>
    ${columnChart(cols, { caption: `${total} CVEs, oldest ${esc(oldest.month)} ·` })}
    <p class="sub">${noFix
      ? `<strong>${noFix}</strong> of them have no upgrade available on any image carrying them —
         a supply problem rather than a queue nobody is working.`
      : "Every one of them has an upgrade available somewhere."}</p></section>`;
}

/** teamTable is supporting context, not a ranking. */
function teamTable(teams, view) {
  const rows = (teams || []).filter((t) => t.actionable > 0 || t.unassessed > 0).map((t) => `<tr>
      <td>${esc(t.team || t.class || "unattributed")}</td>
      <td class="num">${t.actionable}</td>
      <td class="num">${t.median_age_days === null ? "-" : t.median_age_days + "d"}</td>
      <td class="num">${t.unstarted || "-"}</td>
      <td class="num">${t.in_flight || "-"}</td>
      <td class="num">${t.kev || "-"}</td>
      <td class="num">${t.unassessed || "-"}</td>
    </tr>`).join("");
  if (!rows) return "";
  return `<section class="panel"><h3>By owner</h3>
    <p class="sub">Context for the above, not a ranking. A team with unassessed images can look
      quiet because nothing scanned them, so that column belongs next to the rest.</p>
    <div class="scroll-x"><table class="mini">
      <thead><tr><th>Owner</th><th class="num">Actionable</th><th class="num">Median age</th>
      <th class="num">Not started</th><th class="num">In progress</th><th class="num">KEV</th>
      <th class="num">Unassessed</th></tr></thead>
      <tbody>${rows}</tbody></table></div></section>`;
}

/** render draws the whole page from one payload. */
export function render(view) {
  const teams = view.teams || [];
  const e = view.estate || {};
  if (!teams.length) {
    return `<p class="muted">No findings in the latest assessment.</p>`;
  }

  const estate = `<section class="panel estate">
    <h3>Across the estate</h3>
    <div class="dr"><dt>Actionable</dt><dd>${e.actionable} of ${e.findings}</dd></div>
    <div class="dr"><dt>Base image leverage</dt>
      <dd>${e.base_total
        ? `a rebuild clears <strong class="ok">${e.base_clears}</strong> of ${e.base_total} CVEs
           <span class="sub">(${pct(e.base_clears, e.base_total)} of everything measured)</span>`
        : '<span class="unknown">not measured</span>'}</dd></div>
    <div class="dr"><dt>Known exploited</dt><dd>${e.kev} · ${e.kev_fixable} with an upgrade available</dd></div>
    <div class="dr"><dt>Fixes not started</dt>
      <dd>${e.unstarted} · <span class="urgent">${e.stale_unstarted}</span>
      older than ${view.stale_fix_days} days</dd></div>
    <div class="age-strip"><div class="sub">Age of everything actionable</div>
      ${ageStrip(e, view.age_bucket_order)}</div>
  </section>`;

  const notes = (view.notes || []).length
    ? `<section class="panel notes"><h3>What this page cannot tell you</h3><ul>${
        (view.notes || []).map((n) => `<li>${esc(n)}</li>`).join("")
      }</ul></section>`
    : "";

  return `${estate}
    ${winsSection(view.wins)}
    ${issuesSection(view.issues)}
    ${trendSection(view.trend)}
    ${teamTable(teams, view)}
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
