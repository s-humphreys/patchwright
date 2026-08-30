import { barChart, stackedBar } from './charts.js';
import { showStatus } from './status.js';
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
      <p class="muted">No base differential has run. Enable <code>remediation.baseDiff</code>.</p></section>`;
  }
  const rows = wins.map((w) => ({
    label: shortRef(w.from_ref),
    value: w.clears,
    cls: "bar-win",
    sub: `→ ${shortRef(w.to_ref)} · ${w.images} image${w.images === 1 ? "" : "s"}`,
    title: `clears ${w.clears} of ${w.total}` + (w.introduces ? `, introduces ${w.introduces}` : ", introduces none"),
  }));
  const detail = wins.map((w) => `<li>
      <details>
        <summary><strong class="ok">${w.clears}</strong> cleared of ${w.total}
          <span class="sub"><code>${esc(shortRef(w.from_ref))}</code> → <code>${esc(shortRef(w.to_ref))}</code>
          · ${w.images} image${w.images === 1 ? "" : "s"}${w.teams > 1 ? ` · ${w.teams} teams` : ""}
          ${w.kev_cleared ? ` · ${w.kev_cleared} KEV` : ""}
          · ${w.introduces ? `<span class="warn">+${w.introduces} new</span>` : "none new"}</span></summary>
        ${imageList(w.image_refs)}
      </details>
    </li>`).join("");
  return `<section class="panel"><h3>Biggest wins</h3>
    ${barChart(rows, { empty: "Nothing to rank." })}
    <ul class="win-list">${detail}</ul></section>`;
}

/**
 * imageList renders images as links into the queue.
 *
 * A count somebody cannot expand is a number they have to take on trust. Each one
 * opens the finding it names, so "15 images on a dead line" ends at the image
 * rather than at a number.
 */
function imageList(images) {
  if (!images || !images.length) return "";
  return `<ul class="img-list">${images.map((i) =>
    `<li><a href="/?finding=${encodeURIComponent(i)}"><code>${esc(i)}</code></a></li>`).join("")}</ul>`;
}

/** issuesSection lists what nobody is acting on, by the nature of the problem. */
function issuesSection(issues) {
  if (!issues || !issues.length) {
    return `<section class="panel"><h3>Not being addressed</h3>
      <p class="ok">Nothing outstanding.</p></section>`;
  }
  const items = issues.map((i) => `<li class="issue">
      <details>
        <summary><strong>${i.count}</strong> ${esc(i.title)}
          <span class="sub">${esc(i.why)}${i.teams > 1 ? ` · ${i.teams} teams` : ""}</span></summary>
        ${imageList(i.images)}
      </details>
    </li>`).join("");
  return `<section class="panel"><h3>Not being addressed</h3>
    <ul class="issue-list">${items}</ul></section>`;
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
    <p class="sub">Context, not a ranking.</p>
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
           <span class="sub">(${pct(e.base_clears, e.base_total)})</span>`
        : '<span class="unknown">not measured</span>'}</dd></div>
    <div class="dr"><dt>Known exploited</dt><dd>${e.kev} · ${e.kev_fixable} with an upgrade available</dd></div>
    <div class="dr"><dt>Fixes not started</dt>
      <dd>${e.unstarted} · <span class="urgent">${e.stale_unstarted}</span> over ${view.stale_fix_days}d</dd></div>
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

if (typeof document !== "undefined" && $("#analytics")) {
  load();
  showStatus();
  // A completed assessment changes every number here, so follow it rather than
  // leaving the reader on figures the header says are stale.
  document.addEventListener("pw:assessed", () => { load(); showStatus(); });
}
