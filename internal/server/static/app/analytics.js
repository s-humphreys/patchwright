import { barChart } from './charts.js';
import { loadHistory } from './history.js';
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

/** shortRef trims a digest reference to something readable in a label. */
function shortRef(ref) {
  if (!ref) return "";
  const at = ref.indexOf("@sha256:");
  if (at < 0) return ref;
  return `${ref.slice(0, at)}@${ref.slice(at + 8, at + 20)}`;
}

/**
 * winsSection ranks the base upgrades that clear the most, headed by the estate's
 * total leverage: the one number from the old estate panel nothing else carries.
 */
function winsSection(wins, e = {}) {
  const leverage = e.base_total
    ? `<p class="sub">Across the estate a rebuild clears <strong class="ok">${e.base_clears}</strong> of ${e.base_total} CVEs (${pct(e.base_clears, e.base_total)}).</p>`
    : "";
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
          · ${(w.services || []).length} service${(w.services || []).length === 1 ? "" : "s"}
          · ${w.images} image${w.images === 1 ? "" : "s"}${w.teams > 1 ? ` · ${w.teams} teams` : ""}
          ${w.kev_cleared ? ` · ${w.kev_cleared} KEV` : ""}
          · ${w.introduces ? `<span class="warn">+${w.introduces} new</span>` : "none new"}</span></summary>
        ${serviceTable(w.services)}
      </details>
    </li>`).join("");
  return `<section class="panel"><h3>Biggest wins</h3>${leverage}
    ${barChart(rows, { empty: "Nothing to rank." })}
    <ul class="win-list">${detail}</ul></section>`;
}

/**
 * serviceTable renders the affected services as a table.
 *
 * A count somebody cannot expand is a number they have to take on trust, so the
 * list is there. By SERVICE rather than by image reference: one service is
 * typically present at an rc, a preview and a release at once, so an image list is
 * mostly the same name repeated.
 *
 * A table rather than a two-column list. The list wrapped into columns, which put
 * the second service level with the first and read as two unrelated things; and
 * with the owner and version count beside each name there are three fields per row,
 * which is a table whether or not it is drawn as one. Rows highlight on hover and
 * the body scrolls, so a base carrying a hundred services stays one screen.
 */
function serviceTable(services) {
  if (!services || !services.length) return "";
  const rows = services.map((s) => {
    const name = s.service.split("/").pop();
    return `<tr>
      <td><a href="/?service=${encodeURIComponent(name)}${
        s.team ? `&team=${encodeURIComponent(s.team)}` : ""
      }" title="${esc(s.service)}"><code>${esc(name)}</code></a></td>
      <td>${s.team ? esc(s.team) : '<span class="muted">unattributed</span>'}</td>
      <td class="num">${s.images}</td>
    </tr>`;
  }).join("");
  return `<div class="svc-scroll"><table class="mini svc-table">
    <thead><tr><th>Service</th><th>Owner</th><th class="num">Versions</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
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
        ${serviceTable(i.services)}
      </details>
    </li>`).join("");
  return `<section class="panel"><h3>Not being addressed</h3>
    <ul class="issue-list">${items}</ul></section>`;
}

/**
 * render draws the "what to fix first" half of the page: the biggest wins and the
 * problems nobody is acting on. The team table, the estate panel and the notes
 * that used to follow were cut once the movement section above took over what they
 * said; a team's age profile and the estate's totals now come from the record
 * rather than being inferred from one assessment.
 */
export function render(view) {
  const e = view.estate || {};
  if (!e.findings && !(view.wins || []).length && !(view.issues || []).length) {
    return `<p class="muted">No findings in the latest assessment.</p>`;
  }
  return `${winsSection(view.wins, e)}
    ${issuesSection(view.issues)}`;
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
  loadHistory($("#history"));
  showStatus();
  // A completed assessment changes every number here, so follow it rather than
  // leaving the reader on figures the header says are stale.
  document.addEventListener("pw:assessed", () => { load(); loadHistory($("#history")); showStatus(); });
}
