import { SIGNAL_BADGES, badge, count, epss } from './badges.js';
import { fixPath, maxRisk, priorityText, ticketsFor, upgradeCell } from './cells.js';
import { S } from './state.js';
import { $, esc } from './util.js';

// The detail panel: everything about one finding, on demand.
//
// This is what let the queue drop from fourteen columns to five. A column costs every
// row's width forever to answer a question somebody asks about one row occasionally,
// which is why the table had grown columns for EPSS, risk score and liveness — each
// defensible alone, collectively unreadable.
//
// The rule the table follows applies here more strongly, not less: every field states
// what is unknown as unknown. This is where somebody comes to decide, and a blank
// where data is missing would be read as a zero.

/** The finding the panel is showing, so a refresh can re-render it in place. */
let shown = null;
/** Where focus was before opening, to put it back on close. */
let restoreFocus = null;

/** row renders one label/value pair, or nothing when there is nothing to say. */
function row(label, value, help) {
  if (value === "" || value === null || value === undefined) return "";
  const title = help ? ` title="${esc(help)}"` : "";
  return `<div class="dr"><dt${title}>${esc(label)}</dt><dd>${value}</dd></div>`;
}

function unknown(text, help) {
  return `<span class="unknown" title="${esc(help)}">${esc(text)}</span>`;
}

/** vulnTable lists the CVEs, worst first, with everything known about each. */
function vulnTable(f) {
  if (!f.scanned) {
    return `<p class="muted">This image was not scanned, so there is no per-CVE detail.
      The counts above come from the scan provider; fix availability, EPSS and KEV are
      unknown rather than absent.</p>`;
  }
  const vulns = (f.vulns || []).slice().sort((a, b) =>
    (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || (b.epss || 0) - (a.epss || 0) || (b.cvss || 0) - (a.cvss || 0));
  if (!vulns.length) return `<p class="muted">Scanned, and no CVEs were found.</p>`;
  const rows = vulns.slice(0, 40).map((v) => `<tr>
    <td><code>${esc(v.id)}</code></td>
    <td class="${esc(v.severity || "")}">${esc(v.severity || "-")}</td>
    <td class="num">${v.cvss ? v.cvss.toFixed(1) : "-"}</td>
    <td class="num">${v.epss ? v.epss.toFixed(2) : (f.exploit_checked ? "-" : "?")}</td>
    <td class="num">${v.risk_score ? Math.round(v.risk_score) : "-"}</td>
    <td>${v.kev ? badge(SIGNAL_BADGES.kev, "kev") : ""}</td>
    <td>${v.fix_available
      ? `<span class="act-direct">${esc(v.fixed_version || "fix available")}</span>`
      : '<span class="muted">no fix</span>'}</td>
  </tr>`).join("");
  const more = vulns.length > 40
    ? `<p class="muted">Showing the 40 worst of ${vulns.length}.</p>` : "";
  return `<div class="scroll-x"><table class="mini">
    <thead><tr><th>CVE</th><th>Severity</th><th class="num">CVSS</th><th class="num">EPSS</th>
    <th class="num">Risk</th><th>KEV</th><th>Fix</th></tr></thead>
    <tbody>${rows}</tbody></table></div>${more}`;
}

/** sections builds the panel body. */
function sections(f) {
  const u = f.upgrade;
  const tickets = ticketsFor(f);
  const p = f.in_flight;

  const verdict = [
    row("Verdict", `${priorityText(f)}${f.suppressed ? " (suppressed)" : ""}`),
    row("Because", (f.reasons || []).length
      ? (f.reasons || []).map((r) => `<code>${esc(r)}</code>`).join(" ")
      : unknown("no rule recorded", "No policy rule recorded a reason for this verdict.")),
    row("Signals", (f.signals || []).length
      ? (f.signals || []).map((s) => badge(SIGNAL_BADGES[s], s)).join(" ")
      : '<span class="muted">none</span>'),
    row("Exposure", f.exposure === "unknown"
      ? unknown("unknown", "Nothing reported whether this is reachable from the internet. Not the same as internal.")
      : esc(f.exposure)),
    row("Running now", f.liveness
      ? (f.liveness.live ? "yes" : "no")
      : unknown("?", "No live reconciliation ran, so it is not known whether this is running.")),
  ].join("");

  const risk = [
    row("Counts", f.provider_assessed
      ? ["critical", "high", "medium", "low"].map((s) => `${count(f, s)} ${s}`).join(", ")
      : unknown("not assessed", "The scan provider never assessed this image; its counts are absent, not zero.")),
    row("Fixable criticals", f.scanned ? String(f.fixable_critical ?? 0)
      : unknown("?", "Not scanned, so fix availability is unknown.")),
    row("Highest EPSS", f.exploit_checked ? epss(f)
      : unknown("?", "No exploit source ran.")),
    row("Highest risk score", f.exploit_checked
      ? (maxRisk(f) ? String(Math.round(maxRisk(f))) : unknown("-", "The provider scored none of these CVEs."))
      : unknown("?", "No exploit source ran.")),
    row("Oldest CVE", f.oldest_cve_days != null
      ? `${f.oldest_cve_days} days (first seen ${esc(String(f.oldest_cve_first_seen || "").slice(0, 10))})`
      : unknown("unknown", "No CVE here carries a first-seen date: either no age source ran, or the provider has never seen these CVEs.")),
    row("Scan error", f.scan_error ? `<code>${esc(f.scan_error)}</code>` : ""),
  ].join("");

  const fix = [
    row("Fix path", `<span class="${esc(fixPath(f))}">${esc(fixPath(f))}</span>`),
    row("Upgrade", u ? upgradeCell(f) : unknown("none reported", "No upgrade information for this image.")),
    row("How it was compared", u?.comparison ? esc(u.comparison) : ""),
    row("Why not resolved", u && !u.resolved
      ? `<code>${esc(u.reason || "no reason recorded")}</code>` : ""),
    row("Change lands in", u?.source
      ? `<code>${esc(u.source)}</code>${u.source_path ? ` path <code>${esc(u.source_path)}</code>` : ""}` : ""),
    row("Version owned by", u?.manager || u?.managed ? esc(u.manager || u.managed) : ""),
  ].join("");

  const action = [
    row("Pull request", p
      ? `<a href="${esc(p.url || "#")}" target="_blank" rel="noreferrer">${esc(p.title)}</a>
         <div class="sub">${esc(p.repository)} · open ${p.open_days}d${p.stale ? " · stale" : ""}${p.exact ? "" : " · different target version"}</div>`
      : f.in_flight_reason
        ? unknown("cannot be matched", f.in_flight_reason)
        : f.in_flight_checked
          ? '<span class="muted">none open</span>'
          : unknown("?", "In-flight detection did not run.")),
    row("Tickets", S.ticketsByRepo
      ? (tickets.length
        ? tickets.map((t) => `<a href="${esc(t.url || "#")}" target="_blank" rel="noreferrer">${esc(t.key)}</a>
            <span class="ticket-status">${esc(t.status || "")}</span>`).join("<br>")
        : '<span class="muted">none open</span>')
      : unknown("?", "Jira is not configured, so ticket state is unknown.")),
  ].join("");

  const where = [
    row("Digest", f.digest
      ? `<code>${esc(f.digest)}</code>`
      : unknown("not pinned", "This deployment does not pin a digest, so what runs can change without the tag changing.")),
    row("Workloads", String(f.workload_count ?? 0)),
    row("Namespaces", (f.dimensions?.namespace || []).map((n) => esc(n)).join(", ")
      || '<span class="muted">none reported</span>'),
    row("Accounts", (f.dimensions?.account || []).map((n) => esc(n)).join(", ")),
    row("Owner rule", f.owner?.rule
      ? `<code>${esc(f.owner.rule)}</code>`
      : unknown("none matched", "No ownership rule attributed this workload, usually a missing namespace label.")),
    row("Provider assessed", f.provider_assessed
      ? "yes"
      : `no${(f.assessment_issues || []).length ? ": " + esc(f.assessment_issues[0]) : ""}`),
  ].join("");

  return `
    <section><h4>Verdict</h4><dl>${verdict}</dl></section>
    <section><h4>Risk</h4><dl>${risk}</dl></section>
    <section><h4>Fix</h4><dl>${fix}</dl></section>
    <section><h4>In progress</h4><dl>${action}</dl></section>
    <section><h4>Where it runs</h4><dl>${where}</dl></section>
    <section><h4>Vulnerabilities</h4>${vulnTable(f)}</section>`;
}

/** openDetail shows one finding. */
export function openDetail(f) {
  shown = f;
  const el = $("#detail");
  el.innerHTML = `
    <div class="detail-head">
      <div>
        <code class="detail-title">${esc(f.image)}</code>
        <div class="sub">${esc(f.owner?.team || "unattributed")} · ${esc(f.owner?.class || "no class")}</div>
      </div>
      <button id="detailClose" class="linkish" aria-label="Close details">close</button>
    </div>
    <div class="detail-body">${sections(f)}</div>`;
  el.hidden = false;
  document.body.classList.add("detail-open");
  restoreFocus = document.activeElement;
  $("#detailClose").addEventListener("click", closeDetail);
  /** @type {any} */ ($("#detailClose")).focus();
}

export function closeDetail() {
  shown = null;
  const el = $("#detail");
  el.hidden = true;
  el.innerHTML = "";
  document.body.classList.remove("detail-open");
  const back = /** @type {any} */ (restoreFocus);
  if (back && typeof back.focus === "function") back.focus();
  restoreFocus = null;
}

/** shownImage reports which finding the panel is on, so a refresh can re-render it. */
export function shownImage() {
  return shown ? shown.image : null;
}

/** findingFor resolves a row element back to the finding it was rendered from. */
function findingFor(el) {
  const tr = el.closest("tbody tr");
  if (!tr) return null;
  return S.queueRows.find((x) => x.image === /** @type {any} */ (tr).dataset.image) || null;
}

// initDetail wires opening from the queue and closing with Escape. Delegated, so it
// survives the re-render every refresh performs.
export function initDetail() {
  $("#findings").addEventListener("click", (e) => {
    const t = /** @type {any} */ (e.target);
    // Links inside a row are their own actions: a ticket or pull request link opens
    // its target rather than the panel.
    if (t.closest("a")) return;
    const f = findingFor(t);
    if (f) openDetail(f);
  });
  $("#findings").addEventListener("keydown", (e) => {
    const ke = /** @type {any} */ (e);
    if (ke.key !== "Enter" && ke.key !== " ") return;
    const f = findingFor(ke.target);
    if (!f) return;
    ke.preventDefault(); // Space would otherwise scroll the page.
    openDetail(f);
  });
  document.addEventListener("keydown", (e) => {
    if (/** @type {any} */ (e).key === "Escape" && !$("#detail").hidden) closeDetail();
  });
}

/** openCVEDetail shows one CVE and every image carrying it. */
export function openCVEDetail(g) {
  shown = { image: null, cve: g.id };
  const el = $("#detail");
  const rows = g.images.slice()
    .sort((a, b) => a.image.localeCompare(b.image))
    .map((i) => `<tr>
      <td class="wrap"><code>${esc(i.image)}</code></td>
      <td>${i.team ? esc(i.team) : unknown("unattributed", "No ownership rule matched this workload.")}</td>
      <td>${i.fixed ? `<span class="act-direct">${esc(i.fixed)}</span>` : '<span class="muted">no fix</span>'}</td>
      <td>${esc(i.fix)}</td>
    </tr>`).join("");
  const teams = [...g.teams].sort();
  el.innerHTML = `
    <div class="detail-head">
      <div>
        <code class="detail-title">${esc(g.id)}</code>
        <div class="sub">${esc(g.severity)}${g.kev ? " · known exploited" : ""} · ${g.images.length} image${g.images.length === 1 ? "" : "s"}</div>
      </div>
      <button id="detailClose" class="linkish" aria-label="Close details">close</button>
    </div>
    <div class="detail-body">
      <section><h4>Assessment</h4><dl>
        ${row("Severity", `<span class="${esc(g.severity)}">${esc(g.severity)}</span>`)}
        ${row("CVSS", g.cvss ? g.cvss.toFixed(1) : unknown("unknown", "No CVSS score was reported for this CVE."))}
        ${row("EPSS", g.epss ? g.epss.toFixed(2) : unknown("?", "No exploit source ran, so exploitation pressure is unknown."))}
        ${row("Risk score", g.risk ? String(Math.round(g.risk)) : unknown("-", "The scan provider scored this CVE for none of these images."))}
        ${row("Known exploited", g.kev ? badge(SIGNAL_BADGES.kev, "kev") : '<span class="muted">not in CISA KEV</span>')}
      </dl></section>
      <section><h4>Scope</h4><dl>
        ${row("Images affected", String(g.images.length))}
        ${row("Teams involved", teams.length ? teams.map((t) => esc(t)).join(", ") : unknown("none attributed", "No ownership rule matched any affected workload."))}
        ${row("Fix available on", g.fixable
          ? `${g.fixable} of ${g.images.length} images`
          : unknown("none", "No affected image has a fix available: there is nothing to upgrade to yet."))}
      </dl></section>
      <section><h4>Affected images</h4>
        <div class="scroll-x"><table class="mini">
          <thead><tr><th>Image</th><th>Team</th><th>Fixed in</th><th>Fix path</th></tr></thead>
          <tbody>${rows}</tbody></table></div>
      </section>
    </div>`;
  el.hidden = false;
  document.body.classList.add("detail-open");
  restoreFocus = document.activeElement;
  $("#detailClose").addEventListener("click", closeDetail);
  /** @type {any} */ ($("#detailClose")).focus();
}

/** shownCVE reports which CVE the panel is on, so a refresh can re-render it. */
export function shownCVE() {
  return shown && shown.cve ? shown.cve : null;
}

// initCVEDetail opens a CVE's scope from the CVE table.
export function initCVEDetail(lookup) {
  const open = (target) => {
    const tr = target.closest("tbody tr");
    if (!tr) return false;
    const g = lookup(/** @type {any} */ (tr).dataset.cve);
    if (!g) return false;
    openCVEDetail(g);
    return true;
  };
  $("#cves").addEventListener("click", (e) => {
    const t = /** @type {any} */ (e.target);
    if (t.closest("a")) return;
    open(t);
  });
  $("#cves").addEventListener("keydown", (e) => {
    const ke = /** @type {any} */ (e);
    if (ke.key !== "Enter" && ke.key !== " ") return;
    if (open(ke.target)) ke.preventDefault();
  });
}
