import { SIGNAL_BADGES, badge, count, epss } from './badges.js';
import { fixPath, maxRisk, priorityText, ticketsFor, upgradeCell, upgradeStrategyWhy } from './cells.js';
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
/**
 * Where "back" goes, innermost last.
 *
 * The panel drills: a CVE lists the images carrying it, a work item lists its
 * deployments, and either can open one. Replacing the panel with no way back means
 * finding your place again by hand, so each drill records how to rebuild what it left.
 * Entries are closures rather than keys, because the thing to return to is the panel
 * that was open, not an identifier that may no longer resolve after a refresh.
 * @type {{label: string, open: () => void}[]}
 */
let trail = [];

/** backButton renders the way out of a drill-in, or nothing at the top level. */
function backButton() {
  if (trail.length === 0) return "";
  const to = trail[trail.length - 1];
  return `<button id="detailBack" class="linkish" aria-label="Back to ${esc(to.label)}">← ${esc(to.label)}</button>`;
}

/** wireBack attaches the back button, if the head rendered one. */
function wireBack() {
  const btn = $("#detailBack");
  if (!btn) return;
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    const to = trail.pop();
    if (to) to.open();
  });
}

/** drill opens a panel from another one, recording how to come back. */
function drill(label, reopen, open) {
  trail.push({ label, open: reopen });
  open();
}

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
// supportRow renders the maintenance status of the base line.
//
// Three outcomes, kept apart on purpose: maintained, not maintained, and not checked.
// Collapsing the third into either of the others is how a queue ends up asserting
// something nobody verified.
function supportRow(u) {
  const st = u && u.support;
  if (!st || !st.known) {
    return unknown("not checked",
      "No support source ran, or this base image is not one it recognises. That is an absence of information, not a clean bill of health.");
  }
  if (st.supported) {
    const until = st.eol ? ` until ${esc(st.eol)}` : "";
    return `<span class="ok">yes</span> — ${esc(st.product)} ${esc(st.cycle)}, maintained${until}` +
      (st.source ? ` <span class="sub">per ${esc(st.source)}</span>` : "");
  }
  const bits = [`<span class="badge badge-eol">eol</span> ${esc(st.product)} ${esc(st.cycle)} is no longer maintained`];
  if (st.eol) bits.push(`support ended ${esc(st.eol)}`);
  const moves = [];
  if (st.recommended) moves.push(`move to <code>${esc(st.recommended)}</code> (maintained, already long-term supported)`);
  if (st.nearest) moves.push(`smallest supported move <code>${esc(st.nearest)}</code>`);
  if (st.newest) moves.push(`<span class="muted">newest line ${esc(st.newest)}, not recommended yet</span>`);
  if (moves.length) bits.push(moves.join("; "));
  if (!st.recommended) {
    bits.push(unknown("no maintained line found",
      "The source lists no maintained line for this product, so there is no target to name. The finding stands: nothing will fix this image in place."));
  }
  if (st.source) bits.push(`<span class="sub">per ${esc(st.source)}</span>`);
  return bits.join(" — ");
}

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
    // Support status sits in the fix panel because it IS the fix answer here: on a dead
    // line there is no version to move along, only a line to move off.
    row("Base line supported", supportRow(u), "Whether the runtime or distribution this image is built on is still maintained. Not checked is not the same as supported."),
    row("Newest available", u?.newest
      ? `${esc(u.newest)} <span class="sub">${esc(upgradeStrategyWhy(u))}</span>` : ""),
    row("Upgrade policy", u?.ceiling
      ? `held at ${esc(u.ceiling)}${u.ceiling_reason ? ` — ${esc(u.ceiling_reason)}` : ""}` +
        (u.ceiling_expired ? " " + unknown("(expired, not applied)", "The ceiling's end date has passed, so it was not applied. The constraint is due a revisit.") : "")
      : u?.strategy && u.strategy !== "latest" ? `${esc(u.strategy)} upgrades only` : ""),
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
    row("Namespaces", (f.dimensions?.namespace || []).map((n) => esc(n)).join("<br>")
      || '<span class="muted">none reported</span>'),
    row("Accounts", (f.dimensions?.account || []).map((n) => esc(n)).join("<br>")),
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
      <div class="detail-actions">${backButton()}<button id="detailClose" class="linkish" aria-label="Close details">close</button></div>
    </div>
    <div class="detail-body">${sections(f)}</div>`;
  el.hidden = false;
  document.body.classList.add("detail-open");
  writeDeepLink({ finding: f.image });
  restoreFocus = document.activeElement;
  $("#detailClose").addEventListener("click", closeDetail);
  wireBack();
  /** @type {any} */ ($("#detailClose")).focus();
}

/** writeDeepLink reflects the open panel into the address bar, so the view is a link
 *  somebody can send — and so a ticket can link back to its own evidence. */
function writeDeepLink(params) {
  const q = new URLSearchParams(location.search);
  for (const key of ["service", "team", "finding", "cve"]) q.delete(key);
  for (const [k, v] of Object.entries(params)) if (v) q.set(k, String(v));
  const query = q.toString();
  history.replaceState(null, "", query ? `?${query}` : location.pathname);
}

export function closeDetail() {
  shown = null;
  trail = [];
  writeDeepLink({});
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

/** groupFor resolves a queue row back to the work item it renders, when grouped. */
function groupFor(el) {
  const tr = el.closest("tbody tr");
  if (!tr) return null;
  const image = /** @type {any} */ (tr).dataset.image;
  return (S.groupRows || []).find((g) => g.image === image) || null;
}

// initDetail wires opening from the queue and closing with Escape. Delegated, so it
// survives the re-render every refresh performs.
export function initDetail() {
  // A queue row is a work item when grouped and a deployment when not, so open
  // whichever the row actually represents.
  const openRow = (target) => {
    const g = groupFor(target);
    if (g) {
      openGroupDetail(g);
      return true;
    }
    const f = findingFor(target);
    if (f) {
      openDetail(f);
      return true;
    }
    return false;
  };
  $("#findings").addEventListener("click", (e) => {
    const t = /** @type {any} */ (e.target);
    // Links inside a row are their own actions: a ticket or pull request link opens
    // its target rather than the panel.
    if (t.closest("a")) return;
    openRow(t);
  });
  $("#findings").addEventListener("keydown", (e) => {
    const ke = /** @type {any} */ (e);
    if (ke.key !== "Enter" && ke.key !== " ") return;
    if (openRow(ke.target)) ke.preventDefault(); // Space would otherwise scroll.
  });
  document.addEventListener("keydown", (e) => {
    if (/** @type {any} */ (e).key === "Escape" && !$("#detail").hidden) closeDetail();
  });
  // Clicking away closes it. The tables are excluded because they open panels
  // themselves: their handlers run first, so closing here would immediately shut the
  // panel that a click on another row had just opened.
  document.addEventListener("click", (e) => {
    if (/** @type {any} */ ($("#detail")).hidden) return;
    const t = /** @type {any} */ (e.target);
    // A node already removed from the document belongs to a handler that has run and
    // re-rendered something. It cannot be tested for containment — a detached node is
    // inside nothing — so treating it as an outside click closes a panel the click
    // was meant to change.
    if (!t.isConnected) return;
    if (t.closest("#detail") || t.closest("#findings") || t.closest("#cves")) return;
    closeDetail();
  });
}

/** openCVEDetail shows one CVE and every image carrying it. */
export function openCVEDetail(g) {
  shown = { image: null, cve: g.id };
  const el = $("#detail");
  const rows = g.images.slice()
    .sort((a, b) => a.image.localeCompare(b.image))
    .map((i) => `<tr class="openable" tabindex="0" data-image="${esc(i.image)}"
        aria-label="Show details for ${esc(i.image)}">
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
      <div class="detail-actions">${backButton()}<button id="detailClose" class="linkish" aria-label="Close details">close</button></div>
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
  wireDrillRows(el, g.id, () => openCVEDetail(g));
  writeDeepLink({ cve: g.id });
  restoreFocus = document.activeElement;
  $("#detailClose").addEventListener("click", closeDetail);
  wireBack();
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

/** openGroupDetail shows one work item: the shared change, and every tag it covers. */
export function openGroupDetail(g) {
  shown = { image: g.image, group: g.key };
  const el = $("#detail");
  const rows = g.findings.slice()
    .sort((a, b) => (b.counts?.critical ?? 0) - (a.counts?.critical ?? 0))
    .map((f) => `<tr class="openable" tabindex="0" data-image="${esc(f.image)}"
        aria-label="Show details for ${esc(f.image)}">
      <td class="wrap"><code>${esc(f.tag || f.image)}</code></td>
      <td class="wrap">${(f.dimensions?.account || []).map((a) => esc(a)).join("<br>")
        || '<span class="muted">-</span>'}</td>
      <td class="${esc(f.priority || "")}">${esc(f.priority || "none")}</td>
      <td class="num">${f.provider_assessed
        ? `${f.counts?.critical ?? 0}C/${f.counts?.high ?? 0}H`
        : unknown("?", "Never assessed by the scan provider.")}</td>
      <td>${f.liveness ? (f.liveness.live ? "yes" : "no") : unknown("?", "No live reconciliation ran.")}</td>
    </tr>`).join("");

  const [assessed, total] = g.assessedOf;
  el.innerHTML = `
    <div class="detail-head">
      <div>
        <code class="detail-title">${esc(g.repository)}</code>
        <div class="sub">${esc(g.owner?.team || "unattributed")} · ${g.findings.length} deployment${g.findings.length === 1 ? "" : "s"}</div>
      </div>
      <div class="detail-actions">${backButton()}<button id="detailClose" class="linkish" aria-label="Close details">close</button></div>
    </div>
    <div class="detail-body">
      <section><h4>The change</h4><dl>
        ${row("Upgrade", g.upgrade ? upgradeCell(g.lead) : unknown("none reported", "No upgrade information for these images."))}
        ${row("Applies to", `${g.findings.length} deployed tag${g.findings.length === 1 ? "" : "s"}, one rebuild promoted forward`)}
        ${row("Coverage", assessed === total
          ? `all ${total} assessed by the provider`
          : unknown(`${assessed} of ${total} assessed`, "The rest were never assessed, so their counts are absent rather than zero."))}
        ${row("Worst verdict", `${esc(g.priority || "none")}${g.worstWhere
          ? ` in ${esc(g.worstWhere)}`
          : g.findings.length > 1
            ? " — the same in every deployment"
            : ""}`,
          g.worstWhere
            ? "The deployments here disagree, and this is where the worst verdict came from."
            : "The verdict does not depend on where this runs: either every deployment agrees, or one deployment runs in several places at once.")}
      </dl></section>
      <section><h4>In progress</h4><dl>
        ${row("Pull request", g.in_flight
          ? `<a href="${esc(g.in_flight.url || "#")}" target="_blank" rel="noreferrer">${esc(g.in_flight.title)}</a>
             <div class="sub">${esc(g.in_flight.repository)} · open ${g.in_flight.open_days}d${g.in_flight.stale ? " · stale" : ""}</div>`
          : g.in_flight_checked ? '<span class="muted">none open</span>'
            : unknown("?", "In-flight detection did not run for every image here."))}
        ${row("Tickets", S.ticketsByRepo
          ? (ticketsFor(g.lead).length
            ? ticketsFor(g.lead).map((t) => `<a href="${esc(t.url || "#")}" target="_blank" rel="noreferrer">${esc(t.key)}</a>
                <span class="ticket-status">${esc(t.status || "")}</span>`).join("<br>")
            : '<span class="muted">none open</span>')
          : unknown("?", "Jira is not configured, so ticket state is unknown."))}
      </dl></section>
      <section><h4>Deployments</h4>
        <p class="muted">Select one for its CVEs and everything else known about it.</p>
        <div class="scroll-x"><table class="mini">
          <thead><tr><th>Tag</th><th>Accounts</th><th>Verdict</th><th class="num">C/H</th><th>Live</th></tr></thead>
          <tbody>${rows}</tbody></table></div>
      </section>
    </div>`;
  el.hidden = false;
  document.body.classList.add("detail-open");
  // Team and service rather than a group key: those are what a ticket knows about
  // itself, and they stay valid when tags move on.
  writeDeepLink({ service: g.repository, team: g.owner?.team || "" });
  restoreFocus = document.activeElement;
  $("#detailClose").addEventListener("click", closeDetail);
  wireBack();
  // Drill from the work item to one deployment. The panel replaces itself rather than
  // stacking: two sheets deep is a place people get lost.
  wireDrillRows(el, "the work item", () => openGroupDetail(g));
  /** @type {any} */ ($("#detailClose")).focus();
}

/**
 * openFromURL opens whatever the address bar names, once the data has loaded.
 *
 * This is what makes a ticket's link work. The link names a team and service rather
 * than an image tag, because a tag will have moved on by the time somebody clicks a
 * ticket — the service and its owner have not.
 *
 * A link naming something no longer in the queue opens nothing and returns why. It
 * must never open the nearest match: quietly showing somebody a different service than
 * the one they clicked through for is worse than showing them the queue.
 * @returns {string} a message when the link could not be honoured, else ""
 */
export function openFromURL(groups, cveLookup, params = new URLSearchParams(location.search)) {

  const cve = params.get("cve");
  if (cve) {
    const g = cveLookup ? cveLookup(cve) : null;
    if (g) {
      openCVEDetail(g);
      return "";
    }
    return `${cve} is not in this assessment. It may be fixed, or no scanned image carries it.`;
  }

  const finding = params.get("finding");
  if (finding) {
    const f = S.queueRows.find((x) => x.image === finding);
    if (f) {
      openDetail(f);
      return "";
    }
    return `No finding for ${finding} in this assessment. It may have been redeployed, or a filter is hiding it.`;
  }

  const service = params.get("service");
  if (!service) return "";
  const team = params.get("team");
  const match = (groups || []).find((g) =>
    g.repository === service && (!team || g.owner?.team === team));
  if (match) {
    openGroupDetail(match);
    return "";
  }
  return `No queue item for ${service}${team ? ` owned by ${team}` : ""} in this assessment. ` +
    `It may already be fixed, or a filter is hiding it.`;
}

/**
 * wireDrillRows makes a panel's table rows open the finding they name, recording the
 * way back to the panel they were opened from.
 *
 * Shared by the work item's deployments and a CVE's affected images: both list images,
 * and both should behave the same when clicked.
 */
function wireDrillRows(el, label, reopen) {
  el.querySelectorAll("tbody tr.openable").forEach((tr) => {
    const open = (e) => {
      // Stop here. Opening the finding replaces this panel's contents, which detaches
      // this row — and a detached node is inside nothing, so the click-away handler
      // would see the click as landing outside the panel and close it.
      if (e) e.stopPropagation();
      const image = /** @type {any} */ (tr).dataset.image;
      const f = S.queueRows.find((x) => x.image === image);
      if (!f) {
        // The image is in this CVE's scope but filtered out of the queue, so there is
        // no finding loaded to show. Say so rather than doing nothing on a click.
        const cell = tr.querySelector("td");
        if (cell && !cell.querySelector(".unknown")) {
          cell.insertAdjacentHTML("beforeend",
            ' ' + unknown("(filtered out of the queue)",
              "This image carries the CVE but a queue filter is hiding it, so there is no finding to open."));
        }
        return;
      }
      drill(label, reopen, () => openDetail(f));
    };
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => {
      const ke = /** @type {any} */ (e);
      if (ke.key !== "Enter" && ke.key !== " ") return;
      ke.preventDefault();
      open(ke);
    });
  });
}
