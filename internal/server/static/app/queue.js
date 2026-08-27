import { GROUP_COLUMNS, groupFindings } from './groups.js';
import { writeURL } from './urlstate.js';
import { SIGNAL_ORDER } from './badges.js';
import { PRI_RANK, fixPath, ticketsFor, upgradeText } from './cells.js';
import { renderFreshness } from './panels.js';
import { S } from './state.js';
import { FINDING_COLUMNS, renderTable } from './table.js';
import { $, esc, get } from './util.js';

export function renderFindings(rows) {
  // Grouped by default: one row per piece of work rather than per deployment. Both
  // counts are shown, because neither alone is the whole truth: the item count is what
  // there is to do, the finding count is what it covers.
  if (grouped()) {
    const groups = groupFindings(rows);
    S.groupRows = groups;
    $("#queueCount").textContent = rows.length === S.queueRows.length
      ? `${groups.length} items covering ${rows.length} findings`
      : `${groups.length} items covering ${rows.length} of ${S.queueRows.length} findings`;
    renderTable("findings", GROUP_COLUMNS, groups);
    return;
  }
  // Cleared rather than left holding the last grouped render: state that describes
  // something no longer on screen is state something else will act on.
  S.groupRows = [];
  $("#queueCount").textContent = rows.length === S.queueRows.length
    ? `${rows.length} findings`
    : `${rows.length} of ${S.queueRows.length} findings`;
  renderTable("findings", FINDING_COLUMNS, rows);
}

/** grouped reports whether the queue is collapsed to work items. */
export function grouped() {
  const el = /** @type {any} */ ($("#groupRows"));
  return !el || el.checked;
}

// UNATTRIBUTED stands for findings no ownership rule could attribute to a team.
// The API treats an empty team parameter as "no filter", so this case cannot be
// expressed as a query and is filtered here instead. It is worth having: an
// unowned finding is a thing to fix in the cluster labels, and being able to list
// them is how that gets noticed.
export const UNATTRIBUTED = "\u0000unattributed";

export async function loadFindings() {
  const params = new URLSearchParams();
  if ($("#onlyActionable").checked) params.set("actionable", "true");
  if ($("#showSuppressed").checked) params.set("suppressed", "true");
  const d = await get("/api/v1/findings?" + params);
  S.queueRows = d.findings || [];
  S.ticketsByRepo = d.tickets;
  populateOwnerFilters(S.queueRows);
  applyOwnerFilters();
  renderFreshness(d.assessment);
}

// Options come from the rows actually present, so the dropdowns can never offer a
// team with nothing behind it, and each carries its count.
export function populateOwnerFilters(rows) {
  const classSel = $("#classFilter"), teamSel = $("#teamFilter");
  const chosenClass = classSel.value, chosenTeam = teamSel.value;

  const classes = new Map();
  for (const f of rows) {
    const c = f.owner?.class || "-";
    classes.set(c, (classes.get(c) || 0) + 1);
  }
  const teams = new Map();
  for (const f of rows) {
    if (chosenClass && (f.owner?.class || "-") !== chosenClass) continue;
    const key = f.owner?.team ? f.owner.team : UNATTRIBUTED;
    teams.set(key, (teams.get(key) || 0) + 1);
  }

  const fill = (sel, entries, allLabel, keep) => {
    const opts = [`<option value="">${allLabel} (${rows.length})</option>`];
    for (const [value, n] of [...entries].sort((a, b) => b[1] - a[1])) {
      const label = value === UNATTRIBUTED ? "(unattributed)" : value;
      opts.push(`<option value="${esc(value)}">${esc(label)} (${n})</option>`);
    }
    sel.innerHTML = opts.join("");
    // Keep the selection if it still exists, so a refresh does not reset the view.
    sel.value = [...sel.options].some((o) => o.value === keep) ? keep : "";
  };
  fill(classSel, classes, "all classes", chosenClass);
  fill(teamSel, teams, "all teams", chosenTeam);

  const fixSel = $("#fixFilter");
  const chosenFix = fixSel.value;
  const fixCounts = new Map();
  for (const f of rows) {
    if (chosenClass && (f.owner?.class || "-") !== chosenClass) continue;
    const p = fixPath(f);
    fixCounts.set(p, (fixCounts.get(p) || 0) + 1);
  }
  const ordered = ["direct", "managed", "none", "unknown", "?"]
    .filter((k) => fixCounts.has(k));
  fixSel.innerHTML = [`<option value="">all fixes (${rows.length})</option>`]
    .concat(ordered.map((k) => `<option value="${esc(k)}">${esc(k)} (${fixCounts.get(k)})</option>`))
    .join("");
  fixSel.value = [...fixSel.options].some((o) => o.value === chosenFix) ? chosenFix : "";

  // Urgency, for the question "what is urgent in this team" without reading every row.
  // Ordered worst-first rather than alphabetically: the list is a severity scale, and
  // sorting it as text puts "high" above "urgent".
  const urgSel = $("#urgencyFilter");
  if (urgSel) {
    const chosenUrgency = urgSel.value;
    const urgCounts = new Map();
    for (const f of rows) {
      if (chosenClass && (f.owner?.class || "-") !== chosenClass) continue;
      const p = f.priority || "none";
      urgCounts.set(p, (urgCounts.get(p) || 0) + 1);
    }
    const byRank = [...urgCounts.keys()].sort((a, b) => (PRI_RANK[b] ?? 0) - (PRI_RANK[a] ?? 0));
    urgSel.innerHTML = [`<option value="">any urgency (${rows.length})</option>`]
      .concat(byRank.map((k) => `<option value="${esc(k)}">${esc(k)} (${urgCounts.get(k)})</option>`))
      .join("");
    urgSel.value = [...urgSel.options].some((o) => o.value === chosenUrgency) ? chosenUrgency : "";
  }

  // Only signals actually present are offered. An option that can only ever return
  // nothing is a worse answer than no option.
  const sigSel = $("#signalFilter");
  const chosenSignal = sigSel.value;
  const sigCounts = new Map();
  for (const f of rows) {
    if (chosenClass && (f.owner?.class || "-") !== chosenClass) continue;
    for (const sig of f.signals || []) sigCounts.set(sig, (sigCounts.get(sig) || 0) + 1);
  }
  sigSel.innerHTML = [`<option value="">any signal (${rows.length})</option>`]
    .concat(SIGNAL_ORDER.filter((k) => sigCounts.has(k))
      .map((k) => `<option value="${esc(k)}">${esc(k)} (${sigCounts.get(k)})</option>`))
    .join("");
  sigSel.value = [...sigSel.options].some((o) => o.value === chosenSignal) ? chosenSignal : "";
}

// haystack is what the search box matches against: the fields someone would
// plausibly type a fragment of. Ticket keys are included so "PROJ-12" finds
// every image a grouped ticket covers.
export function haystack(f) {
  const parts = [
    f.image, f.repository, f.registry, f.owner?.team, f.owner?.class, f.priority,
    (f.dimensions?.namespace || []).join(" "),
    (f.dimensions?.account || []).join(" "),
    upgradeText(f), fixPath(f),
    f.in_flight ? `${f.in_flight.title} ${f.in_flight.repository}` : "",
    (f.signals || []).join(" "), f.exposure,
    ticketsFor(f).map((t) => `${t.key} ${t.status}`).join(" "),
  ];
  return parts.filter(Boolean).join(" ").toLowerCase();
}

export function applyOwnerFilters() {
  writeURL();
  const c = $("#classFilter").value, t = $("#teamFilter").value, x = $("#fixFilter").value;
  const sig = $("#signalFilter").value;
  const urg = $("#urgencyFilter")?.value || "";
  const q = $("#search").value.trim().toLowerCase();
  const rows = S.queueRows.filter((f) => {
    if (c && (f.owner?.class || "-") !== c) return false;
    if (t === UNATTRIBUTED && f.owner?.team) return false;
    if (t && t !== UNATTRIBUTED && f.owner?.team !== t) return false;
    // Fix is a separate question from actionable: "does policy say act" versus
    // "is there a version to move to". An image on its latest release can be both
    // actionable and unfixable, which is a decision rather than a bump.
    if (x && fixPath(f) !== x) return false;
    if (sig && !(f.signals || []).includes(sig)) return false;
    if (urg && (f.priority || "none") !== urg) return false;
    // "Has a fix" is the common case of the dropdown: something to move to,
    // whether applied here or via a chart or operator.
    if ($("#onlyFixable").checked && !["direct", "managed"].includes(fixPath(f))) return false;
    if (q && !haystack(f).includes(q)) return false;
    return true;
  });
  renderFindings(rows);
}

// Pending ticket actions.
//
// The page showed which findings had tickets but nothing about writes waiting to
// happen, so an imminent rewrite or close was invisible unless someone read the logs.
// A service about to change a tracker should say so where people are looking.
//
// Read-only by design: there is no apply button. A POST that writes to Jira should
// not be one stray click away from a dashboard behind a shared token.
// What each action does, in words somebody who did not build this would use. The kind
// itself ("note-done", "extend") is internal vocabulary: useful for matching a row to a
// log line, which is why it stays in the hover, but meaningless as a column.
