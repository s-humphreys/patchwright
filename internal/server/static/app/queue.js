import { GROUP_COLUMNS, groupFindings } from './groups.js';
import { apply, filterState, populate } from './filters.js';
import { renderCVEs } from './cves.js';
import { current as currentView } from './tabs.js';
import { writeURL } from './urlstate.js';
import { renderFreshness } from './panels.js';
import { S } from './state.js';
import { FINDING_COLUMNS, renderTable } from './table.js';
import { $, get } from './util.js';

export function renderFindings(rows) {
  // Grouped by default: one row per piece of work rather than per deployment. Both
  // counts are shown, because neither alone is the whole truth: the item count is what
  // there is to do, the finding count is what it covers.
  if (grouped()) {
    const groups = groupFindings(rows);
    S.groupRows = groups;
    $("#queueCount").textContent = countText(
      `${groups.length} item${groups.length === 1 ? "" : "s"} covering`, rows.length);
    renderTable("findings", GROUP_COLUMNS, groups);
    return;
  }
  // Cleared rather than left holding the last grouped render: state that describes
  // something no longer on screen is state something else will act on.
  S.groupRows = [];
  $("#queueCount").textContent = countText("", rows.length).trimStart();
  renderTable("findings", FINDING_COLUMNS, rows);
}

/** grouped reports whether the queue is collapsed to work items. */
export function grouped() {
  const el = /** @type {any} */ ($("#groupRows"));
  return !el || el.checked;
}

// loadFindings fetches the queue. The two toggles that reach the server are here rather
// than in the filter model: "actionable only" and "include suppressed" change which
// findings the API returns at all, so they are a different question from narrowing what
// came back.
export async function loadFindings() {
  const params = new URLSearchParams();
  if ($("#onlyActionable").checked) params.set("actionable", "true");
  if ($("#showSuppressed").checked) params.set("suppressed", "true");
  const d = await get("/api/v1/findings?" + params);
  S.queueRows = d.findings || [];
  S.ticketsByRepo = d.tickets;
  applyOwnerFilters();
  renderFreshness(d.assessment);
}

// applyOwnerFilters is the single entry point after any control changes: it records the
// state in the URL, works out what survives, refreshes the dropdowns against that, and
// re-renders whichever view is showing.
//
// Named for what it did originally; it now governs the whole page rather than the queue,
// which is the point of the change.
export function applyOwnerFilters() {
  writeURL();
  const st = filterState();
  S.filtered = apply(S.queueRows, st, null);
  populate(S.queueRows, st);
  renderCurrentView();
}

/**
 * renderCurrentView draws the visible view from the filtered set.
 *
 * Every view reads S.filtered, so switching tabs cannot show a differently-filtered
 * population - which is exactly what the CVE view used to do by rendering S.queueRows.
 */
export function renderCurrentView() {
  if (currentView() === "cves") {
    const { groups, total } = renderCVEs(S.filtered);
    $("#queueCount").textContent = countText(
      `${groups.length} CVE${groups.length === 1 ? "" : "s"} across`, total);
    return;
  }
  renderFindings(S.filtered);
}

// countText says how much of the estate the number describes, and only mentions the
// total when filtering is actually narrowing it.
function countText(prefix, shown) {
  const all = S.queueRows.length;
  return shown === all
    ? `${prefix} ${shown} findings`
    : `${prefix} ${shown} of ${all} findings`;
}

// populateOwnerFilters refreshes the dropdowns against the current control state. Kept as
// a named export because it is the step that has to happen after new findings arrive and
// before anything reads the controls.
export function populateOwnerFilters(rows) {
  populate(rows || S.queueRows, filterState());
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
