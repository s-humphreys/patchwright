import { initialQuery, readURL } from './urlstate.js';
import { initConfig } from './config.js';
import { initCSV } from './csv.js';
import { nav } from './nav.js';
import { renderCoverage, renderDataAge, renderFreshness, renderTiles } from './panels.js';
import { groupByKey, initCVEDetail, initDetail, openCVEDetail, openDetail, openFromURL, openGroupDetail, shownCVE, shownGroup, shownImage } from './detail.js';
import { cveGroup } from './cves.js';
import { initTabs, show } from './tabs.js';
import { wireFacets } from './filters.js';
import { applyOwnerFilters, loadFindings, renderCurrentView } from './queue.js';
import { S } from './state.js';
import { initTable, renderBreakdown } from './table.js';
import { $, get, hasAssessment } from './util.js';

// Whether the shareable filter state has been applied. Once only: a later poll must
// not undo what the reader has changed since.
let restored = false;

export async function loadAll() {
  try {
    const [summary, owners] = await Promise.all([
      get("/api/v1/summary"), get("/api/v1/owners"),
    ]);
    renderFreshness(summary.assessment);
    // The header already polls, but this reload has fresher data in hand; feeding it
    // in avoids a redundant request and a second of disagreement between the two.
    nav()?.observe(summary.assessment);
    if (!hasAssessment(summary.assessment)) {
      // Show nothing rather than zeros: an empty dashboard is honest, a dashboard
      // of zeros is a claim.
      $("#coverage").innerHTML = `<div class="banner">No assessment has completed yet,
        so there is nothing to report. A full run reconciles every cluster and scans every
        image, which takes several minutes; this page fills in as soon as it finishes.</div>`;
      if (summary.assessment?.running) setTimeout(loadAll, 5000);
      $("#tiles").innerHTML = "";
      $("#findings tbody").innerHTML = "";
      $("#breakdown tbody").innerHTML = "";
      $("#queueCount").textContent = "";
      $("#dataAge").textContent = "";
      return;
    }
    renderCoverage(summary.summary);
    renderDataAge(summary.summary);
    renderTiles(summary.summary);
    // Findings first: they carry whether Jira was consulted, which the breakdown
    // needs in order to distinguish "no tickets" from "not asked".
    await loadFindings();
    // After the first load, because the dropdowns are built from the findings: a
    // team or signal cannot be restored before its option exists.
    if (!restored) {
      restored = true;
      if (readURL()) applyOwnerFilters();
      // A link from a ticket names a team and service; open what it asked for, or say
      // why it could not be honoured rather than silently showing the whole queue.
      // From the link the page arrived with, not the address bar: the first render
      // has already rewritten that.
      const missed = openFromURL(S.groupRows, cveGroup, initialQuery());
      if (missed) {
        $("#queueCount").insertAdjacentHTML("afterend",
          `<span class="unknown" id="linkMiss"> · ${missed}</span>`);
      }
    }
    renderBreakdown(owners.owners);
    // Re-render an open panel against the new data rather than leaving it showing
    // figures from the previous run, or closing it under somebody mid-read.
    //
    // The KIND has to survive the refresh, not just the subject. A work item panel
    // records a representative image as well as its key, so asking "which image is
    // open" gets an answer for a service panel too and reopens it as that one image -
    // the panel narrows itself under the reader a minute after they opened it.
    const openGroup = shownGroup();
    const openImage = shownImage();
    if (openGroup) {
      const fresh = groupByKey(openGroup);
      if (fresh) openGroupDetail(fresh);
    } else if (openImage) {
      const fresh = S.queueRows.find((f) => f.image === openImage);
      if (fresh) openDetail(fresh);
    }
    const openCVE = shownCVE();
    if (openCVE) {
      const fresh = cveGroup(openCVE);
      if (fresh) openCVEDetail(fresh);
    }
  } catch (e) {
    $("#freshness").textContent = `error: ${e.message}`;
    $("#freshness").className = "meta err";
  }
}

/**
 * debounce collapses a burst of calls into the last one.
 *
 * Trailing rather than leading: the reader's last keystroke is the query they meant,
 * and filtering on the first character of it is work thrown away.
 * @param {() => void} fn
 * @param {number} ms
 */
function debounce(fn, ms) {
  /** @type {any} */
  let timer = null;
  return () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      fn();
    }, ms);
  };
}

// init wires every listener and starts the poll. Nothing runs at import time, so a
// module can be imported by a test without a page to attach to.
export function init() {
  // Drilling into a breakdown count lands on the queue with the filters applied: the
  // question after "how many" is always "which ones", and the tab has to follow or the
  // reader applies a filter to a table they cannot see.
  initTable(() => {
    show("queue");
    applyOwnerFilters();
  });
  initDetail();
  initCVEDetail(cveGroup);
  // Rendered on switch as well as on load: aggregating every CVE across the estate is
  // wasted work for a reader who never opens the view.
  // Switching view re-renders from the filtered set rather than re-fetching or
  // re-filtering: the filter bar governs the page, so a tab change is a change of
  // presentation only.
  initTabs(() => renderCurrentView());
  initConfig();
  $("#groupRows").addEventListener("change", applyOwnerFilters);
  $("#onlyActionable").addEventListener("change", loadFindings);
  $("#showSuppressed").addEventListener("change", loadFindings);
  // Every facet through one wiring: they are multi-select now, so "which control
  // changed" no longer decides anything - each change re-filters and repopulates the
  // rest, which is what faceting means.
  wireFacets(applyOwnerFilters);
  $("#onlyFixable").addEventListener("change", applyOwnerFilters);
  // Debounced, because every keystroke re-filters the estate, rebuilds the facets and
  // redraws the table. On the CVE view that measured about a second per character, so
  // typing a service name froze the page for as long as it took to type it. 120ms is
  // below the point a reader notices a delay and above the gap between keystrokes.
  $("#search").addEventListener("input", debounce(applyOwnerFilters, 120));
  // The header owns the refresh control and knows when an assessment finishes;
  // this page owns what to reload when it does. Wiring it the other way round put
  // polling logic in three page scripts and let two of them drift.
  document.addEventListener("pw:assessed", () => loadAll());
  document.addEventListener("pw:assessing", (e) => renderFreshness(/** @type {any} */ (e).detail));

  initCSV();
  loadAll();
  // No blind reload on a timer. The header polls the assessment meta every fifteen
  // seconds - a small, revalidated response - and fires pw:assessed when the timestamp
  // changes, which is both sooner than sixty seconds and enormously cheaper: the old
  // interval re-fetched and re-rendered the whole estate whether or not anything had
  // happened, which on a real estate was the single most expensive thing this page did.
}

init();
