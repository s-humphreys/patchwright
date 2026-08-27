import { initialQuery, readURL } from './urlstate.js';
import { initConfig } from './config.js';
import { renderCoverage, renderDataAge, renderFreshness, renderTiles } from './panels.js';
import { groupByKey, initCVEDetail, initDetail, openCVEDetail, openDetail, openFromURL, openGroupDetail, shownCVE, shownGroup, shownImage } from './detail.js';
import { cveGroup, renderCVEs } from './cves.js';
import { current as currentView, initTabs } from './tabs.js';
import { initPending, loadPending } from './pending.js';
import { applyOwnerFilters, loadFindings, populateOwnerFilters } from './queue.js';
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
    if (currentView() === "cves") renderCVEs(S.queueRows);
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
    // Once per load, not per poll: see loadPending.
    loadPending();
  } catch (e) {
    $("#freshness").textContent = `error: ${e.message}`;
    $("#freshness").className = "meta err";
  }
}

// init wires every listener and starts the poll. Nothing runs at import time, so a
// module can be imported by a test without a page to attach to.
export function init() {
  initTable();
  initDetail();
  initCVEDetail(cveGroup);
  // Rendered on switch as well as on load: aggregating every CVE across the estate is
  // wasted work for a reader who never opens the view.
  initTabs((view) => { if (view === "cves") renderCVEs(S.queueRows); });
  initConfig();
  initPending();
  $("#groupRows").addEventListener("change", applyOwnerFilters);
  $("#onlyActionable").addEventListener("change", loadFindings);
  $("#showSuppressed").addEventListener("change", loadFindings);
  $("#classFilter").addEventListener("change", () => {
  // Team options depend on the chosen class, so rebuild them before filtering.
  populateOwnerFilters(S.queueRows);
  applyOwnerFilters();
});
  $("#teamFilter").addEventListener("change", applyOwnerFilters);
  $("#fixFilter").addEventListener("change", applyOwnerFilters);
  $("#signalFilter").addEventListener("change", applyOwnerFilters);
  $("#onlyFixable").addEventListener("change", applyOwnerFilters);
  $("#search").addEventListener("input", applyOwnerFilters);
  $("#refresh").addEventListener("click", async () => {
  await fetch("/api/v1/assessments", { method: "POST" });
  // The refresh is asynchronous, so poll until the server stops reporting it.
  const poll = setInterval(async () => {
    const s = await get("/api/v1/summary");
    if (!s.assessment?.running) { clearInterval(poll); loadAll(); }
    else renderFreshness(s.assessment);
  }, 2000);
});

  loadAll();
  setInterval(loadAll, 60000);
}

init();
