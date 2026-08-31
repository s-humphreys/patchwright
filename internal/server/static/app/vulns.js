import { S } from './state.js';
import { get } from './util.js';

// Per-CVE detail, loaded only when something actually needs it.
//
// The queue is fetched with `vulns=false`. On a real estate the per-CVE arrays are
// 97% of that payload - 208,697 CVEs against 612 findings, 41MB against 1.3MB - and
// the queue shows none of them: it shows the worst score per image, which the API
// sends as an aggregate. Loading all of it up front meant every reader waited for data
// most of them never looked at, and then waited again every sixty seconds.
//
// So the CVE view, the detail panels and a CVE-view export ask for it here. It is
// fetched once per assessment and merged into the findings already on the page.
//
// Merged into the EXISTING objects rather than replacing them. A panel holds the
// finding it was opened with and the queue holds the same object, so swapping in a
// fresh array would leave the panel rendering a detached copy no refresh reaches.

// The one attempt to load detail, and which assessment it belongs to.
//
// A record rather than a pair of stamps. An earlier version used null both for "never
// tried" and for "the assessment has no timestamp", so a failed load read as
// never-tried and the caller repainting itself retried immediately - an unbounded loop
// of requests against a server that was already failing.
/** @type {{stamp: any, status: 'loading'|'ready'|'failed'}|null} */
let attempt = null;
/** @type {Array<() => void>} */
const waiting = [];

/**
 * vulnState is what a caller renders from: "ready", "loading", "failed" or "absent".
 *
 * Four states rather than a boolean, because a failure and a wait must not look
 * identical on screen: a caller that cannot tell them apart renders an empty CVE
 * table, which reads as an estate with no CVEs.
 * @returns {'ready'|'loading'|'failed'|'absent'}
 */
export function vulnState() {
  // A new assessment invalidates the last attempt: merging last hour's CVEs into this
  // hour's findings would date the answer without saying so.
  if (attempt && attempt.stamp === S.assessedAt) return attempt.status;
  // Otherwise the question is whether the detail is on the page, not whether this
  // module is what put it there. A caller holding findings fetched WITH their CVEs has
  // nothing to wait for, and gating on "did my loader run" would leave it waiting for
  // data it already has.
  return S.queueRows.some((r) => r.vulns !== undefined) ? "ready" : "absent";
}

/** loaded reports whether per-CVE detail is on the page for the current assessment. */
export function loaded() {
  return vulnState() === "ready";
}

/**
 * ensureVulns starts the load if it has not been tried, and registers a callback for
 * when it settles. The callback is how a panel or a table repaints itself: this module
 * knows when the data lands and nothing about what to draw.
 *
 * It does NOT call back synchronously and it does NOT retry a failure. Both were bugs:
 * calling back synchronously made a repainting caller re-enter this function, and
 * retrying a failure turned that re-entry into an unbounded loop of requests.
 *
 * @param {() => void} [then] run once, when the load settles either way
 * @returns {'ready'|'loading'|'failed'|'absent'} the state the caller should render
 */
export function ensureVulns(then) {
  const state = vulnState();
  if (state === "ready" || state === "failed") return state;
  if (then) waiting.push(then);
  if (state === "absent") {
    attempt = { stamp: S.assessedAt, status: "loading" };
    void fetchVulns(S.assessedAt);
  }
  return "loading";
}

/**
 * awaitVulns is ensureVulns for a caller that can wait: an export, rather than a
 * render. Resolves to the settled state.
 * @returns {Promise<'ready'|'failed'>}
 */
export function awaitVulns() {
  return new Promise((resolve) => {
    const state = ensureVulns(() => resolve(vulnState() === "ready" ? "ready" : "failed"));
    if (state === "ready" || state === "failed") resolve(state);
  });
}

/**
 * retryVulns clears a failure so the next ensureVulns tries again. For a reader who
 * asks, never automatically.
 */
export function retryVulns() {
  if (vulnState() === "failed") attempt = null;
  S.vulnError = undefined;
}

/** resetVulns drops loaded detail, for a new assessment. */
export function resetVulns() {
  attempt = null;
  waiting.length = 0;
  perImage.clear();
  S.vulnError = undefined;
}

// Per-image detail, for a panel.
//
// A panel needs the CVEs of one image, and the estate's worth of them is 2.6MB
// compressed. /api/v1/finding?image= answers in a few kilobytes, so opening a row does
// not pay for the CVE view somebody may never look at.
//
// Tracked per image rather than through the single attempt above: these are
// independent requests and one failing says nothing about the others.
/** @type {Map<string, 'loading'|'failed'>} */
const perImage = new Map();

/**
 * ensureDetail loads the CVEs for particular images and calls back when they land.
 *
 * @param {any[]} rows the findings whose detail is wanted, usually one
 * @param {() => void} [then] run once, when the last of them settles
 * @returns {boolean} true when every row already has its detail, so the caller can
 *   render without showing a wait
 */
export function ensureDetail(rows, then) {
  // Whatever put it there - a per-image fetch, or the whole set for the CVE view.
  if (rows.every((r) => r.vulns !== undefined)) return true;
  const wanted = rows.filter((r) => r && r.vulns === undefined && r.image &&
    perImage.get(r.image) !== "loading" && perImage.get(r.image) !== "failed");
  if (!wanted.length) {
    // Either everything asked for is in flight or has failed; the in-flight ones will
    // call back on their own.
    return rows.every((r) => r.vulns !== undefined);
  }
  for (const row of wanted) perImage.set(row.image, "loading");
  void Promise.all(wanted.map((row) => loadOne(row))).then(() => {
    if (then) then();
  });
  return false;
}

async function loadOne(row) {
  try {
    const d = await get("/api/v1/finding?image=" + encodeURIComponent(row.image));
    // Assigned even when empty: an array is "scanned, none found", which is a
    // different answer from the undefined this replaces.
    row.vulns = d.finding?.vulns || [];
    perImage.delete(row.image);
  } catch (e) {
    perImage.set(row.image, "failed");
    S.vulnError = e.message;
  }
}

/** detailFailed reports whether this image's own detail could not be loaded. */
export function detailFailed(image) {
  return perImage.get(image) === "failed";
}

async function fetchVulns(stamp) {
  try {
    // The same server-side toggles the queue was fetched with, so the two describe one
    // population: detail fetched without suppressed findings would silently drop their
    // CVEs from a view showing them.
    const d = await get("/api/v1/findings" + queueQuery());
    merge(d.findings || []);
    attempt = { stamp, status: "ready" };
  } catch (e) {
    // Recorded against this assessment rather than retried. A caller renders the
    // failure, and the next assessment - or an explicit retry - is what tries again.
    attempt = { stamp, status: "failed" };
    S.vulnError = e.message;
  } finally {
    const callbacks = waiting.splice(0);
    for (const cb of callbacks) cb();
  }
}

// queueQuery mirrors the toggles that reach the server. Read from the controls rather
// than imported from queue.js, which already imports this module.
function queueQuery() {
  const params = new URLSearchParams();
  const actionable = /** @type {any} */ (document.querySelector("#onlyActionable"));
  const suppressed = /** @type {any} */ (document.querySelector("#showSuppressed"));
  if (actionable?.checked) params.set("actionable", "true");
  if (suppressed?.checked) params.set("suppressed", "true");
  const q = params.toString();
  return q ? "?" + q : "";
}

/**
 * merge attaches each finding's CVEs to the row already on the page, by image
 * reference - the identity the rest of the page uses for a deployment.
 *
 * A row the response does not mention keeps what it had. A finding that vanished
 * between the two requests means the assessment changed, which the stamp handles.
 * @param {any[]} detailed
 */
function merge(detailed) {
  const byImage = new Map();
  for (const f of detailed) byImage.set(f.image, f.vulns || []);
  for (const row of S.queueRows) {
    const vulns = byImage.get(row.image);
    if (vulns) row.vulns = vulns;
  }
}
