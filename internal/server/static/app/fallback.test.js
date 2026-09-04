// A fallback scan replaces "?" with real numbers. The rendering has one job beyond
// showing them: never let a reader compare them against the provider's counts in the
// same column without knowing they came from a different scanner.
import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";

const dom = new JSDOM(`<!doctype html><html><body></body></html>`);
globalThis.window = /** @type {any} */ (dom.window);
globalThis.document = dom.window.document;

const { count, SIGNAL_ORDER, SIGNAL_BADGES } = await import("./badges.js");
const { severityCell } = await import("./cells.js");
const { dataGaps } = await import("./panels.js");

const unassessed = { provider_assessed: false, counts: { critical: 12, high: 3 } };
const fallback = { ...unassessed, fallback_scanned: true, counts_source: "trivy" };

test('an unassessed image with no fallback still reads "?"', () => {
  assert.equal(count(unassessed, "critical"), "?");
  assert.match(severityCell(unassessed), /\?/);
});

test("a fallback count is shown, and marked as not the provider's", () => {
  assert.equal(count(fallback, "critical"), "12~");
  const cell = severityCell(fallback);
  assert.match(cell, /12C/);
  assert.match(cell, /~/, "an unmarked number would be read as the provider's");
  assert.match(cell, /trivy/, "the tooltip should name the source of the numbers");
});

test("zero from a fallback scan is a real zero, not a question mark", () => {
  const clean = { ...fallback, counts: {} };
  assert.equal(count(clean, "critical"), "0~");
  assert.match(severityCell(clean), /0/);
});

test("the fallback badge exists and sits beside unassessed", () => {
  assert.ok(SIGNAL_BADGES["fallback-scan"], "a signal with no badge renders as a bare string");
  assert.equal(
    SIGNAL_ORDER.indexOf("fallback-scan") - SIGNAL_ORDER.indexOf("unassessed"), 1,
    "it only ever appears with unassessed, so it belongs next to it");
});

test("the provider gap is still reported when a fallback covered part of it", () => {
  const gaps = dataGaps({
    provider_assessed: 643, provider_unassessed: 6, actionable: 10,
    fallback_scanned: 5, fallback_failed: 1, uncovered: 1, scanned: 500, exploit_checked: 500,
    fallback_failures: [{ reason: "UNAUTHORIZED", findings: 1 }],
  });
  const provider = gaps.find((g) => g.headline.includes("never assessed by the scan provider"));
  assert.ok(provider, "the provider gap must not disappear because something compensated");
  assert.match(provider.count, /6 of 649/);
  assert.match(provider.detail, /fallback scanner supplied counts for 5/);

  const residual = gaps.find((g) => g.headline.includes("could not cover"));
  assert.ok(residual, "the residual gap needs its own line");
  assert.match(residual.count, /1 of 6/);
});

test("no residual line when no fallback ran at all", () => {
  const gaps = dataGaps({
    provider_assessed: 643, provider_unassessed: 6, actionable: 10,
    uncovered: 6, scanned: 500, exploit_checked: 500,
  });
  assert.equal(gaps.filter((g) => g.headline.includes("could not cover")).length, 0,
    "without a fallback, uncovered is just provider_unassessed said twice");
});
