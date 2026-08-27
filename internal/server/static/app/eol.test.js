// End-of-life rendering: the three states, and the one that must never be silent.
import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";

const dom = new JSDOM(`<!doctype html><html><body></body></html>`);
globalThis.window = /** @type {any} */ (dom.window);
globalThis.document = dom.window.document;

const { upgradeText, upgradeCell, endOfLifeStatus, supportWhy } = await import("./cells.js");
const { SIGNAL_ORDER, SIGNAL_WEIGHT, SIGNAL_BADGES } = await import("./badges.js");

const deadNode = {
  product: "nodejs", cycle: "20", eol: "2026-04-30",
  known: true, supported: false,
  recommended: "24", nearest: "22", newest: "26", source: "endoflife.date",
};

function finding(upgrade) {
  return { image: "reg/app:1", upgrade, remediation_checked: true };
}

test("a dead line with no target never renders as a dash", () => {
  // "-" means "you are already current". Here it would mean "nothing will ever fix
  // this", and the entire point of carrying support status is that those two cells
  // must not look identical.
  const text = upgradeText(finding({
    kind: "base", resolved: true, available: false,
    support: { ...deadNode, recommended: "", nearest: "", newest: "" },
  }));
  assert.notEqual(text, "-");
  assert.match(text, /end of life/i);
});

test("a dead line names the move when there is one", () => {
  const text = upgradeText(finding({
    kind: "base", resolved: true, available: false, support: deadNode,
  }));
  assert.match(text, /move to nodejs 24/);
});

test("an out-of-track upgrade is labelled a migration, not a bump", () => {
  const html = upgradeCell(finding({
    kind: "base", name: "docker.io/node", current: "20-alpine", latest: "24-alpine",
    resolved: true, available: true, actionable: true, out_of_track: true, support: deadNode,
  }));
  assert.match(html, /major/, "an out-of-track move must be marked as such");
  assert.match(html, /24-alpine/);
});

test("an unchecked base is not reported as supported, and not as end of life either", () => {
  // The failure this guards: rendering absence as either verdict. No support block at
  // all, and a block that says known=false, are both "we did not look".
  for (const support of [undefined, { known: false, supported: false, product: "nodejs", cycle: "20" }]) {
    const u = { kind: "base", resolved: true, available: false, support };
    assert.equal(endOfLifeStatus(u), null, "unchecked must not count as end of life");
    assert.equal(upgradeText(finding(u)), "-", "unchecked keeps the ordinary no-upgrade rendering");
  }
});

test("a supported line is not flagged", () => {
  const u = {
    kind: "base", resolved: true, available: false,
    support: { product: "nodejs", cycle: "24", eol: "2028-04-30", known: true, supported: true },
  };
  assert.equal(endOfLifeStatus(u), null);
  assert.equal(supportWhy(u), "");
});

test("the hover attributes the claim and dates it", () => {
  // An unattributed claim that somebody's runtime is dead starts an argument. A dated
  // one from a named source starts a rebuild.
  const why = supportWhy({ support: deadNode });
  assert.match(why, /2026-04-30/);
  assert.match(why, /endoflife\.date/);
  assert.match(why, /24/);
});

test("end of life outranks kev in the signal order", () => {
  // A KEV is one exploited CVE a rebuild closes today. A dead line is every future CVE
  // with no rebuild that closes any of them, so burying it under KEV would sort the
  // compounding problem below the immediate one.
  assert.ok(SIGNAL_ORDER.indexOf("end-of-life") < SIGNAL_ORDER.indexOf("kev"));
  assert.ok(SIGNAL_WEIGHT["end-of-life"] > SIGNAL_WEIGHT.kev);
  assert.ok(SIGNAL_BADGES["end-of-life"], "the signal needs a badge or it renders as a bare string");
});

test('a ceiling inside a dead line says so, and does not pretend to a fix', async () => {
  // Individually unremarkable facts: policy holds this at 3.12, and 3.12 is finished.
  // Together they are the finding, and the resolver deliberately will not step past the
  // constraint - so the page has to say a person must lift it.
  const { upgradeStrategyWhy } = await import("./cells.js");
  const why = upgradeStrategyWhy({
    ceiling: "3.12", rule: "docker.io/python", ceiling_reason: "deps not ready",
    newest: "3.14.7", held_back: true, available: false,
    support: {
      product: "python", cycle: "3.12", eol: "2026-01-01",
      known: true, supported: false, recommended: "3.14", source: "endoflife.date",
    },
  });
  assert.match(why, /docker\.io\/python/, "the deciding rule must be named");
  assert.match(why, /no longer maintained/);
  assert.match(why, /ceiling lifted first/, "the reader needs to know what unblocks it");
});
