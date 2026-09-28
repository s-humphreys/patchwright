// Operator-chosen images: the version is the operator's choice, so "no upgrade" must
// not read as "already current", and an operator's chart upgrade must read as the
// operator's move rather than the image's.
import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";

const dom = new JSDOM(`<!doctype html><html><body></body></html>`);
globalThis.window = /** @type {any} */ (dom.window);
globalThis.document = dom.window.document;

const { fixPath, upgradeCell, upgradeText, upgradeTitle } = await import("./cells.js");

const reason = "version chosen by the operator that reconciles EventBus/argo-events/cpo; " +
  "which operator that is could not be determined, so its upgrade could not be resolved";

function finding(upgrade) {
  return { image: "docker.io/nats:2.10.29", upgrade, remediation_checked: true };
}

test("no operator upgrade says whose choice the version is, not that it is current", () => {
  const f = finding({
    kind: "image", current: "2.10.29", resolved: true, available: false,
    managed: "operator", source: "EventBus/argo-events/cpo", operator_chosen: true, reason,
  });
  assert.equal(fixPath(f), "none");
  assert.notEqual(upgradeText(f), "-");
  assert.match(upgradeText(f), /operator/);
  const title = upgradeTitle(f);
  assert.ok(title.includes(reason), title);
  assert.doesNotMatch(title, /latest available version/);
});

test("an ordinary image with no upgrade is still current", () => {
  const f = finding({ kind: "image", current: "1.0.0", resolved: true, available: false });
  assert.equal(upgradeText(f), "-");
  assert.match(upgradeTitle(f), /latest available version/);
});

test("a controller that moves with its operator shows no tag of its own", () => {
  const f = finding({
    kind: "image", current: "v1.6.0", resolved: true, available: true, actionable: false,
    managed: "operator", manager: "flux-operator", operator_chosen: true,
  });
  assert.equal(fixPath(f), "managed");
  assert.doesNotMatch(upgradeText(f), /→/);
  assert.match(upgradeCell(f), /moves with its operator/);
});

test("an operator's chart upgrade leads with the operator", () => {
  const html = upgradeCell(finding({
    kind: "chart", name: "argo-events", current: "2.4.15", latest: "2.4.16",
    resolved: true, available: true, actionable: true,
    managed: "operator", manager: "argo-events", operator_chosen: true, image_current: "2.10.29",
  }));
  assert.ok(html.indexOf("operator") < html.indexOf("chart"), html);
  assert.match(html, /argo-events/);
});
