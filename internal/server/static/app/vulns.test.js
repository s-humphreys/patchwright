// The queue no longer carries per-CVE detail: on a real estate it was 97% of the
// payload and none of what the queue draws. These cover what that trade must not
// break - an absent CVE list never reading as an empty one, and a failed load never
// turning into a loop of requests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body>' +
  '<table id="findings"><thead><tr></tr></thead><tbody></tbody></table>' +
  '<table id="cves"><thead><tr></tr></thead><tbody></tbody></table>' +
  '<aside id="detail" hidden></aside>' +
  '<span id="queueCount"></span>' +
  '<input id="onlyActionable" type="checkbox"><input id="showSuppressed" type="checkbox">' +
  '</body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;
globalThis.history = dom.window.history;

const { ensureVulns, resetVulns, retryVulns, vulnState } = await import('./vulns.js');
const { S } = await import('./state.js');
const { openDetail, closeDetail } = await import('./detail.js');

// Every fetch is stubbed: these are about the state machine, not the network.
let calls = 0;
/** @type {string[]} */
let urls = [];
/** @type {(url: string) => Promise<any>} */
let responder = async () => ({ findings: [] });
globalThis.fetch = async (url) => {
  calls++;
  urls.push(String(url));
  const body = await responder(String(url));
  return { ok: true, json: async () => body };
};

// The two endpoints in play: the whole set for the CVE view, one image for a panel.
const respondWith = (vulns) => async (url) => (url.includes("/api/v1/finding?image=")
  ? { finding: { image: "reg/app:1.0.0", vulns } }
  : { findings: [{ image: "reg/app:1.0.0", vulns }] });

function setUp() {
  calls = 0;
  urls = [];
  S.assessedAt = '2026-08-31T09:00:00Z';
  S.queueRows = [];
  S.vulnError = undefined;
  resetVulns();
  closeDetail();
}

function summaryRow(over = {}) {
  // What the API returns with vulns=false: aggregates, no arrays.
  return {
    image: 'reg/app:1.0.0', repository: 'app', owner: { team: 'orders' },
    counts: { critical: 2 }, provider_assessed: true, scanned: true,
    exploit_checked: true, vuln_count: 3, top_epss: 0.91, top_epss_percentile: 0.99,
    top_risk_score: 812, known_exploited: true, signals: [], reasons: [],
    dimensions: {}, ...over,
  };
}

test('detail is absent until something asks for it, then present', async () => {
  setUp();
  S.queueRows = [summaryRow()];
  assert.equal(vulnState(), 'absent', 'summary rows carry no CVEs');

  responder = respondWith([{ id: 'CVE-1' }]);
  let settled = 0;
  assert.equal(ensureVulns(() => settled++), 'loading');
  await new Promise((r) => setTimeout(r, 0));

  assert.equal(vulnState(), 'ready');
  assert.equal(settled, 1, 'the caller is told once, when it lands');
  assert.deepEqual(S.queueRows[0].vulns, [{ id: 'CVE-1' }], 'merged into the row on the page');
});

// The merge has to reach the object the panel is holding. Replacing the array would
// leave an open panel rendering a copy nothing updates.
test('detail merges into the existing row objects', async () => {
  setUp();
  const row = summaryRow();
  S.queueRows = [row];
  responder = respondWith([{ id: 'CVE-9' }]);
  ensureVulns();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(row.vulns[0].id, 'CVE-9', 'the same object the queue and panel share');
});

test('one load serves every caller', async () => {
  setUp();
  S.queueRows = [summaryRow()];
  responder = respondWith([]);
  let settled = 0;
  ensureVulns(() => settled++);
  ensureVulns(() => settled++);
  ensureVulns(() => settled++);
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls, 1, 'three askers, one request');
  assert.equal(settled, 3, 'all three told');
});

// The regression. A failed load left the state indistinguishable from never-tried, so
// the caller repainting itself asked again immediately, forever.
test('a failed load does not retry itself', async () => {
  setUp();
  S.queueRows = [summaryRow()];
  responder = async () => {
    throw new Error('gateway timeout');
  };
  ensureVulns();
  await new Promise((r) => setTimeout(r, 0));

  assert.equal(vulnState(), 'failed');
  assert.equal(S.vulnError, 'gateway timeout', 'the reason is kept, to be rendered');

  // What the repainting caller does next. It must not start another request.
  for (let i = 0; i < 5; i++) assert.equal(ensureVulns(() => {}), 'failed');
  assert.equal(calls, 1, 'a failure is reported, not hammered');

  // Only an explicit retry tries again.
  responder = async () => ({ findings: [] });
  retryVulns();
  assert.equal(ensureVulns(), 'loading');
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls, 2);
});

// The state machine must not call back synchronously: a caller whose callback
// repaints would re-enter it mid-decision.
test('the callback never runs before the caller returns', async () => {
  setUp();
  S.queueRows = [summaryRow()];
  responder = async () => ({ findings: [] });
  let ranSynchronously = true;
  ensureVulns(() => {
    ranSynchronously = false;
  });
  assert.equal(ranSynchronously, true, 'nothing ran during the call itself');
  await new Promise((r) => setTimeout(r, 0));
});

test('a new assessment invalidates loaded detail', async () => {
  setUp();
  S.queueRows = [summaryRow()];
  responder = respondWith([{ id: 'CVE-1' }]);
  ensureVulns();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(vulnState(), 'ready');

  // The hourly refresh replaced the findings. Last hour's CVEs describe findings that
  // may no longer exist, so they must not be treated as this hour's.
  S.assessedAt = '2026-08-31T10:00:00Z';
  S.queueRows = [summaryRow()];
  assert.equal(vulnState(), 'absent');
});

// A caller that fetched findings WITH their CVEs has nothing to wait for. Gating on
// "did this module run" would leave it waiting for data it is already holding.
test('rows that already carry CVEs count as loaded', () => {
  setUp();
  S.queueRows = [summaryRow({ vulns: [{ id: 'CVE-1' }] })];
  assert.equal(vulnState(), 'ready');
});

// The worst sentence this page could produce over an image carrying four hundred CVEs.
test('a panel opened before detail arrives says it is waiting, not that there are none', async () => {
  setUp();
  const row = summaryRow();
  S.queueRows = [row];
  responder = async () => new Promise(() => {}); // never settles

  openDetail(row);
  const text = document.querySelector('#detail').textContent;
  assert.match(text, /Loading 3 CVEs/, 'says what it is waiting for, and how many');
  assert.doesNotMatch(text, /no CVEs were found/);
});

test('a panel says why detail could not be loaded rather than showing nothing', async () => {
  setUp();
  const row = summaryRow();
  S.queueRows = [row];
  responder = async () => {
    throw new Error('502 bad gateway');
  };
  openDetail(row);
  await new Promise((r) => setTimeout(r, 0));

  const text = document.querySelector('#detail').textContent;
  assert.match(text, /could not be loaded: 502 bad gateway/);
  assert.match(text, /has 3 CVEs/, 'the count is known even when the list is not');
});

// The panel repaints itself when the detail lands, so a reader who clicked early does
// not have to click again.
test('an open panel fills in when detail arrives', async () => {
  setUp();
  const row = summaryRow();
  S.queueRows = [row];
  responder = respondWith([{ id: 'CVE-7', severity: 'critical', cvss: 9.8, epss: 0.91, kev: true }]);

  openDetail(row);
  assert.match(document.querySelector('#detail').textContent, /Loading/);
  await new Promise((r) => setTimeout(r, 0));
  assert.match(document.querySelector('#detail').textContent, /CVE-7/,
    'the panel the reader is looking at now shows the CVEs');
});

// A finding nobody scanned has no CVEs to wait for, and saying "loading" forever over
// one would be a different kind of lie.
test('an unscanned image still says why it has no CVE detail', () => {
  setUp();
  const row = summaryRow({ scanned: false, vuln_count: 0 });
  S.queueRows = [row];
  openDetail(row);
  const text = document.querySelector('#detail').textContent;
  assert.match(text, /was not scanned/);
  assert.doesNotMatch(text, /Loading/);
});

// A panel needs one image's CVEs. The estate's worth of them is 2.6MB compressed, and
// most readers open a panel long before they open the CVE view.
test('opening a panel fetches only that image', async () => {
  setUp();
  const row = summaryRow();
  S.queueRows = [row, summaryRow({ image: 'reg/other:2.0.0' })];
  responder = respondWith([{ id: 'CVE-3' }]);

  openDetail(row);
  await new Promise((r) => setTimeout(r, 0));

  assert.equal(calls, 1, 'one request, not the whole estate');
  assert.match(urls[0], /\/api\/v1\/finding\?image=reg%2Fapp%3A1\.0\.0$/,
    'the single-finding endpoint, with the reference encoded');
  assert.deepEqual(row.vulns, [{ id: 'CVE-3' }]);
  assert.equal(S.queueRows[1].vulns, undefined, 'the row nobody opened was left alone');
});

// Reopening the same panel must not re-fetch what is already there.
test('a second open of the same panel costs nothing', async () => {
  setUp();
  const row = summaryRow();
  S.queueRows = [row];
  responder = respondWith([{ id: 'CVE-3' }]);
  openDetail(row);
  await new Promise((r) => setTimeout(r, 0));
  const after = calls;
  openDetail(row);
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(calls, after, 'no request for detail already on the page');
});

// A work item is typically the same service at two or three tags, and the panel lists
// all of them.
test('opening a work item fetches every deployment in it, once', async () => {
  setUp();
  const rows = [summaryRow(), summaryRow({ image: 'reg/app:1.0.1' })];
  S.queueRows = rows;
  responder = async (url) => ({
    finding: { image: decodeURIComponent(url.split('image=')[1]), vulns: [{ id: 'CVE-5' }] },
  });

  const { ensureDetail } = await import('./vulns.js');
  let settled = 0;
  assert.equal(ensureDetail(rows, () => settled++), false);
  await new Promise((r) => setTimeout(r, 0));

  assert.equal(calls, 2, 'one request per deployment');
  assert.equal(settled, 1, 'the caller is told once, when the last lands');
  assert.ok(rows.every((r) => r.vulns.length === 1));
  assert.equal(ensureDetail(rows), true, 'and now there is nothing to wait for');
});

// A scanned image with no CVEs must end up with an empty array, not stay undefined -
// otherwise the panel says "loading" forever over an image that is genuinely clean.
test('an image with no CVEs stops waiting', async () => {
  setUp();
  const row = summaryRow({ vuln_count: 0 });
  S.queueRows = [row];
  responder = respondWith([]);
  openDetail(row);
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(row.vulns, [], 'scanned and none found is an answer');
  assert.match(document.querySelector('#detail').textContent, /no CVEs were found/);
});
