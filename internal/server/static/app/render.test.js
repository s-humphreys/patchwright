// Tests for the page's rendering, run with `npm test` (node --test + jsdom).
//
// These exist because of two bugs that shipped invisibly: a duplicate `title` key
// that silently overrode a column's hover text, and a CSS class used before it
// existed. Both are the same failure — nothing was asserting what the page renders.
//
// The assertions below are deliberately about meaning rather than markup: the point
// is that absent data never renders as good news.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>');
globalThis.document = dom.window.document;
globalThis.window = dom.window;
// The modules read the page's globals the way a browser provides them, so the test
// environment has to provide the same ones rather than the modules taking a document
// parameter they would never be given in production.
globalThis.location = dom.window.location;
globalThis.history = dom.window.history;

const { signalsCell } = await import('./badges.js');
const { riskCell, upgradeCell, upgradeText } = await import('./cells.js');
const { FINDING_COLUMNS } = await import('./table.js');
const { dataGaps, shortReason } = await import('./panels.js');

/** A finding with nothing notable: assessed, internal, no upgrade. */
function finding(over = {}) {
  return {
    image: 'reg/app:1', repository: 'app', registry: 'reg',
    counts: { critical: 0, high: 0 }, provider_assessed: true,
    scanned: true, exploit_checked: true, remediation_checked: true,
    exposure: 'internal', signals: [], vulns: [], in_flight_checked: true,
    ...over,
  };
}

// The rendered text, not the hover text: several titles mention the word "internal"
// while asserting the opposite, so matching anywhere in the markup proves nothing.
const shown = (html) => html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();

test('unknown exposure never renders as internal', () => {
  const unknown = shown(signalsCell(finding({ exposure: 'unknown' })));
  assert.match(unknown, /\?/);
  assert.doesNotMatch(unknown, /internal/);

  const internal = shown(signalsCell(finding({ exposure: 'internal' })));
  assert.match(internal, /internal/);
});

test('an exposed finding shows the badge and no internal claim', () => {
  const html = shown(signalsCell(finding({ exposure: 'public', signals: ['exposed'] })));
  assert.match(html, /exposed/);
  assert.doesNotMatch(html, /internal/);
});

test('a stale pull request links to itself and reports its age', () => {
  const html = signalsCell(finding({
    signals: ['in-flight', 'stale-fix'],
    in_flight: { repository: 'app', title: 'Update x', open_days: 340, exact: true, stale: true,
                 url: 'https://example.com/pr/1' },
  }));
  assert.match(html, /pr 340d/);
  assert.match(html, /stale/);
  assert.match(html, /href="https:\/\/example.com\/pr\/1"/);
});

test('an unmatchable image says so rather than showing an absence', () => {
  const html = signalsCell(finding({ in_flight_reason: 'image records no build repository label' }));
  assert.match(html, /unmatchable/);
});

test('risk is "?" when nothing checked and "-" when checked but unscored', () => {
  assert.match(riskCell(finding({ exploit_checked: false })), /\?/);
  assert.match(riskCell(finding({ exploit_checked: true, vulns: [] })), /-/);
  assert.match(riskCell(finding({ vulns: [{ id: 'CVE-1', risk_score: 812.5 }] })), /813|812/);
});

test('an unresolved upgrade renders as unknown, not as "no upgrade"', () => {
  const f = finding({ upgrade: { kind: 'base', resolved: false, reason: 'registry unreadable' } });
  assert.equal(upgradeText(f), '?');
});

test('a managed upgrade leads with who owns the version', () => {
  const html = upgradeCell(finding({
    upgrade: { kind: 'image', name: 'ghcr.io/x/y', current: 'v1', latest: '2', available: true,
               resolved: true, actionable: false, managed: 'helm', manager: 'y-0.33.0' },
  }));
  // The owner badge comes before the kind badge: the tag is not where the change goes.
  assert.ok(html.indexOf('helm') < html.indexOf('image'), html);
  assert.match(html, /y-0\.33\.0/);
});

test('every column declares each key once', () => {
  // A duplicate key in an object literal silently wins, which is how upgradeTitle
  // stopped rendering for weeks.
  for (const col of FINDING_COLUMNS) {
    const keys = Object.keys(col);
    assert.equal(new Set(keys).size, keys.length, `duplicate key in column ${col.label}`);
  }
});

test('every column can render and sort a bare finding', () => {
  // Guards against a column reaching into a field that may be absent: half these
  // fields are optional in the API by design.
  for (const col of FINDING_COLUMNS) {
    assert.doesNotThrow(() => col.get(finding()), `column ${col.label} get`);
    if (col.sort) assert.doesNotThrow(() => col.sort(finding()), `column ${col.label} sort`);
  }
});

test('a dominant blocker is named in the headline, not hidden behind the toggle', () => {
  const gaps = dataGaps({
    provider_assessed: 600, provider_unassessed: 0, scanned: 600, exploit_checked: 600,
    remediation_unresolved: 500,
    remediation_blockers: [{ reason: 'read image config: POST https://x UNAUTHORIZED: auth required', findings: 497 }],
  });
  const headline = gaps.map((g) => g.headline).join(' ');
  assert.match(headline, /cannot authenticate to the registry/);
});

test('no scan is a severe gap, because whole priority tiers cannot fire', () => {
  const gaps = dataGaps({ provider_assessed: 10, provider_unassessed: 0, scanned: 0, exploit_checked: 0 });
  assert.ok(gaps.some((g) => g.severe && /scanned/.test(g.headline)), JSON.stringify(gaps));
});

test('shortReason keeps a dotted label key intact', () => {
  assert.equal(shortReason('image records no base image'), 'image records no base image');
  assert.match(shortReason('POST https://x UNAUTHORIZED: authentication required'),
    /cannot authenticate/);
});

test('a stale link does not silently filter the queue to nothing', async () => {
  // A shared link naming a team that has gone away, or a signal nothing carries
  // today, must leave the filter unset. A filter matching nothing looks exactly like
  // an empty queue, which is the wrong thing for a stale link to do to somebody.
  const { readURL } = await import('./urlstate.js');
  document.body.innerHTML = `
    <select id="teamFilter"><option value="">all</option><option value="sre">sre</option></select>
    <input id="search"><input type="checkbox" id="onlyActionable" checked>`;
  dom.reconfigure({ url: 'http://x/?team=gone&q=nats' });
  globalThis.location = dom.window.location;
  readURL();
  assert.equal(document.querySelector('#teamFilter').value, '', 'unknown team was applied');
  assert.equal(document.querySelector('#search').value, 'nats', 'free text should apply');
});
