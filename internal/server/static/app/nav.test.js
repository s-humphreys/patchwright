// The shared header: where you are, and whether anything is happening.
//
// The two rules worth pinning are that the refresh control is DISABLED rather than
// hidden while an assessment runs, and that the page you are on is marked as such.
// A control that vanishes takes its explanation with it; a nav with no current page
// reads as one run-on line of links.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', {
  url: 'http://x/', pretendToBeVisual: true,
});
globalThis.window = dom.window;
globalThis.document = dom.window.document;
globalThis.HTMLElement = dom.window.HTMLElement;
globalThis.customElements = dom.window.customElements;
globalThis.CustomEvent = dom.window.CustomEvent;

await import('./nav.js');
const { ago } = await import('./util.js');

/** mount puts a header on the page and returns it. */
function mount(page = 'queue') {
  document.body.innerHTML = `<pw-nav page="${page}"></pw-nav>`;
  return document.querySelector('pw-nav');
}

test('the page you are on is marked, so the nav reads as a choice', () => {
  const el = mount('analytics');
  const current = el.querySelectorAll('[aria-current="page"]');
  assert.equal(current.length, 1, 'exactly one destination should be current');
  assert.equal(current[0].getAttribute('href'), '/analytics');
});

test('every page gets the same three destinations', () => {
  const el = mount('tickets');
  const hrefs = [...el.querySelectorAll('.pages a')].map((a) => a.getAttribute('href'));
  assert.deepEqual(hrefs, ['/', '/analytics', '/tickets']);
});

test('a running assessment disables the control rather than hiding it', () => {
  const el = mount();
  const btn = el.querySelector('#refresh');
  assert.equal(btn.disabled, false);

  el.running(true, ' for 2m');
  assert.equal(btn.disabled, true, 'a second assessment must not be requestable');
  assert.ok(btn.offsetParent !== null || btn.isConnected, 'the button must stay on the page');
  assert.match(btn.className, /is-running/, 'and say that something is happening');
  assert.match(btn.title, /2m/, 'the tooltip should say how long it has been going');

  el.running(false);
  assert.equal(btn.disabled, false);
  assert.doesNotMatch(btn.className, /is-running/);
});

test('clicking while an assessment runs does nothing', () => {
  // Belt and braces: disabled already stops the click, but refresh() is also
  // reachable from the poll and from other pages.
  const el = mount();
  let posts = 0;
  globalThis.fetch = async () => { posts++; return { json: async () => ({}) }; };
  el.running(true);
  el.refresh();
  assert.equal(posts, 0, 'a second assessment was requested while one was running');
});

test('the busy state is announced, not only drawn', () => {
  const el = mount();
  el.running(true);
  assert.equal(el.getAttribute('aria-busy'), 'true');
  el.running(false);
  assert.equal(el.getAttribute('aria-busy'), 'false');
});

test('ago says how long ago, because that is the question being asked', () => {
  const now = Date.parse('2026-08-30T12:00:00Z');
  assert.match(ago('2026-08-30T11:56:00Z', now), /4 minutes ago/);
  assert.match(ago('2026-08-29T12:00:00Z', now), /yesterday|1 day ago/);
  assert.equal(ago('not a date', now), '', 'an unparseable timestamp should render nothing');
});
