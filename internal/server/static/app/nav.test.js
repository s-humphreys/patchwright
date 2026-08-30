// The shared header: where you are, and whether anything is happening.
//
// The two rules worth pinning are that the refresh control is DISABLED rather than
// hidden while an assessment runs, and that the page you are on is marked as such.
// A control that vanishes takes its explanation with it; a nav with no current page
// reads as one run-on line of links.
import { after, test } from 'node:test';
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
  const el = document.querySelector('pw-nav');
  // The header polls from the moment it connects, which is the point of it. In a
  // test that interval would keep the process alive forever, so each mount starts
  // from a stopped one and the last is torn down below.
  el.stop();
  return el;
}

// Removing the element fires disconnectedCallback, which stops its polling. Without
// this the suite hangs after the last assertion passes.
after(() => { document.body.innerHTML = ''; });

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

test('an assessment somebody else started puts this page into the same state', () => {
  // An assessment is a property of the SERVER, not of the tab that asked for it.
  // Two people watching the same run must both be told, or the one who did not
  // start it can start a second.
  const el = mount();
  const btn = el.querySelector('#refresh');
  assert.equal(btn.disabled, false);

  el.observe({ running: true, started_at: new Date().toISOString() });
  assert.equal(btn.disabled, true, 'a run started elsewhere must disable this control too');
  assert.match(btn.className, /is-running/);
  el.stop();
});

test('finishing fires once, not on every idle poll', () => {
  // pw:assessed reloads the page it reaches. Firing it whenever the server happens
  // to be idle would reload every open page every fifteen seconds.
  const el = mount();
  let reloads = 0;
  document.addEventListener('pw:assessed', () => reloads++);

  el.observe({ running: false });
  assert.equal(reloads, 0, 'idle is not a completion');

  el.observe({ running: true, started_at: new Date().toISOString() });
  el.observe({ running: false });
  assert.equal(reloads, 1, 'a run that has just finished should reload once');

  el.observe({ running: false });
  assert.equal(reloads, 1, 'and not again while it stays idle');
  el.stop();
});

test('a failed poll leaves the state alone rather than re-enabling', async () => {
  // Re-enabling on a network blip invites a second run against a server already
  // doing one.
  // The failing fetch is installed BEFORE the state is set: observe() re-polls
  // immediately when it changes speed, so a stub installed afterwards would answer
  // that first poll instead of the one under test.
  globalThis.fetch = async () => { throw new Error('network'); };
  const el = mount();
  el.observe({ running: true, started_at: new Date().toISOString() });
  el.stop();

  await el.check();
  assert.equal(el.querySelector('#refresh').disabled, true,
    'a failed poll is not a finished assessment');
  el.stop();
});
