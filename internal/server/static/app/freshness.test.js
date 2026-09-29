// After a restart with a history store, the page serves the previous process's
// assessment until this one's first run completes. Its age alone reads as a slow
// refresh, so the freshness line has to say what it is.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body>' +
  '<span id="version"></span><span id="freshness"></span>' +
  '</body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;

const { renderFreshness } = await import('./panels.js');
const line = () => document.querySelector('#freshness');
const minutesAgo = (n) => new Date(Date.now() - n * 60_000).toISOString();

test('an assessment this process ran says only its age', () => {
  renderFreshness({ generated_at: minutesAgo(3), running: false, version: 'v1' });
  assert.match(line().textContent, /^assessed /);
  assert.doesNotMatch(line().textContent, /restart/);
});

test('an assessment loaded from the store says it is held over from before a restart', () => {
  renderFreshness({ generated_at: minutesAgo(40), running: false, version: 'v1', loaded_from_store: true });
  assert.match(line().textContent, /^assessed .* · kept from before a restart$/);
  assert.match(line().title, /stored by the previous process/);
});

test('while the first run is in flight, both facts are stated', () => {
  renderFreshness({
    generated_at: minutesAgo(40), started_at: minutesAgo(1), running: true, version: 'v1', loaded_from_store: true,
  });
  assert.match(line().textContent, /kept from before a restart · reassessing/);
});

test('a failed refresh is stated beside the age of what is still served, not instead of it', () => {
  renderFreshness({
    generated_at: minutesAgo(40), running: false, version: 'v1', loaded_from_store: true, error: 'provider unreachable',
  });
  assert.match(line().textContent, /^assessed .* · kept from before a restart · last refresh failed: provider unreachable$/);
  assert.equal(line().className, 'meta err');
});

test('a failure with nothing to serve is the whole line', () => {
  renderFreshness({ generated_at: '0001-01-01T00:00:00Z', running: false, version: 'v1', error: 'provider unreachable' });
  assert.equal(line().textContent, 'last refresh failed: provider unreachable');
});
