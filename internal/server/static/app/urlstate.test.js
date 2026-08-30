// A shared link must survive the page rendering itself.
//
// It did not: the controls reflect themselves into the address bar on the first
// render, and writeURL rebuilt the query from the controls alone — so a link carrying
// ?service=…&team=… had those parameters deleted before anything read them. The panel
// never opened and the URL reset itself, which is exactly what somebody clicking a
// ticket link saw.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const url = 'http://x/?q=topno&fixable=true&service=storefront&team=data-platform';
const dom = new JSDOM(`<!doctype html><html><body>
  <details class="ms" id="classFilter"><summary></summary><div class="ms-menu"></div></details>
  <details class="ms" id="teamFilter"><summary></summary><div class="ms-menu">
    <label class="ms-opt"><input type="checkbox" value="data-platform"><span>data-platform</span></label>
  </div></details>
  <details class="ms" id="fixFilter"><summary></summary><div class="ms-menu"></div></details>
  <details class="ms" id="signalFilter"><summary></summary><div class="ms-menu"></div></details>
  <input id="search">
  <input type="checkbox" id="onlyFixable">
  <input type="checkbox" id="onlyActionable" checked>
  <input type="checkbox" id="showSuppressed">
  <input type="checkbox" id="groupRows" checked>
</body></html>`, { url });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;
globalThis.history = dom.window.history;

const { initialQuery, readURL, writeURL } = await import('./urlstate.js');

test('the arriving link is remembered even after the page rewrites the URL', () => {
  // The first render writes the controls into the address bar, and the panel
  // parameters survive it — that is the fix.
  writeURL();
  assert.match(location.search, /service=storefront/,
    'writeURL must not delete a parameter it does not own');
  // And the link the page was opened with is readable regardless of what has been
  // written since.
  const arrived = initialQuery();
  assert.equal(arrived.get('service'), 'storefront');
  assert.equal(arrived.get('team'), 'data-platform');
  assert.equal(arrived.get('q'), 'topno');
});

test('filters from the link are applied, not discarded', () => {
  const changed = readURL();
  assert.equal(changed, true);
  assert.equal(document.querySelector('#search').value, 'topno');
  assert.equal(document.querySelector('#onlyFixable').checked, true);
  assert.equal(document.querySelector('#teamFilter input[value=data-platform]').checked, true);
});

test('writeURL preserves parameters that belong to something else', () => {
  history.replaceState(null, '', '?service=storefront&view=cves');
  document.querySelector('#search').value = 'nats';
  writeURL();
  const now = new URLSearchParams(location.search);
  assert.equal(now.get('q'), 'nats', 'the control it owns is written');
  assert.equal(now.get('service'), 'storefront', 'the panel parameter survives');
  assert.equal(now.get('view'), 'cves', 'so does the view');
});

test('clearing a control removes its parameter rather than leaving a stale one', () => {
  history.replaceState(null, '', '?q=nats&service=storefront');
  document.querySelector('#search').value = '';
  writeURL();
  const now = new URLSearchParams(location.search);
  assert.equal(now.has('q'), false);
  assert.equal(now.get('service'), 'storefront');
});
