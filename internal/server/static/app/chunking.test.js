// Big tables are drawn in chunks. The CVE view is ten thousand rows, and building them
// in one string measured about a second - paid again on every keystroke.
//
// The thing these protect is that chunking is not truncation: every row still arrives.
// A cap would have been simpler and would have quietly dropped rows from a filtered
// view somebody was about to act on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body>' +
  '<table id="findings"><thead><tr></tr></thead><tbody></tbody></table>' +
  '</body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;

const { renderTable, rendering } = await import('./table.js');

const COLUMNS = [{ label: 'ID', get: (r) => r.id, sort: (r) => r.id }];
const rows = (n) => Array.from({ length: n }, (_, i) => ({ id: `row-${i}`, image: `img-${i}` }));
const count = () => document.querySelectorAll('#findings tbody tr').length;
// The fill defers with setTimeout in this environment; drain it.
const settle = async () => {
  for (let i = 0; i < 200 && rendering('findings'); i++) {
    await new Promise((r) => setTimeout(r, 0));
  }
};

test('a small table is drawn in one go', () => {
  renderTable('findings', COLUMNS, rows(40));
  assert.equal(count(), 40, 'nothing to defer, so nothing is deferred');
  assert.equal(rendering('findings'), false);
});

test('a large table paints immediately and then completes', async () => {
  renderTable('findings', COLUMNS, rows(3000));
  const first = count();
  assert.ok(first > 0 && first < 3000,
    `want a partial first paint, got ${first} of 3000`);
  assert.equal(rendering('findings'), true, 'the rest is still coming');

  await settle();
  assert.equal(count(), 3000, 'every row arrives: chunking is not truncation');
  assert.equal(rendering('findings'), false);
});

test('rows keep their order across chunks', async () => {
  renderTable('findings', COLUMNS, rows(1200));
  await settle();
  const ids = [...document.querySelectorAll('#findings tbody tr')]
    .map((tr) => tr.textContent.trim());
  assert.equal(ids[0], 'row-0');
  assert.equal(ids[599], 'row-599', 'a chunk boundary must not reorder anything');
  assert.equal(ids[1199], 'row-1199');
});

// The one that matters for a filter bar: keystrokes arrive faster than a big table
// fills, so a superseded render must stop rather than append its rows under the new
// one's - which would show two filter states at once.
test('a new render supersedes one still filling', async () => {
  renderTable('findings', COLUMNS, rows(5000));
  renderTable('findings', COLUMNS, rows(20).map((r) => ({ ...r, id: `late-${r.id}` })));
  await settle();

  const trs = [...document.querySelectorAll('#findings tbody tr')];
  assert.equal(trs.length, 20, 'only the latest render is on screen');
  assert.ok(trs.every((tr) => tr.textContent.includes('late-')),
    'no rows from the abandoned render survived');
});

test('every row is openable, including ones added after the first paint', async () => {
  renderTable('findings', COLUMNS, rows(1200));
  await settle();
  const openable = document.querySelectorAll('#findings tbody tr.openable').length;
  assert.equal(openable, 1200, 'a row a reader can see is a row they can click');
  const last = document.querySelector('#findings tbody tr:last-child');
  assert.equal(last.getAttribute('data-image'), 'img-1199');
  assert.equal(last.getAttribute('tabindex'), '0', 'the keyboard reaches the late rows too');
});
