// The headline has to be readable by somebody who did not build it. These assert the
// arithmetic closes and that no tile states something the data does not support.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body><div id="tiles"></div></body></html>',
  { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;

const { renderTiles } = await import('./panels.js');

const summary = (over = {}) => ({
  findings: 671, actionable: 571, suppressed: 220, known_exploited: 31,
  end_of_life: 16, exposed: 0, exposure_unknown: 0, upgradable: 558,
  unique_images: 887, in_flight: 1, in_flight_checked: 671, ...over,
});

function tiles() {
  return [...document.querySelectorAll('#tiles .tile')].map((el) => ({
    n: el.querySelector('.n').textContent,
    label: el.querySelector('.l').textContent,
    sub: el.querySelector('.tile-sub')?.textContent || '',
    title: el.getAttribute('title') || '',
  }));
}

test('the funnel arithmetic closes', () => {
  // raised - suppressed = in the queue. If the headline does not add up, a reader stops
  // trusting the rest of the page, and they are right to.
  renderTiles(summary());
  const by = Object.fromEntries(tiles().map((t) => [t.label, Number(t.n)]));
  assert.equal(by.raised, 891, 'raised is findings plus suppressed');
  assert.equal(by.raised - by.suppressed, by['in the queue']);
  assert.ok(by['needs action'] <= by['in the queue'], 'actionable is a subset of the queue');
});

test('every number carries an explanation', () => {
  // A number whose definition is a guess gets argued about rather than acted on.
  renderTiles(summary());
  for (const t of tiles()) {
    assert.ok(t.title.length > 20, `${t.label} has no usable explanation`);
  }
  const explains = document.querySelectorAll('#tiles details.tile-explain');
  assert.equal(explains.length, 2, 'each group needs its expandable definitions');
  for (const d of explains) {
    assert.equal(d.hasAttribute('open'), false, 'definitions start collapsed');
    assert.ok(d.querySelectorAll('dt').length >= 3);
  }
});

test('the sharp end is present and led by exploitation', () => {
  renderTiles(summary());
  const labels = tiles().map((t) => t.label);
  for (const want of ['known exploited', 'end of life', 'internet-facing']) {
    assert.ok(labels.includes(want), `missing ${want}`);
  }
  // Known exploited must be marked urgent, not rendered like a neutral count.
  const kev = [...document.querySelectorAll('#tiles .tile')]
    .find((el) => el.querySelector('.l').textContent === 'known exploited');
  assert.match(kev.className, /tile-urgent/);
});

test('zero exposed with zero unknown says "none reported", not "0"', () => {
  // Zero of both is a claim that nothing in the estate is reachable. Where a provider
  // reports that uniformly it is a statement about the provider, and a bare 0 would
  // launder it into a fact about the estate.
  renderTiles(summary({ exposed: 0, exposure_unknown: 0 }));
  const t = tiles().find((x) => x.label === 'internet-facing');
  assert.equal(t.sub, 'none reported');
  assert.match(t.title, /does not populate|nothing exposed/);
});

test('an unchecked count renders as unknown rather than zero', () => {
  // No support source this run: "0 end of life" would be the most reassuring possible
  // way to be wrong.
  renderTiles(summary({ end_of_life: undefined }));
  const t = tiles().find((x) => x.label === 'end of life');
  assert.equal(t.n, '?');
  assert.match(t.title, /not checked/i);
});

test('fix in flight is hidden when detection did not run', () => {
  // "0 in flight" without a pull-request source would claim nobody is working on any
  // of it.
  renderTiles(summary({ in_flight_checked: 0 }));
  assert.equal(tiles().find((x) => x.label === 'fix in flight'), undefined);
  renderTiles(summary({ in_flight_checked: 671 }));
  assert.ok(tiles().find((x) => x.label === 'fix in flight'));
});
