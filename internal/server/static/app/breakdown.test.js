// The breakdown answers "who has the most work". A security reviewer asks a different
// question: which teams are carrying the sharp end - how many urgent, how many
// exploited, in whose name. These are about that, and about the count being a way INTO
// the queue rather than a number to read out and retype.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body>' +
  '<table id="breakdown"><thead><tr></tr></thead><tbody></tbody></table>' +
  '<input type="search" id="search">' +
  '<select id="classFilter"></select><select id="teamFilter"></select>' +
  '<select id="urgencyFilter"></select><select id="signalFilter"></select>' +
  '<select id="fixFilter"></select>' +
  '<input type="checkbox" id="onlyActionable" checked>' +
  '<input type="checkbox" id="onlyFixable">' +
  '<input type="checkbox" id="showSuppressed">' +
  '<input type="checkbox" id="groupRows" checked>' +
  '</body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;
globalThis.history = dom.window.history;

const { renderBreakdown, breakdownColumns, applyDrilldown, expandedClasses, drilldown } =
  await import('./table.js');

function owner(over = {}) {
  return {
    class: 'engineering', team: 'orders', total: 10, unassessed: 0, actionable: 4,
    direct: 3, managed: 1, fixable: 2, ticketed: 0, cves: {}, cves_from: 10,
    urgent: 2, known_exploited: 1, exposed: 0, end_of_life: 1, ...over,
  };
}

test('the breakdown reports urgency and exploitation per team', () => {
  renderBreakdown([owner()]);
  const labels = breakdownColumns().map((c) => c.label);
  for (const want of ['Urgent', 'KEV', 'Exposed', 'EOL']) {
    assert.ok(labels.includes(want), `missing column ${want}`);
  }
  const text = document.querySelector('#breakdown tbody').textContent;
  assert.match(text, /orders|engineering/);
});

test('a count is a link into the queue, and a zero is not', () => {
  // Offering to show nothing is worse than saying there is nothing: a link to an empty
  // queue looks like a filter that failed.
  const withKev = drilldown({ classKey: 'engineering', teamKey: 'orders' }, 3, { signal: 'kev' });
  assert.match(withKev, /<a /, 'a non-zero count should be a link');
  assert.match(withKev, /data-drill-signal="kev"/);
  assert.match(withKev, /data-drill-team="orders"/);

  const zero = drilldown({ classKey: 'engineering', teamKey: 'orders' }, 0, { signal: 'kev' });
  assert.doesNotMatch(zero, /<a /, 'a zero must not be a link to an empty queue');
});

test('drilling in applies filters the reader can see', () => {
  // Not a private query: the selects show why the queue looks like this, so somebody
  // landing on 3 rows out of 500 can tell what was applied and adjust it.
  const sig = document.querySelector('#signalFilter');
  sig.innerHTML = '<option value=""></option><option value="kev">kev</option>';
  const team = document.querySelector('#teamFilter');
  team.innerHTML = '<option value=""></option><option value="orders">orders</option>';

  let applied = 0;
  const missed = applyDrilldown({ team: 'orders', signal: 'kev' }, () => { applied++; });
  assert.equal(missed.length, 0);
  assert.equal(sig.value, 'kev');
  assert.equal(team.value, 'orders');
  assert.equal(applied, 1, 'the queue must be re-filtered, not just the controls set');
});

test('drilling in agrees with what the counts were drawn from', () => {
  // The breakdown excludes suppressed findings, so the queue it lands on must too, or
  // the list will not match the number that was clicked. And an urgency drilldown has
  // to clear "actionable only", because these counts are of everything in the row.
  const sup = document.querySelector('#showSuppressed');
  const act = document.querySelector('#onlyActionable');
  sup.checked = true;
  act.checked = true;
  const urg = document.querySelector('#urgencyFilter');
  urg.innerHTML = '<option value=""></option><option value="urgent">urgent</option>';

  applyDrilldown({ team: '', urgency: 'urgent' }, null);
  assert.equal(sup.checked, false, 'suppressed findings are not in the counts');
  assert.equal(act.checked, false, 'the count includes findings policy did not mark actionable');
  assert.equal(urg.value, 'urgent');
});

test('a filter value that does not exist is reported, not silently ignored', () => {
  // Selecting nothing would show the whole queue as though the drilldown had worked,
  // which is the same failure as a filter that silently matches everything.
  const sig = document.querySelector('#signalFilter');
  sig.innerHTML = '<option value=""></option>'; // kev not present in this data
  const missed = applyDrilldown({ signal: 'kev' }, null);
  assert.ok(missed.includes('signal'), `expected signal to be reported as missed, got ${missed}`);
});

test('clicking a count does not collapse the class it is in', () => {
  // The link sits inside an expandable row, so without stopping propagation the row's
  // own handler fires too and shuts the section the reader just drilled into.
  expandedClasses.add('engineering');
  renderBreakdown([owner(), owner({ team: 'payments', urgent: 1 })]);
  const link = document.querySelector('#breakdown a.drill');
  assert.ok(link, 'no drilldown link rendered');
  assert.ok(link.closest('tr'), 'link is not inside a row');
});

test('the urgency filter narrows the queue and orders worst first', async () => {
  // The list is a severity scale, so sorting the options as text puts "high" above
  // "urgent" and the first thing a reader reaches for is the wrong one.
  const { populateOwnerFilters } = await import('./queue.js');
  const { S } = await import('./state.js');
  const f = (priority) => ({
    image: `reg/${priority}:1`, repository: priority, owner: { class: 'engineering', team: 'orders' },
    priority, counts: {}, signals: [], provider_assessed: true,
  });
  S.queueRows = [f('urgent'), f('high'), f('high'), f('low')];
  populateOwnerFilters(S.queueRows);

  const opts = [...document.querySelector('#urgencyFilter').options].map((o) => o.value);
  assert.equal(opts[0], '', 'the first option is "any"');
  assert.deepEqual(opts.slice(1), ['urgent', 'high', 'low'], 'options must run worst first');
  const labels = [...document.querySelector('#urgencyFilter').options].map((o) => o.textContent);
  assert.match(labels[2], /high \(2\)/, 'each option carries its count');
});

test('KEV is a share of the estate, not of the row', async () => {
  // The question is "who carries the exploited work", and a row-relative percentage
  // cannot answer it: three findings all exploited is 100% of a tiny row and might be a
  // tenth of the estate's problem.
  renderBreakdown([
    owner({ team: 'ics', total: 100, actionable: 90, known_exploited: 7 }),
    owner({ team: 'data-platform', total: 13, actionable: 12, known_exploited: 12 }),
  ]);
  const cols = breakdownColumns().map((c) => c.label);
  const kev = cols.indexOf('KEV');
  assert.ok(kev > 0, 'no KEV column');

  const rows = [...document.querySelectorAll('#breakdown tbody tr')];
  const text = (tr) => tr.querySelectorAll('td')[kev].textContent.replace(/\s+/g, ' ').trim();
  // 7 and 12 of 19 across the table.
  const cells = rows.map(text).join(' | ');
  assert.match(cells, /37% of all/, `expected ics at 37%, got: ${cells}`);
  assert.match(cells, /63% of all/, `expected data-platform at 63%, got: ${cells}`);
  // Labelled, because an unlabelled percentage beside row-relative ones would be read
  // as the same kind of number.
  assert.match(cells, /of all/);
});

test('the actionable count stays visible after losing its column', async () => {
  // It is the denominator of four columns to the right. A share whose denominator is
  // nowhere on screen is what produced "104%" in the first place.
  renderBreakdown([owner({ team: 'ics', total: 100, actionable: 90 })]);
  const cols = breakdownColumns().map((c) => c.label);
  assert.equal(cols.includes('Actionable'), false, 'the standalone column should be gone');
  for (const dependent of ['Direct', 'Managed', 'Fixable', 'Ticketed']) {
    assert.ok(cols.includes(dependent), `${dependent} column missing`);
  }
  const findings = document.querySelectorAll('#breakdown tbody tr td')[cols.indexOf('Findings')];
  assert.match(findings.textContent.replace(/\s+/g, ' '), /90 actionable/,
    'the denominator for the columns to the right must still be readable');
});

test('EPSS reads as a probability, and a small one is not rounded to nothing', async () => {
  // Published 0-1, it reads as a rating out of one and invites comparison with CVSS.
  // As a percentage it says what it means. The small end matters most, because most
  // scores live there: rounding 0.0006 to "0%" claims no chance on a CVE that has some.
  const { epssPercent } = await import('./cells.js');
  assert.equal(epssPercent(0.61), '61%');
  assert.equal(epssPercent(0.006), '0.6%');
  assert.equal(epssPercent(0.0006), '<0.1%');
  assert.equal(epssPercent(0), '0%');
  assert.equal(epssPercent(1), '100%');
  assert.equal(epssPercent(undefined), '-');
  assert.equal(epssPercent(null), '-');
});
