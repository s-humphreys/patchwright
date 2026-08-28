// One filter bar governing every view.
//
// It used to filter the queue alone while sitting above the tabs as though it governed
// both, so the CVE view showed the whole estate under controls that appeared to narrow it.
// And each dropdown counted its options over a different subset, so the number beside an
// option did not describe what choosing it would do.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body>' +
  '<input type="search" id="search">' +
  '<select id="classFilter"></select><select id="teamFilter"></select>' +
  '<select id="urgencyFilter"></select><select id="signalFilter"></select>' +
  '<select id="fixFilter"></select>' +
  '<input type="checkbox" id="onlyActionable" checked>' +
  '<input type="checkbox" id="onlyFixable">' +
  '<input type="checkbox" id="showSuppressed">' +
  '<input type="checkbox" id="groupRows">' +
  '<span id="queueCount"></span>' +
  '<button class="tab" id="tabQueue" aria-selected="true" aria-controls="panelQueue">Queue</button>' +
  '<button class="tab" id="tabCVEs" aria-selected="false" aria-controls="panelCVEs">CVEs</button>' +
  '<div id="panelQueue"></div><div id="panelCVEs" hidden></div>' +
  '<table id="findings"><thead><tr></tr></thead><tbody></tbody></table>' +
  '<div id="cveNote"></div>' +
  '<table id="cves"><thead><tr></tr></thead><tbody></tbody></table>' +
  '<aside id="detail" hidden></aside>' +
  '</body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;
globalThis.history = dom.window.history;

const { apply, filterState, populate, FACETS, UNATTRIBUTED } = await import('./filters.js');
const { applyOwnerFilters, renderCurrentView } = await import('./queue.js');
const { show } = await import('./tabs.js');
const { S } = await import('./state.js');

/** A finding with a CVE, so the CVE view has something to aggregate. */
function finding(over = {}) {
  const { team = 'orders', cls = 'engineering', cve = 'CVE-1', ...rest } = over;
  return {
    image: `reg/${team}-${cve}:1`, repository: team, registry: 'reg', tag: '1',
    owner: { class: cls, team }, priority: 'high', signals: [], counts: { critical: 1 },
    provider_assessed: true, scanned: true, exploit_checked: true,
    vulns: [{ id: cve, severity: 'critical', cvss: 9, epss: 0.5, kev: false }],
    upgrade: { kind: 'base', resolved: true, available: true, actionable: true,
      name: 'docker.io/base', current: '1', latest: '2' },
    ...rest,
  };
}

const rows = [
  finding({ team: 'orders', cve: 'CVE-A', priority: 'urgent', signals: ['kev'] }),
  finding({ team: 'orders', cve: 'CVE-B' }),
  finding({ team: 'payments', cve: 'CVE-C', priority: 'low' }),
  finding({ team: 'payments', cve: 'CVE-D', cls: 'platform' }),
];

function setUp() {
  // The visible tab is global state, so it is reset here too. Without this, a test
  // inherits whichever view its predecessor left showing and asserts against a table
  // nothing has re-rendered - which passes and fails for reasons unrelated to the code.
  show('queue');
  S.queueRows = rows;
  S.ticketsByRepo = {};
  for (const f of FACETS) document.querySelector(f.id).innerHTML = '';
  document.querySelector('#search').value = '';
  document.querySelector('#onlyFixable').checked = false;
  document.querySelector('#groupRows').checked = false;
  applyOwnerFilters();
}

const choose = (id, value) => {
  const el = document.querySelector(id);
  el.value = value;
  applyOwnerFilters();
};
const queueRowCount = () => document.querySelectorAll('#findings tbody tr').length;
const cveRowCount = () => document.querySelectorAll('#cves tbody tr').length;
const count = () => document.querySelector('#queueCount').textContent;

test('the CVE view is filtered by the same controls as the queue', () => {
  // The bug. The filter bar sits above both tabs; it has to mean the same thing in both.
  setUp();
  show('cves');
  renderCurrentView();
  assert.equal(cveRowCount(), 4, 'unfiltered: every CVE');

  choose('#teamFilter', 'orders');
  assert.equal(cveRowCount(), 2, 'the CVE view must drop the other team\'s CVEs');
  assert.match(count(), /2 CVEs across 2 of 4 findings/);

  // And back, without switching tabs.
  choose('#teamFilter', '');
  assert.equal(cveRowCount(), 4);
});

test('switching view keeps the filter, and the two views agree on the population', () => {
  setUp();
  choose('#urgencyFilter', 'urgent');
  assert.equal(queueRowCount(), 1);

  show('cves');
  renderCurrentView();
  assert.equal(cveRowCount(), 1, 'the CVE view inherited a different population');

  show('queue');
  renderCurrentView();
  assert.equal(queueRowCount(), 1, 'the filter did not survive coming back');
  assert.equal(document.querySelector('#urgencyFilter').value, 'urgent');
});

test('options are counted over the other filters, so a count says what picking it does', () => {
  setUp();
  // Unfiltered, both teams are offered with their totals.
  const teamOpts = () => [...document.querySelector('#teamFilter').options]
    .map((o) => `${o.value}:${o.textContent}`).join(' | ');
  assert.match(teamOpts(), /orders \(2\)/);
  assert.match(teamOpts(), /payments \(2\)/);

  // Narrow the class: the team list must narrow with it, and the counts must follow.
  choose('#classFilter', 'platform');
  assert.doesNotMatch(teamOpts(), /orders/, 'a team with nothing behind it is still offered');
  assert.match(teamOpts(), /payments \(1\)/);
});

test('a value that cannot return anything is not offered at all', () => {
  setUp();
  choose('#teamFilter', 'orders');
  const urgencies = [...document.querySelector('#urgencyFilter').options].map((o) => o.value);
  // "low" belongs only to payments, so with orders selected it must be gone.
  assert.ok(!urgencies.includes('low'), `low should not be offered: ${urgencies}`);
  assert.ok(urgencies.includes('urgent'));
});

test('a selection that stops matching is kept and shown as zero, not silently dropped', () => {
  // The case that actually happens: an hourly refresh brings findings in which the
  // reader's chosen value no longer appears. Clearing it for them would change what they
  // are looking at without saying so, and leave the URL describing a state the page is
  // not in.
  //
  // Note that faceting makes the other route impossible: a value with nothing behind it
  // is not offered, so it cannot be picked in the first place.
  setUp();
  choose('#urgencyFilter', 'low');
  assert.equal(queueRowCount(), 1);

  // New data, no "low" anywhere in it.
  S.queueRows = rows.filter((f) => f.priority !== 'low');
  applyOwnerFilters();

  const urg = document.querySelector('#urgencyFilter');
  assert.equal(urg.value, 'low', 'the selection was dropped behind the reader\'s back');
  const label = [...urg.options].find((o) => o.value === 'low').textContent;
  assert.match(label, /\(0\)/, 'a selection matching nothing should say so');
  assert.equal(queueRowCount(), 0, 'and the table has to agree with the filter');
});

test('the search box narrows every view too', () => {
  setUp();
  document.querySelector('#search').value = 'payments';
  applyOwnerFilters();
  assert.equal(queueRowCount(), 2);
  show('cves');
  renderCurrentView();
  assert.equal(cveRowCount(), 2);
});

test('grouping by service groups only what survived the filter', () => {
  setUp();
  show('queue');
  document.querySelector('#groupRows').checked = true;
  choose('#teamFilter', 'payments');
  // Two payments findings, one attributed to another class, so grouping by team and
  // service yields two work items - both of them from the filtered set.
  assert.ok(queueRowCount() > 0);
  for (const g of S.groupRows) {
    assert.equal(g.owner?.team, 'payments',
      `a group leaked in from outside the filter: ${g.key}`);
  }
});

test('apply can ignore one filter, which is what makes faceting possible', () => {
  const st = { class: 'platform', team: 'orders', q: '', fixable: false };
  // With both applied, nothing matches: orders is engineering.
  assert.equal(apply(rows, st, null).length, 0);
  // Ignoring team, the class still narrows.
  assert.equal(apply(rows, st, 'team').length, 1);
  // Ignoring class, the team does.
  assert.equal(apply(rows, st, 'class').length, 2);
});

test('unattributed findings are selectable, since an unowned finding is a thing to fix', () => {
  setUp();
  S.queueRows = [...rows, finding({ team: '', cve: 'CVE-E' })];
  applyOwnerFilters();
  const teams = [...document.querySelector('#teamFilter').options].map((o) => o.value);
  assert.ok(teams.includes(UNATTRIBUTED), `no unattributed option: ${teams}`);
  choose('#teamFilter', UNATTRIBUTED);
  assert.equal(queueRowCount(), 1);
});

test('filterState reads what the controls say, nothing more', () => {
  setUp();
  document.querySelector('#search').value = '  Orders  ';
  document.querySelector('#onlyFixable').checked = true;
  choose('#signalFilter', 'kev');
  const st = filterState();
  assert.equal(st.q, 'orders', 'the search term should be trimmed and lowered once');
  assert.equal(st.fixable, true);
  assert.equal(st.signal, 'kev');
});

test('populate leaves the dropdowns alone when there is nothing to show', () => {
  // An empty assessment must not throw: the page renders before findings arrive.
  setUp();
  S.queueRows = [];
  populate([], filterState());
  applyOwnerFilters();
  assert.equal(queueRowCount(), 0);
  assert.match(count(), /0 findings/);
});

test('a deep link filters the view it names', async () => {
  // The whole point of putting filters in the URL: "the CVEs affecting payments" is a
  // link somebody can send. It has to arrive filtered, in the view it names.
  const { readURL } = await import('./urlstate.js');
  setUp();

  // Options are populated from the unfiltered set before the URL is read, which is what
  // makes any combination expressible - including one that matches nothing.
  const link = new URLSearchParams('view=cves&team=payments&urgency=low');
  readURL(link);
  show('cves');
  applyOwnerFilters();

  assert.equal(document.querySelector('#teamFilter').value, 'payments');
  assert.equal(document.querySelector('#urgencyFilter').value, 'low');
  assert.equal(cveRowCount(), 1, 'the link should arrive filtered, not showing the estate');
});

test('the URL keeps up with the controls, including which view is showing', async () => {
  const { writeURL } = await import('./urlstate.js');
  setUp();
  show('cves');
  choose('#signalFilter', 'kev');
  writeURL();
  assert.match(location.search, /signal=kev/);
  assert.match(location.search, /view=cves/, 'the view must survive a filter change');

  // And clearing a filter removes its parameter rather than leaving a stale one.
  choose('#signalFilter', '');
  assert.doesNotMatch(location.search, /signal=/);
  assert.match(location.search, /view=cves/);
});

test('a link naming a combination with nothing behind it shows empty, not everything', async () => {
  // The dangerous rendering is the whole estate under filters that appear to narrow it,
  // which is the bug this all started from.
  const { readURL } = await import('./urlstate.js');
  setUp();
  readURL(new URLSearchParams('team=orders&urgency=low'));
  applyOwnerFilters();
  assert.equal(queueRowCount(), 0);
  assert.match(count(), /0 of 4 findings/);
});
