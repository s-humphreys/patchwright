// Exporting what is on screen.
//
// The point of the button is that somebody has already narrowed the estate to the
// thing they were asked about. An export that ignored the filters would hand them
// the whole estate back and make them narrow it twice.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;

const { cell, toCSV, exportRows } = await import('./csv.js');

function finding(over = {}) {
  return {
    image: 'reg/orders-api:1', registry: 'reg', repository: 'orders-api', tag: '1',
    owner: { class: 'engineering', team: 'orders' },
    priority: 'high', actionable: true, suppressed: false, signals: ['kev'],
    exposure: 'public', counts: { critical: 2, high: 1 }, scanned: true,
    vulns: [{ id: 'CVE-1', kev: true, epss: 0.61, epss_percentile: 0.98 }],
    upgrade: { kind: 'base', current: '1', latest: '2', available: true },
    base_diff: { clears: 10, total: 12 },
    dimensions: { namespace: ['orders'] },
    ...over,
  };
}

test('a value containing a comma, quote or newline cannot break the file', () => {
  // A CSV that splits a field silently is worse than one that fails: the row still
  // parses, with everything after it shifted a column.
  assert.equal(cell('plain'), 'plain');
  assert.equal(cell('a,b'), '"a,b"');
  assert.equal(cell('say "hi"'), '"say ""hi"""');
  assert.equal(cell('two\nlines'), '"two\nlines"');
  assert.equal(cell(null), '');
  assert.equal(cell(undefined), '');
});

test('rows are joined with CRLF, which is what spreadsheets expect', () => {
  const out = toCSV(['a', 'b'], [[1, 2]]);
  assert.equal(out, 'a,b\r\n1,2');
});

test('the findings export carries what somebody would filter on', async () => {
  const file = await exportRows('queue', [finding()]);
  assert.ok(file);
  const [header, row] = file.body.split('\r\n');
  for (const col of ['image', 'team', 'priority', 'kev', 'max_epss', 'max_epss_percentile', 'exposure']) {
    assert.ok(header.includes(col), `missing column ${col}`);
  }
  assert.ok(row.includes('orders-api'));
  assert.ok(row.includes('0.61'), 'the EPSS score should be exported, not just rendered');
  assert.ok(row.includes('0.98'), 'and its percentile, which is what was asked for by name');
});

test('it exports the rows it is given, which is the filtered set', async () => {
  // Not the estate. The caller passes S.filtered, the same set the table draws.
  const file = await exportRows('queue', [finding(), finding({ image: 'reg/other:1' })]);
  assert.equal(file.body.split('\r\n').length, 3, 'header plus two rows');
});

test('the CVE view exports CVEs, not findings', async () => {
  const file = await exportRows('cves', [finding()]);
  assert.ok(file.name.includes('cves'));
  const [header, row] = file.body.split('\r\n');
  assert.ok(header.startsWith('cve,'));
  assert.ok(row.startsWith('CVE-1,'));
});

test('nothing to export says so rather than writing an empty file', async () => {
  // An empty file looks like an answer: zero findings, rather than a filter that
  // matched nothing.
  assert.equal(await exportRows('queue', []), null);
  assert.equal(await exportRows('queue', null), null);
});

test('an unscanned finding still exports, with its CVE columns empty', async () => {
  // Absence of CVE detail is not absence of the finding, and a row missing from an
  // export is indistinguishable from a finding that does not exist.
  const file = await exportRows('queue', [finding({ scanned: false, vulns: [] })]);
  assert.ok(file);
  assert.equal(file.body.split('\r\n').length, 2);
});

// The CVE export needs per-CVE detail, and the queue does not load it. An export that
// wrote a header and no rows would be worse than a pause: the reader takes a file as
// an answer.
test('a CVE export waits for the detail rather than writing an empty file', async () => {
  const { S } = await import('./state.js');
  const { resetVulns } = await import('./vulns.js');
  S.assessedAt = '2026-08-31T09:00:00Z';
  resetVulns();

  const row = {
    image: 'reg/app:1.0.0', repository: 'app', owner: { team: 'orders' }, scanned: true,
    counts: { critical: 1 }, provider_assessed: true, signals: [], vuln_count: 1,
  };
  S.queueRows = [row];

  let served = false;
  globalThis.fetch = async () => {
    served = true;
    return {
      ok: true,
      json: async () => ({ findings: [{ image: 'reg/app:1.0.0',
        vulns: [{ id: 'CVE-2026-9', severity: 'critical', cvss: 9.1, kev: true, fix_available: true }] }] }),
    };
  };

  const file = await exportRows('cves', [row]);
  assert.ok(served, 'the export fetched the detail it needed');
  assert.ok(file, 'and produced a file rather than reporting nothing to export');
  assert.match(file.body, /CVE-2026-9/);
  assert.match(file.body.split('\r\n')[0], /^cve,severity/);
});
