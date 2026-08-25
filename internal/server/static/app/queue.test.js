// Tests for the five-column queue and the detail panel it defers to.
//
// The queue's whole claim is that four questions are answerable at a glance: how
// urgent, what is it and whose, is there a fix, and is anything already happening.
// These assert that each column answers its question, and that the panel holds
// everything the columns stopped showing — without any of it turning absence into
// good news on the way.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body>' +
  '<table id="findings"><thead><tr></tr></thead><tbody></tbody></table>' +
  '<aside id="detail" hidden></aside>' +
  '</body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;
globalThis.history = dom.window.history;

const { FINDING_COLUMNS, renderTable } = await import('./table.js');
const { openDetail, closeDetail, shownImage } = await import('./detail.js');
const { S } = await import('./state.js');

function finding(over = {}) {
  return {
    image: 'reg/app:1', repository: 'app', registry: 'reg', digest: '',
    owner: { class: 'cpo', team: 'cpe', rule: 'by-namespace' },
    counts: { critical: 2, high: 5 }, provider_assessed: true,
    scanned: true, exploit_checked: true, remediation_checked: true,
    exposure: 'internal', signals: [], vulns: [], workload_count: 3,
    in_flight_checked: true, dimensions: { namespace: ['apps'] }, reasons: ['any-critical'],
    priority: 'high',
    ...over,
  };
}

test('the queue is five columns: urgency, severity, image, fix, action', () => {
  // The point of the redesign. A column costs every row's width forever, so growing
  // this list back is a decision that has to be argued for, not an accident.
  assert.deepEqual(FINDING_COLUMNS.map((c) => c.label),
    ['Urgency', 'Severity', 'Image', 'Fix', 'Action']);
});

test('urgency shows the verdict and what drives it', () => {
  const html = FINDING_COLUMNS[0].get(finding({ signals: ['exposed', 'kev'], priority: 'urgent' }));
  assert.match(html, /urgent/);
  assert.match(html, /exposed/);
  assert.match(html, /kev/);
});

test('severity says "?" when the provider never assessed the image', () => {
  const col = FINDING_COLUMNS[1];
  assert.match(col.get(finding({ provider_assessed: false })), /\?/);
  assert.match(col.get(finding()), /2C/);
  assert.match(col.get(finding()), /5H/);
  // Zero is a real answer when the image was assessed, and must read differently
  // from the unassessed case above.
  assert.match(col.get(finding({ counts: {} })), /0/);
});

test('urgency names the rule that decided it', () => {
  // The case this exists for: four tags of one image with identical counts and four
  // different verdicts, because each runs in a different environment. Without the
  // rule the column looks arbitrary.
  const prod = FINDING_COLUMNS[0].get(finding({
    priority: 'high', reasons: ['matched actionable rule "production-critical"'],
  }));
  const dev = FINDING_COLUMNS[0].get(finding({
    priority: 'low', reasons: ['matched actionable rule "any-critical"'],
  }));
  assert.match(prod, /production-critical/);
  assert.match(dev, /any-critical/);
  // Nothing recorded a reason: say so rather than leaving the cell looking complete.
  assert.match(FINDING_COLUMNS[0].get(finding({ reasons: [] })), /no rule matched/);
});

test('the image cell carries its owner and namespace instead of two more columns', () => {
  const html = FINDING_COLUMNS[2].get(finding());
  assert.match(html, /reg\/app:1/);
  assert.match(html, /cpe/);
  assert.match(html, /apps/);
  // An unattributed finding says so rather than showing a dash that reads as a team.
  assert.match(FINDING_COLUMNS[2].get(finding({ owner: {} })), /unattributed/);
});

test('fix keeps none, unknown and never-looked distinct', () => {
  const col = FINDING_COLUMNS[3];
  assert.match(col.get(finding({ remediation_checked: false })), /\?/);
  assert.match(col.get(finding({ upgrade: { resolved: false, kind: 'base' } })), /unknown/);
  assert.match(col.get(finding({ upgrade: { resolved: true, available: false, kind: 'base' } })), /none/);
  const html = col.get(finding({
    upgrade: { kind: 'base', name: 'x/y', current: '1', latest: '2', available: true,
               resolved: true, actionable: true },
  }));
  assert.match(html, /1 → 2/);
});

test('action distinguishes nothing happening from not having looked', () => {
  const col = FINDING_COLUMNS[4];
  S.ticketsByRepo = { app: [] };
  assert.match(col.get(finding()), /-/);

  const pr = col.get(finding({
    in_flight: { repository: 'app', title: 'Update x', open_days: 34, exact: true, stale: false,
                 url: 'https://example.com/1' },
  }));
  assert.match(pr, /pr 34d/);
  assert.match(pr, /href="https:\/\/example.com\/1"/);

  // Jira not configured: ticket state is unknown, and saying "-" would claim there is
  // no ticket.
  S.ticketsByRepo = undefined;
  assert.match(col.get(finding()), /\?/);
  S.ticketsByRepo = { app: [] };
});

test('rows carry their image so a click can find the finding again', () => {
  renderTable('findings', FINDING_COLUMNS, [finding()]);
  const tr = document.querySelector('#findings tbody tr');
  assert.equal(tr.dataset.image, 'reg/app:1');
  assert.equal(tr.getAttribute('tabindex'), '0', 'rows must be reachable by keyboard');
});

test('the detail panel shows every section, and unknowns as unknown', () => {
  openDetail(finding({
    provider_assessed: false, scanned: false, exploit_checked: false,
    liveness: null, exposure: 'unknown', in_flight_checked: false, digest: '',
  }));
  const el = document.querySelector('#detail');
  assert.equal(el.hidden, false);
  const text = el.textContent;
  for (const heading of ['Verdict', 'Risk', 'Fix', 'In progress', 'Where it runs', 'Vulnerabilities']) {
    assert.ok(text.includes(heading), `missing section ${heading}`);
  }
  // Nothing was gathered, so nothing may read as a clean result.
  assert.match(text, /not assessed/);
  assert.match(text, /unknown/);
  assert.ok(!/\b0 critical\b/.test(text), 'unassessed counts must not render as zero');
  assert.equal(shownImage(), 'reg/app:1');
  closeDetail();
  assert.equal(el.hidden, true);
});

test('the panel lists CVEs worst first, and says when there are none to list', () => {
  openDetail(finding({
    scanned: true,
    vulns: [
      { id: 'CVE-quiet', severity: 'high', cvss: 7.5, epss: 0.01 },
      { id: 'CVE-exploited', severity: 'high', cvss: 7.1, epss: 0.9, kev: true, fix_available: true, fixed_version: '1.2.3' },
    ],
  }));
  const text = document.querySelector('#detail').textContent;
  assert.ok(text.indexOf('CVE-exploited') < text.indexOf('CVE-quiet'),
    'a KEV-listed CVE must sort above a quiet one');
  assert.match(text, /1\.2\.3/);
  closeDetail();

  openDetail(finding({ scanned: false }));
  assert.match(document.querySelector('#detail').textContent, /was not scanned/);
  closeDetail();
});

test('anything hidden by attribute stays hidden despite its own display rule', () => {
  // An author rule setting `display` beats the browser's display:none for [hidden].
  // The detail panel shipped stuck open and empty because of exactly this, so every
  // selector that sets display needs a matching [hidden] rule.
  const css = readFileSync(new URL('./app.css', import.meta.url), 'utf8');
  const sets = new Set([...css.matchAll(/^([.#][\w-]+)\s*\{[^}]*\bdisplay:/gm)].map((m) => m[1]));
  const guarded = new Set([...css.matchAll(/^([.#][\w-]+)\[hidden\]/gm)].map((m) => m[1]));
  const toggled = ['.detail', '.tab-panel'];
  for (const sel of toggled) {
    if (sets.has(sel)) {
      assert.ok(guarded.has(sel), `${sel} sets display but has no [hidden] rule`);
    }
  }
});

test('every stylesheet token it uses is defined', () => {
  // A CSS class used before it existed shipped twice. The same mistake with a custom
  // property fails silently in exactly the same way.
  const css = readFileSync(new URL('./app.css', import.meta.url), 'utf8');
  const used = new Set([...css.matchAll(/var\(--([a-z-]+)/g)].map((m) => m[1]));
  const defined = new Set([...css.matchAll(/--([a-z-]+):/g)].map((m) => m[1]));
  const missing = [...used].filter((v) => !defined.has(v));
  assert.deepEqual(missing, [], `undefined custom properties: ${missing.join(', ')}`);
});

test('the queue offers the patch now and names the migration separately', async () => {
  // The topnotch case: a service on python 3.12.3 told to move to 3.14.7 does nothing,
  // because its dependency tree is not ready. Offering 3.12.14 with the newest named
  // turns "we cannot do that" into "we can do that today".
  const { fixCell } = await import('./cells.js');
  const html = fixCell(finding({
    upgrade: {
      kind: 'base', name: 'docker.io/python', current: '3.12.3', latest: '3.12.14',
      newest: '3.14.7', strategy: 'patch', available: true, resolved: true, actionable: true,
    },
  }));
  assert.match(html, /3\.12\.3 → 3\.12\.14/);
  assert.match(html, /newest 3\.14\.7/);
  assert.match(html, /compatibility boundary/, 'and says why it stops short');
});

test('held back reads as a decision, not as up to date', async () => {
  const { fixCell } = await import('./cells.js');
  const html = fixCell(finding({
    upgrade: {
      kind: 'base', name: 'docker.io/python', current: '3.12.14', newest: '3.14.7',
      ceiling: '3.12', ceiling_reason: 'cdt dependencies are not 3.14 ready',
      held_back: true, available: false, resolved: true,
    },
  }));
  assert.match(html, /held at 3\.12/);
  assert.doesNotMatch(html, /none/, '"none" would claim there is nothing newer');
  assert.match(html, /not 3\.14 ready/, 'the reason somebody gave travels with it');
});

test('an expired ceiling says it lapsed rather than holding quietly', async () => {
  const { upgradeStrategyWhy } = await import('./cells.js');
  const why = upgradeStrategyWhy({
    ceiling: '3.12', ceiling_expired: true, newest: '3.14.7',
    ceiling_reason: 'was blocked on dependencies',
  });
  assert.match(why, /end date has passed/);
  assert.match(why, /NOT applied/);
});
