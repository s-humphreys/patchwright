// Tests for the CVE view: the estate read by CVE rather than by image.
//
// The view exists so security can see the scope of one CVE without reading 500 rows,
// so the assertions are about scope being right and about the empty case being honest:
// a CVE list built from unscanned findings is not "no CVEs".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body>' +
  '<p id="cveNote"></p>' +
  '<table id="cves"><thead><tr></tr></thead><tbody></tbody></table>' +
  '<aside id="detail" hidden></aside>' +
  '</body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;
globalThis.history = dom.window.history;

const { CVE_COLUMNS, groupByCVE, renderCVEs } = await import('./cves.js');
const { openCVEDetail, closeDetail, shownCVE } = await import('./detail.js');
const { S } = await import('./state.js');

function finding(image, team, vulns, over = {}) {
  return {
    image, repository: image.split(':')[0], owner: { team, class: 'cpo' },
    counts: {}, provider_assessed: true, scanned: true, exploit_checked: true,
    remediation_checked: true, exposure: 'internal', signals: [], vulns,
    upgrade: { kind: 'base', resolved: true, available: true, actionable: true,
               name: 'base', current: '1', latest: '2' },
    ...over,
  };
}

test('one CVE across many images aggregates to one row with the full scope', () => {
  const { groups } = groupByCVE([
    finding('reg/a:1', 'cpe', [{ id: 'CVE-1', severity: 'high', cvss: 7.5, fix_available: true, fixed_version: '1.1' }]),
    finding('reg/b:1', 'sre', [{ id: 'CVE-1', severity: 'critical', cvss: 9.8, epss: 0.4 }]),
    finding('reg/c:1', 'cpe', [{ id: 'CVE-2', severity: 'low' }]),
  ]);
  const one = groups.find((g) => g.id === 'CVE-1');
  assert.equal(one.images.length, 2);
  assert.deepEqual([...one.teams].sort(), ['cpe', 'sre']);
  // The worst of anything reported: the same CVE is rated differently by distro, and
  // the urgent rating is the one that matters.
  assert.equal(one.severity, 'critical');
  assert.equal(one.cvss, 9.8);
  assert.equal(one.epss, 0.4);
  assert.equal(one.fixable, 1, 'only one of the two images has a fix');
});

test('KEV outranks severity, and severity outranks reach', () => {
  const { groups } = groupByCVE([
    finding('reg/a:1', 'cpe', [
      { id: 'CVE-kev', severity: 'high', kev: true },
      { id: 'CVE-crit', severity: 'critical' },
      { id: 'CVE-wide', severity: 'low' },
    ]),
    finding('reg/b:1', 'cpe', [{ id: 'CVE-wide', severity: 'low' }]),
    finding('reg/c:1', 'cpe', [{ id: 'CVE-wide', severity: 'low' }]),
  ]);
  const rank = CVE_COLUMNS[0].sort;
  const ordered = groups.slice().sort((a, b) => rank(b) - rank(a)).map((g) => g.id);
  assert.deepEqual(ordered, ['CVE-kev', 'CVE-crit', 'CVE-wide']);
});

test('unscanned findings are excluded and reported, never counted as clean', () => {
  const { groups, scanned, total } = groupByCVE([
    finding('reg/a:1', 'cpe', [{ id: 'CVE-1', severity: 'high' }]),
    finding('reg/b:1', 'cpe', [], { scanned: false }),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(scanned, 1);
  assert.equal(total, 2);

  renderCVEs([finding('reg/a:1', 'cpe', [{ id: 'CVE-1', severity: 'high' }]),
              finding('reg/b:1', 'cpe', [], { scanned: false })]);
  const note = document.querySelector('#cveNote').textContent;
  assert.match(note, /1 of 2/);
  assert.match(note, /unknown rather than absent/);
});

test('nothing scanned says why, rather than showing an empty CVE list', () => {
  renderCVEs([finding('reg/a:1', 'cpe', [], { scanned: false })]);
  const note = document.querySelector('#cveNote').textContent;
  assert.match(note, /No image was scanned/);
  assert.match(note, /vuln-source/);
  assert.equal(document.querySelectorAll('#cves tbody tr').length, 0);
});

test('a CVE with no fix anywhere says so rather than showing 0', () => {
  const { groups } = groupByCVE([finding('reg/a:1', 'cpe', [{ id: 'CVE-1', severity: 'high' }])]);
  const html = CVE_COLUMNS[6].get(groups[0]);
  assert.match(html, /none/);
  assert.doesNotMatch(html, /0\/1/);
});

test('the CVE panel lists every affected image and the teams involved', () => {
  const { groups } = groupByCVE([
    finding('reg/a:1', 'cpe', [{ id: 'CVE-1', severity: 'critical', kev: true, fix_available: true, fixed_version: '2.0' }]),
    finding('reg/b:1', 'sre', [{ id: 'CVE-1', severity: 'critical' }]),
  ]);
  openCVEDetail(groups[0]);
  const el = document.querySelector('#detail');
  assert.equal(el.hidden, false);
  const text = el.textContent;
  assert.match(text, /reg\/a:1/);
  assert.match(text, /reg\/b:1/);
  assert.match(text, /cpe/);
  assert.match(text, /sre/);
  assert.match(text, /2\.0/);
  assert.match(text, /no fix/, 'the image without a fix must say so');
  assert.equal(shownCVE(), 'CVE-1');
  closeDetail();
  assert.equal(el.hidden, true);
});

test('rows carry the CVE id so the panel can be reopened after a refresh', () => {
  renderCVEs([finding('reg/a:1', 'cpe', [{ id: 'CVE-1', severity: 'high' }])]);
  const tr = document.querySelector('#cves tbody tr');
  assert.equal(tr.dataset.cve, 'CVE-1');
  assert.equal(tr.getAttribute('tabindex'), '0');
});

test('an affected image opens its finding, with the way back to the CVE', async () => {
  // Reading a CVE's scope raises the obvious next question — what is that image, and is
  // it urgent — and answering it must not cost you your place in the list.
  const { openCVEDetail, closeDetail } = await import('./detail.js');
  const vulns = [{ id: 'CVE-2024-13176', severity: 'medium', fix_available: true, fixed_version: '3.0.16' }];
  const findings = [
    finding('acr.io/alfred:1.0.188', 'qa', vulns, { priority: 'urgent' }),
    finding('acr.io/achievements:1.0.82-rc', '', vulns),
  ];
  S.queueRows = findings;

  const { groups: [cve] } = groupByCVE(findings);
  openCVEDetail(cve);
  const el = document.querySelector('#detail');
  assert.match(el.textContent, /CVE-2024-13176/);

  const row = el.querySelector('tbody tr.openable');
  assert.ok(row, 'affected images must be openable');
  row.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  assert.equal(el.hidden, false, 'the panel stays open');
  assert.match(el.textContent, /Verdict/, 'and shows the finding');

  const back = el.querySelector('#detailBack');
  assert.ok(back, 'a drill-in must offer a way back');
  assert.match(back.textContent, /CVE-2024-13176/, 'named, so it is obvious where back goes');
  back.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  assert.match(el.textContent, /Images affected/, 'back returns to the CVE');
  assert.equal(el.querySelector('#detailBack'), null, 'and the trail is empty again');
  closeDetail();
});

test('an image filtered out of the queue says so rather than doing nothing', async () => {
  // A CVE's scope is every image carrying it; the queue may be filtered to a subset.
  // Clicking one that is hidden has nothing to open, and silence reads as a broken
  // click.
  const { openCVEDetail, closeDetail } = await import('./detail.js');
  const carrying = finding('acr.io/hidden:1.0.0', 'cpe', [{ id: 'CVE-1', severity: 'high' }]);
  const { groups: [cve] } = groupByCVE([carrying]);
  S.queueRows = [];   // the finding is not loaded: a filter is hiding it
  openCVEDetail(cve);
  const el = document.querySelector('#detail');
  el.querySelector('tbody tr.openable').dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  assert.match(el.textContent, /filtered out of the queue/);
  assert.match(el.textContent, /Images affected/, 'and stays on the CVE');
  closeDetail();
});
