// The base-image breakdown: what the base accounts for, and what a rebuild fixes.
//
// The rule this file mostly guards is that "we did not check" never renders as
// "nothing to fix". The previous attempt at package attribution shipped because
// exactly that distinction was collapsed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;

const { baseDiffSection, splitGroup } = await import('./basediff.js');

function vuln(over = {}) {
  return {
    id: 'CVE-1', severity: 'high', kev: false,
    origin: 'base', origin_determined: true, fixed_by_upgrade: false, ...over,
  };
}

function finding(over = {}) {
  return {
    base_diff: {
      from_ref: 'python@sha256:aaa', to_ref: 'python:3.12', os_family: 'debian',
      total: 100, from_base: 90, from_app: 10, unknown: 0,
      clears: 70, leaves: 20, introduces: 0, determined: true,
    },
    vulns: [],
    ...over,
  };
}

const html = (f) => baseDiffSection(f);

test('no differential renders nothing rather than a row of zeroes', () => {
  // Zeroes would read as "the base accounts for nothing", which is the opposite
  // of what an absent scan means.
  assert.equal(html({ vulns: [] }), '');
  assert.equal(html({ base_diff: null, vulns: [] }), '');
});

test('it says how much of the image the base accounts for', () => {
  const out = html(finding());
  assert.match(out, /90<\/strong> from the base image/);
  assert.match(out, /10<\/strong> from this image/);
  assert.match(out, /90%/);
});

test('it says what a rebuild clears, which is the point of the whole thing', () => {
  const out = html(finding());
  assert.match(out, /70<\/strong> of 100 CVEs/);
  assert.match(out, /20 still from the base/);
});

test('an upgrade that introduces CVEs says so', () => {
  // Reporting only what an upgrade fixes is one-sided arithmetic, and the first
  // reader to check it stops trusting the recommendation.
  const f = finding();
  f.base_diff.introduces = 4;
  assert.match(html(f), /4 new/);
});

test('an unscanned candidate reads as not established, never as nothing fixed', () => {
  const f = finding();
  f.base_diff.determined = false;
  f.base_diff.clears = 0;
  f.base_diff.leaves = 0;
  const out = html(f);
  assert.match(out, /not established/);
  assert.doesNotMatch(out, /0<\/strong> of 100/,
    'zero clears must not be rendered as a finding when nothing was compared');
});

test('KEV is split into cleared and still-needing-work, and only the latter is named', () => {
  // The information-overload rule: what needs doing is listed, what is handled is
  // a number.
  const f = finding({
    vulns: [
      vuln({ id: 'CVE-FIXED-1', kev: true, fixed_by_upgrade: true }),
      vuln({ id: 'CVE-FIXED-2', kev: true, fixed_by_upgrade: true }),
      vuln({ id: 'CVE-STAYS', kev: true, fixed_by_upgrade: false }),
    ],
  });
  const out = html(f);
  assert.match(out, /2 \(67%\) cleared by upgrading/);
  assert.match(out, /1 \(33%\) need separate work/);
  assert.match(out, /CVE-STAYS/, 'the one needing work must be named');
  assert.doesNotMatch(out, /CVE-FIXED-1/, 'a cleared CVE is a count, not a list entry');
});

test('a critical that is also KEV is counted once, under KEV', () => {
  // Otherwise the two group totals overlap and add up to more than the image has.
  const f = finding({
    vulns: [vuln({ id: 'CVE-BOTH', kev: true, severity: 'critical' })],
  });
  const el = dom.window.document.createElement('div');
  el.innerHTML = html(f);
  const listed = el.querySelectorAll('.cve-brief [data-cve="CVE-BOTH"]');
  assert.equal(listed.length, 1, `CVE-BOTH is listed ${listed.length} times, should be once`);
  assert.doesNotMatch(el.innerHTML, /Critical/,
    'the critical group should be empty once its only member is counted as KEV');
});

test('undetermined CVEs are kept apart from ones the upgrade will not fix', () => {
  const s = splitGroup([
    vuln({ id: 'A', kev: true, origin_determined: true, fixed_by_upgrade: true }),
    vuln({ id: 'B', kev: true, origin_determined: true, fixed_by_upgrade: false }),
    vuln({ id: 'C', kev: true, origin_determined: false }),
  ], (v) => v.kev);
  assert.deepEqual(s.cleared.map((v) => v.id), ['A']);
  assert.deepEqual(s.remaining.map((v) => v.id), ['B']);
  assert.deepEqual(s.undetermined.map((v) => v.id), ['C'],
    'an unchecked CVE must not be reported as one the upgrade fails to fix');
});

test('a long list of remaining CVEs is capped so the panel stays readable', () => {
  const vulns = [];
  for (let i = 0; i < 20; i++) vulns.push(vuln({ id: `CVE-${i}`, kev: true }));
  const out = html(finding({ vulns }));
  assert.match(out, /and 14 more/);
  assert.ok(!out.includes('CVE-19'), 'the tail should be summarised, not printed');
});

test('a group with nothing in it is not rendered at all', () => {
  const out = html(finding({ vulns: [vuln({ severity: 'low' })] }));
  assert.doesNotMatch(out, /Known exploited/);
  assert.doesNotMatch(out, /Critical/);
});

test('the named CVEs carry the hook the drill-in wires to', () => {
  const out = html(finding({ vulns: [vuln({ id: 'CVE-STAYS', kev: true })] }));
  const el = dom.window.document.createElement('div');
  el.innerHTML = out;
  const link = el.querySelector('.cve-brief [data-cve]');
  assert.ok(link, 'a named CVE must be reachable by the drill-in selector');
  assert.equal(link.dataset.cve, 'CVE-STAYS');
});

test('it names exactly what was compared, so the numbers can be checked', () => {
  const out = html(finding());
  assert.match(out, /python@sha256:aaa/);
  assert.match(out, /python:3\.12/);
});

test('a digest-only move is a rebuild; a version move is an upgrade', () => {
  // "Rebuilding" covers two different asks. Same tag with a newer digest really
  // is just a rebuild. python 3.12.3 to 3.14.7 is a runtime migration, and
  // calling that a rebuild understates it to whoever has to do it.
  const digest = finding();
  digest.base_diff.to_ref = 'docker.io/python@sha256:deadbeef';
  const d = html(digest);
  assert.match(d, /Rebuilding clears/);
  assert.match(d, /same tag, newer digest/);

  const version = finding();
  version.base_diff.to_ref = 'docker.io/python:3.14.7';
  const v = html(version);
  assert.match(v, /Upgrading the base clears/);
  assert.match(v, /moving to <code>3\.14\.7<\/code>/);
  assert.doesNotMatch(v, /same tag/);
});

test('each triage group shows its share, not just a count', () => {
  // 40 of 58 is a different situation from 40 of 400, and a reader comparing
  // images should not have to do the division.
  const vulns = [];
  for (let i = 0; i < 4; i++) vulns.push(vuln({ id: `CVE-C${i}`, kev: true, fixed_by_upgrade: true }));
  vulns.push(vuln({ id: 'CVE-R', kev: true, fixed_by_upgrade: false }));
  const out = html(finding({ vulns }));
  assert.match(out, /4 \(80%\) cleared/);
  assert.match(out, /1 \(20%\) need separate work/);
});
