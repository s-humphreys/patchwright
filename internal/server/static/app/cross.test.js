// The other half of a cross-language contract.
//
// The page groups findings in the browser so filtering responds instantly; the API
// groups them in Go so consumers do not have to. Two implementations of one set of
// rules drift, and silently — both keep returning plausible numbers. So both read
// testdata/grouping.json and both are checked against testdata/grouping.expected.
//
// If this fails, the two no longer agree. Fix whichever one is wrong; do not
// regenerate the expectation to make the failure go away, because the expectation is
// the only thing keeping them honest.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;
globalThis.history = dom.window.history;

const { groupFindings } = await import('./groups.js');

const root = new URL('../../../../testdata/', import.meta.url);
const fixture = JSON.parse(readFileSync(new URL('grouping.json', root), 'utf8'));
const expected = readFileSync(new URL('grouping.expected', root), 'utf8');

/** summarise mirrors pkg/group's cross_test.go exactly, field for field. */
function summarise(groups) {
  return groups.map((g) => {
    const target = g.upgrade ? `${g.upgrade.name}@${g.upgrade.latest}` : 'none';
    const rule = ((g.lead.reasons || [])[0] || '').match(/"([^"]+)"/);
    return [
      `${g.owner?.team || ''}/${g.repository}`,
      `target=${target}`,
      `priority=${g.priority}`,
      `where=${g.worstWhere}`,
      `rule=${rule ? rule[1] : ''}`,
      `crit=${g.counts.critical}`,
      `high=${g.counts.high}`,
      `deployments=${g.findings.length}`,
      `assessed=${g.assessedOf[0]}`,
      `exposure=${g.exposure}`,
      `signals=${[...g.signals].sort().join('+')}`,
      `inflight_checked=${g.in_flight_checked}`,
      `tags=${[...g.tags].sort().join(',')}`,
    ].join(' ');
  }).sort().join('\n') + '\n';
}

test('the page groups findings exactly as the API does', () => {
  const got = summarise(groupFindings(fixture.findings));
  assert.equal(got, expected,
    'the browser and Go groupings disagree; one of them is now wrong');
});
