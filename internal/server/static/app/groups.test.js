// Tests for grouping the queue into work items.
//
// Grouping is where a queue can quietly start lying: a collapsed row has to report the
// worst of several findings, and every aggregation is a chance to turn "urgent in
// production" into "urgent" with no idea where, or "some images unassessed" into a
// clean-looking count. These assert the aggregations stay honest.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body>' +
  '<table id="findings"><thead><tr></tr></thead><tbody></tbody></table>' +
  '<aside id="detail" hidden></aside>' +
  '</body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;
globalThis.history = dom.window.history;

const { GROUP_COLUMNS, groupFindings } = await import('./groups.js');
const { openGroupDetail, closeDetail } = await import('./detail.js');
const { S } = await import('./state.js');

const python = {
  kind: 'base', name: 'docker.io/python', source: 'docker.io/python:3.12.3',
  current: '3.12.3', latest: '3.14.7', available: true, resolved: true, actionable: true,
};

function deployment(repo, tag, account, over = {}) {
  return {
    image: `acr.io/${repo}:${tag}`, repository: repo, tag, registry: 'acr.io',
    owner: { class: 'engineering', team: 'data-platform', rule: 'by-label' },
    counts: { critical: 10, high: 20 }, provider_assessed: true, scanned: true,
    exploit_checked: true, remediation_checked: true, in_flight_checked: true,
    exposure: 'internal', signals: [], vulns: [], workload_count: 1,
    dimensions: { account: [account], namespace: [repo] },
    priority: 'medium', reasons: ['matched actionable rule "any-critical"'],
    upgrade: python,
    ...over,
  };
}

test('deployments of one service collapse into one work item', () => {
  const groups = groupFindings([
    deployment('topnotch', 'V3_20.905922', 'Development US'),
    deployment('topnotch', 'V3_20.907474', 'PreProduction US'),
    deployment('topnotch', 'V3_20.913952', 'Production US'),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].findings.length, 3);
  assert.equal(groups[0].tags.length, 3);
});

test('services sharing a base stay separate: they are separate rebuilds', () => {
  const groups = groupFindings([
    deployment('topnotch', '1', 'Development US'),
    deployment('data-mcp-tools', '1', 'Development UK'),
  ]);
  assert.equal(groups.length, 2, 'one base, two services, two pieces of work');
});

test('one repository owned by two teams never merges', () => {
  // Two repositories on this estate are shared across teams. Merging them would make
  // a row that belongs to nobody and break the team filter.
  const groups = groupFindings([
    deployment('airstrike', '1', 'Production UK'),
    deployment('airstrike', '2', 'Production UK', { owner: { class: 'engineering', team: 'fdx' } }),
  ]);
  assert.equal(groups.length, 2);
  assert.deepEqual(groups.map((g) => g.owner.team).sort(), ['data-platform', 'fdx']);
});

test('the row reports the worst verdict AND where it came from', () => {
  // The point of an environment-tiered policy is that production differs. A collapsed
  // row saying only "urgent" throws away the answer to "urgent where?".
  const [g] = groupFindings([
    deployment('creditdecision-us', 'dev', 'Development US', { priority: 'medium' }),
    deployment('creditdecision-us', 'prod', 'Production US', {
      priority: 'urgent', reasons: ['matched actionable rule "exploited-fixable-critical"'],
    }),
  ]);
  assert.equal(g.priority, 'urgent');
  const html = GROUP_COLUMNS[0].get(g);
  assert.match(html, /urgent/);
  assert.match(html, /Production US/);
});

test('partial assessment is marked, not averaged away', () => {
  const [g] = groupFindings([
    deployment('app', 'a', 'Production UK'),
    deployment('app', 'b', 'Development UK', { provider_assessed: false, counts: {} }),
  ]);
  assert.deepEqual(g.assessedOf, [1, 2]);
  const html = GROUP_COLUMNS[1].get(g);
  assert.match(html, /10C/, 'the known counts still show');
  assert.match(html, /\*/, 'partial coverage is marked');
  assert.match(html, /worst KNOWN/, 'and explained on hover');
});

test('a group nothing assessed says "?" rather than zero', () => {
  const [g] = groupFindings([
    deployment('app', 'a', 'Production UK', { provider_assessed: false, counts: {} }),
  ]);
  assert.match(GROUP_COLUMNS[1].get(g), /\?/);
});

test('exposure and signals take the worst case across the group', () => {
  const [g] = groupFindings([
    deployment('app', 'a', 'Development UK'),
    deployment('app', 'b', 'Production UK', { exposure: 'public', signals: ['exposed', 'kev'] }),
  ]);
  assert.equal(g.exposure, 'public', 'exposed anywhere is exposed');
  assert.deepEqual(g.signals.sort(), ['exposed', 'kev']);
});

test('exposure stays unknown when nothing reported it', () => {
  const [g] = groupFindings([
    deployment('app', 'a', 'Development UK', { exposure: 'unknown' }),
    deployment('app', 'b', 'Production UK', { exposure: 'unknown' }),
  ]);
  assert.equal(g.exposure, 'unknown', 'no reports must not become "internal"');
});

test('in-flight is only "checked" when every deployment was checked', () => {
  const [g] = groupFindings([
    deployment('app', 'a', 'Development UK'),
    deployment('app', 'b', 'Production UK', { in_flight_checked: false }),
  ]);
  assert.equal(g.in_flight_checked, false,
    'a partially checked group must not claim to have looked');
});

test('the service cell names the tag count and the team', () => {
  const [g] = groupFindings([
    deployment('topnotch', '1', 'Development US'),
    deployment('topnotch', '2', 'Production US'),
  ]);
  const html = GROUP_COLUMNS[2].get(g);
  assert.match(html, /topnotch/);
  assert.match(html, /2 tags/);
  assert.match(html, /data-platform/);
});

test('the group panel lists every deployment and can drill into one', () => {
  const findings = [
    deployment('topnotch', '1', 'Development US'),
    deployment('topnotch', '2', 'Production US', { priority: 'urgent' }),
  ];
  S.queueRows = findings;
  const [g] = groupFindings(findings);
  openGroupDetail(g);
  const el = document.querySelector('#detail');
  assert.equal(el.hidden, false);
  const text = el.textContent;
  assert.match(text, /Deployments/);
  assert.match(text, /Development US/);
  assert.match(text, /Production US/);
  assert.match(text, /promoted forward/);
  // Every deployment row is reachable by keyboard, since that is the drill path.
  const rows = el.querySelectorAll('tbody tr.openable');
  assert.equal(rows.length, 2);
  assert.equal(rows[0].getAttribute('tabindex'), '0');
  closeDetail();
});

test('a ticket link opens the work item it names', async () => {
  // The link a ticket writes carries team and service, so it must resolve to the work
  // item even though tags have moved on since the ticket was raised.
  const { openFromURL } = await import('./detail.js');
  const findings = [
    deployment('topnotch', 'new-tag-since-the-ticket', 'Production US'),
  ];
  S.queueRows = findings;
  const groups = groupFindings(findings);
  dom.reconfigure({ url: 'http://x/?service=topnotch&team=data-platform' });
  globalThis.location = dom.window.location;
  const missed = openFromURL(groups, null);
  assert.equal(missed, '', 'the link should have opened something');
  assert.equal(document.querySelector('#detail').hidden, false);
  closeDetail();
});

test('a link naming something gone says so instead of opening the nearest thing', async () => {
  // Quietly showing a different service than the one somebody clicked through for is
  // worse than showing them nothing.
  const { openFromURL } = await import('./detail.js');
  S.queueRows = [];
  dom.reconfigure({ url: 'http://x/?service=deleted-service&team=data-platform' });
  globalThis.location = dom.window.location;
  const missed = openFromURL(groupFindings([]), null);
  assert.match(missed, /deleted-service/);
  assert.match(missed, /already be fixed|filter/);
  assert.equal(document.querySelector('#detail').hidden, true);
});

test('one deployment running everywhere claims no environment', async () => {
  // The nats-server-config-reloader case: a single deployment in six accounts. It is
  // urgent in all of them, and naming the alphabetically first ("Development UK")
  // invented a distinction the policy never drew.
  const [g] = groupFindings([
    deployment('nats-server-config-reloader', '0.14.0', 'Development UK', {
      priority: 'urgent',
      dimensions: {
        account: ['Development UK', 'Development US', 'PreProduction UK',
                  'PreProduction US', 'Production UK', 'Production US'],
        namespace: ['argo-events'],
      },
    }),
  ]);
  assert.equal(g.worstWhere, '', 'no environment distinguishes a single deployment');
  const html = GROUP_COLUMNS[0].get(g);
  assert.doesNotMatch(html, /Development UK/);
  assert.match(html, /any-critical|exploited/, 'the rule is shown instead');
});

test('deployments that agree claim no environment either', async () => {
  const [g] = groupFindings([
    deployment('app', 'a', 'Production UK', { priority: 'high' }),
    deployment('app', 'b', 'Development UK', { priority: 'high' }),
  ]);
  assert.equal(g.worstWhere, '', 'nothing to distinguish when the verdicts match');
});

test('a deployment spanning accounts is counted, not picked from', async () => {
  // Where the deployments DO disagree but the worst one runs in several places,
  // saying "3 accounts" is true where naming one would not be.
  const [g] = groupFindings([
    deployment('app', 'a', 'Development UK', { priority: 'low' }),
    deployment('app', 'b', 'Production UK', {
      priority: 'urgent',
      dimensions: { account: ['Production UK', 'Production US', 'PreProduction UK'], namespace: ['app'] },
    }),
  ]);
  assert.equal(g.worstWhere, '3 accounts');
});

test('drilling into a deployment does not close the panel', async () => {
  // The click re-renders the panel, which detaches the row that was clicked — and a
  // detached node is inside nothing, so the click-away handler saw it as an outside
  // click and closed everything.
  const { initDetail, openGroupDetail } = await import('./detail.js');
  document.body.insertAdjacentHTML('beforeend',
    '<table id="cves"><tbody></tbody></table>');
  initDetail();
  const findings = [
    deployment('topnotch', '1', 'Development US'),
    deployment('topnotch', '2', 'Production US', { priority: 'urgent' }),
  ];
  S.queueRows = findings;
  openGroupDetail(groupFindings(findings)[0]);
  const row = document.querySelector('#detail tbody tr.openable');
  row.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }));
  const el = document.querySelector('#detail');
  assert.equal(el.hidden, false, 'the panel must stay open');
  assert.match(el.textContent, /Verdict/, 'and show the deployment it drilled into');
  closeDetail();
});
