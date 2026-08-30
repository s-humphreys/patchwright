// The analytics page: who is moving and who is not.
//
// The rules under test are mostly about honesty. A page that names teams has to
// be right about them, and every metric here can be wrong in a way that sends a
// security engineer to the wrong conversation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;

const { render } = await import('./analytics.js');
const { barChart, stackedBar } = await import('./charts.js');

function team(over = {}) {
  return {
    class: 'engineering', team: 'orders',
    findings: 10, actionable: 8,
    median_age_days: 40, p90_age_days: 120,
    age_buckets: { '0-7d': 1, '7-30d': 2, '30-90d': 3, '90-180d': 1, '180d+': 1 },
    fixable: 6, unstarted: 4, stale_unstarted: 3,
    in_flight: 1, in_flight_stale: 0, in_flight_median_days: 5,
    tickets_open: 1, tickets_untouched: 1,
    kev: 2, kev_fixable: 2,
    base_clears: 500, base_total: 1000,
    unassessed: 0,
    ...over,
  };
}

function view(over = {}) {
  const t = over.teams || [team()];
  return {
    teams: t,
    wins: over.wins || [],
    issues: over.issues || [],
    estate: team({ team: '', class: '' }),
    age_bucket_order: ['0-7d', '7-30d', '30-90d', '90-180d', '180d+'],
    notes: ['Ticket resolution time is not shown.'],
    stale_fix_days: 30,
    ...over,
  };
}

test('the page leads with the biggest win, not with a team', () => {
  // The earlier version ranked teams by how slow they were. That reads as an
  // accusation to whoever is on top, and it is rarely the useful question: most
  // of the leverage is a base image, where one rebuild fixes everything on it.
  const out = render(view({ wins: [{
    from_ref: 'docker.io/python@sha256:aaaaaaaaaaaaaaaa', to_ref: 'docker.io/python:3.14',
    images: 12, teams: 3, clears: 5860, total: 6746, introduces: 284, kev_cleared: 10,
  }] }));
  assert.match(out, /Biggest wins/);
  assert.match(out, /5860/);
  assert.match(out, /12 images/);
  assert.doesNotMatch(out, /who is not/i);
});

test('a win reports what it introduces as well as what it clears', () => {
  // One-sided arithmetic is how a recommendation stops being trusted.
  const out = render(view({ wins: [{
    from_ref: 'b@sha256:aaaaaaaaaaaaaaaa', to_ref: 'b:2',
    images: 1, teams: 1, clears: 100, total: 120, introduces: 7, kev_cleared: 0,
  }] }));
  assert.match(out, /introduces 7/);
});

test('a win that introduces nothing says so rather than staying silent', () => {
  const out = render(view({ wins: [{
    from_ref: 'b@sha256:aaaaaaaaaaaaaaaa', to_ref: 'b:2',
    images: 1, teams: 1, clears: 100, total: 120, introduces: 0, kev_cleared: 0,
  }] }));
  assert.match(out, /introduces none/);
});

test('issues are grouped by what the problem is, with what to do about it', () => {
  const out = render(view({ issues: [{
    key: 'kev-no-fix', title: 'Known-exploited with no upgrade available', count: 3,
    why: 'No version to move to, so it needs a decision.', teams: 2,
    services: [{ service: 'reg/a', images: 2, team: 'orders' }, { service: 'reg/b', images: 1 }],
  }] }));
  assert.match(out, /Not being addressed/);
  assert.match(out, /Known-exploited with no upgrade available/);
  assert.match(out, /needs a decision/, 'a count with no reading is left to interpretation');
  assert.match(out, /2 teams/);
  assert.match(out, />a</);
  assert.match(out, /<details>/, 'a count somebody cannot expand is one they must take on trust');
  assert.match(out, /<table class="mini svc-table">/, 'three fields per row is a table');
  assert.match(out, /href="\/\?service=/, 'each service should open its queue item');
  assert.match(out, /<td class="num">2<\/td>/, 'a service present at several tags says how many');
});

test('with no issues it says so rather than rendering an empty list', () => {
  const out = render(view({ issues: [] }));
  assert.match(out, /Nothing outstanding/);
});

test('with no base differential the wins panel explains how to turn it on', () => {
  const out = render(view({ wins: [] }));
  assert.match(out, /baseDiff/);
});

test('the owner table is framed as context, not a ranking', () => {
  const out = render(view());
  assert.match(out, /not a ranking/);
});

test('unassessed findings are surfaced, since they can fake a quiet team', () => {
  const out = render(view({ teams: [team({ unassessed: 12 })] }));
  assert.match(out, /12/);
  assert.match(out, /Unassessed/);
});

test('base leverage is on the estate summary, since it is the biggest single lever', () => {
  const out = render(view());
  assert.match(out, /clears <strong class="ok">500<\/strong> of 1000 CVEs/);
  assert.match(out, /50%/);
});

test('the notes are rendered, not just carried in the payload', () => {
  const out = render(view());
  assert.match(out, /What this page cannot tell you/);
  assert.match(out, /Ticket resolution time is not shown/);
});

test('an empty estate says so rather than rendering an empty page', () => {
  const out = render(view({ teams: [] }));
  assert.match(out, /No findings/);
});

test('bar charts drop rows with no value rather than drawing a zero-width bar', () => {
  const out = barChart([
    { label: 'a', value: 5 },
    { label: 'b', value: NaN },
  ]);
  assert.match(out, />a</);
  assert.doesNotMatch(out, />b</);
});

test('a stacked bar with nothing in it says so instead of rendering an empty svg', () => {
  assert.match(stackedBar([{ label: 'x', value: 0 }], { empty: 'nothing yet' }), /nothing yet/);
});

test('chart labels are escaped, since team names come from cluster labels', () => {
  const out = barChart([{ label: '<img src=x onerror=alert(1)>', value: 1 }]);
  assert.doesNotMatch(out, /<img/);
  assert.match(out, /&lt;img/);
});

test('a win expands to the services on that base, not every image tag', () => {
  // "156 images" with no list is a number somebody reconstructs by hand, and a
  // list of 156 references is mostly the same services at different tags.
  const out = render(view({ wins: [{
    from_ref: 'b@sha256:aaaaaaaaaaaaaaaa', to_ref: 'b:2',
    images: 5, teams: 1, clears: 100, total: 120, introduces: 0, kev_cleared: 0,
    services: [{ service: 'reg/one', images: 3 }, { service: 'reg/two', images: 2 }],
  }] }));
  assert.match(out, />one</);
  assert.match(out, />two</);
  assert.match(out, /<td class="num">3<\/td>/);
  assert.match(out, /href="\/\?service=one"/);
});

test('service names are escaped and URL-encoded, not concatenated raw', () => {
  const out = render(view({ issues: [{
    key: 'x', title: 't', count: 1, why: 'w', teams: 1,
    services: [{ service: 'reg/<img src=x>', images: 1 }],
  }] }));
  assert.doesNotMatch(out, /<img src=x/);
  assert.match(out, /&lt;img/);
});
