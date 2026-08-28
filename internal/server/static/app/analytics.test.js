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
    estate: team({ team: '', class: '' }),
    age_bucket_order: ['0-7d', '7-30d', '30-90d', '90-180d', '180d+'],
    notes: ['Ticket resolution time is not shown.'],
    stale_fix_days: 30,
    ...over,
  };
}

test('the headline names the worst thing, not a row of numbers', () => {
  // A row of numbers makes each reader interpret for themselves, and they reach
  // different conclusions from the same row.
  const out = render(view());
  assert.match(out, /3<\/strong> fixes available for over\s*30 days that nobody has started/);
});

test('a team with everything started is said to be fine, not left ambiguous', () => {
  const out = render(view({ teams: [team({
    stale_unstarted: 0, unstarted: 0, in_flight_stale: 0, kev: 2, kev_fixable: 2,
  })] }));
  assert.match(out, /everything actionable is started or tracked/);
});

test('known-exploited findings with no fix outrank merely unstarted ones', () => {
  const out = render(view({ teams: [team({
    stale_unstarted: 0, kev: 5, kev_fixable: 1, unstarted: 2,
  })] }));
  assert.match(out, /4<\/span> known-exploited findings with no upgrade available/);
});

test('stale pull requests are called a review bottleneck, not an engagement problem', () => {
  // The distinction changes who the conversation is with.
  const out = render(view({ teams: [team({
    stale_unstarted: 0, kev: 0, kev_fixable: 0, in_flight_stale: 4,
  })] }));
  assert.match(out, /review bottleneck/);
});

test('an undated team says so instead of showing zero days', () => {
  // Zero reads as "found today", which is the opposite of "we never looked".
  const out = render(view({ teams: [team({ median_age_days: null, p90_age_days: null })] }));
  assert.match(out, /not dated/);
  assert.doesNotMatch(out, /median <strong>0d/);
});

test('unassessed findings are surfaced, since they can fake responsiveness', () => {
  const out = render(view({ teams: [team({ unassessed: 12 })] }));
  assert.match(out, /12<\/span> findings the provider never looked at/);
});

test('base leverage says how much of the queue is not the team\'s to fix', () => {
  const out = render(view());
  assert.match(out, /clears <strong>500<\/strong> of 1000 CVEs/);
  assert.match(out, /50%/);
});

test('the notes are rendered, not just carried in the payload', () => {
  const out = render(view());
  assert.match(out, /What this page cannot tell you/);
  assert.match(out, /Ticket resolution time is not shown/);
});

test('an empty estate says so rather than rendering an empty grid', () => {
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
