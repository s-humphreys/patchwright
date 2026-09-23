// The history page: movement, and the honesty rules around it.
//
// Every number here can be read as an achievement, which is exactly why the tests
// are about what the page must NOT do: add lapses to resolutions, present ticketed
// resolutions as a total, or show a month before the record began as a quiet one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;

const { render } = await import('./history.js');

function counts(opened = 0, resolved = 0, lapsed = 0, ticketed = 0) {
  return { opened, resolved, lapsed, resolved_ticketed: ticketed };
}

function period(label, over = {}) {
  return {
    period: label, start: `${label}-01T00:00:00Z`, end: `${label}-28T00:00:00Z`,
    baseline: 0, opened: 0, resolved: 0, lapsed: 0, reassigned: 0, cves_resolved: 0, kev_cves_resolved: 0,
    resolved_ticketed: 0, resolved_unticketed: 0,
    tickets_raised: 0, tickets_closed: 0, tickets_closed_finding_open: 0,
    epss_decayed: 0, became_known_exploited: 0,
    ...over,
  };
}

function body(over = {}) {
  return {
    status: { enabled: true, retention_days: 365 },
    history: {
      schema_version: 1, enabled: true, bucket: 'month',
      since: '2026-07-01T00:00:00Z', until: '2026-09-22T00:00:00Z',
      first_recorded: '2026-08-15T10:00:00Z', assessments: 40,
      risk: [
        { period: '2026-08', at: '2026-08-31T23:00:00Z', assessments: 20, findings: 600, actionable: 400, risk: { items: 300, sum: 250000, urgent: 50, known_exploited: 30 } },
        { period: '2026-09', at: '2026-09-21T23:00:00Z', assessments: 20, findings: 560, actionable: 380, risk: { items: 280, sum: 200000, urgent: 45, known_exploited: 28 } },
      ],
      movement: [
        period('2026-07'),
        period('2026-08', { baseline: 280, opened: 20, resolved: 2, lapsed: 1, resolved_ticketed: 1, resolved_unticketed: 1, cves_resolved: 40, kev_cves_resolved: 3,
          by_signal: { kev: counts(30, 1, 0, 1), 'epss-high': counts(55, 0, 1) },
          by_rule: { 'exploited-fixable': counts(40, 1, 0, 1) }, by_team: { cpe: counts(60, 2, 0, 1) } }),
        period('2026-09', { opened: 20, resolved: 5, lapsed: 8, resolved_ticketed: 2, resolved_unticketed: 3,
          tickets_raised: 3, tickets_closed: 4, tickets_closed_finding_open: 1, epss_decayed: 10,
          median_days_to_resolve: 12, lapse_reasons: { 'no longer reported': 6, 'no longer running': 2 },
          tickets_closed_by_tool: { 'not-running': 3 },
          by_signal: { kev: counts(2, 3, 1, 2) }, by_rule: { 'any-critical': counts(5, 1, 2) }, by_team: { cpe: counts(10, 5, 8, 2) } }),
      ],
      open: { items: 280, ticketed: 50, missing: 4, by_signal: { kev: 28 }, age_days: { '0-7': 20, '7-30': 200, '30-90': 60 } },
      caveats: ['the record begins 2026-08-15; periods before it are empty because nothing was watching, not because nothing happened'],
    },
    ...over,
  };
}

test('a disabled store says so instead of rendering an empty record', () => {
  const html = render({ status: { enabled: false }, history: { enabled: false, movement: [], risk: [] } });
  assert.match(html, /History is not enabled/);
  assert.doesNotMatch(html, /Direction/);
});

test('the caveats come first, collapsed, with the record start date on the summary line', () => {
  const html = render(body());
  const first = html.indexOf('Read this first');
  const direction = html.indexOf('Direction');
  assert.ok(first >= 0 && first < direction, 'caveats must precede every chart');
  assert.match(html, /<details class="panel notes history-notes"><summary>Read this first · the record begins 2026-08-15<\/summary>/);
  assert.match(html, /begins <strong>2026-08-15<\/strong>/);
  assert.match(html, /Retention is 365 days/);
});

test('direction compares the first and last periods and says which way', () => {
  const html = render(body());
  // 250000 -> 200000 is a 20% fall.
  assert.match(html, /down 20% since 2026-08/);
  assert.match(html, /200,000/);
});

test('one risk point is a point, not a direction', () => {
  const b = body();
  b.history.risk = b.history.risk.slice(-1);
  assert.match(render(b), /one period only: a point, not a direction/);
});

test('resolved and lapsed are shown apart and never summed, with CVEs cleared beside the items', () => {
  const html = render(body());
  // Across the range: 40 opened (the 280 baseline is apart), 7 resolved clearing 40 CVEs, 9 lapsed.
  assert.match(html, /Already open when the record began<\/dt><dd class="muted">280<\/dd>/);
  assert.match(html, /40 opened · <strong class="ok">7<\/strong> resolved, clearing 40 CVEs \(3 known-exploited\) · <span class="muted">9 lapsed<\/span>/);
  assert.doesNotMatch(html, /16 /);
});

test('every heading says the unit, and the definitions live in the note not under the tables', () => {
  const html = render(body());
  assert.match(html, /Movement, in work items/);
  assert.match(html, /Work items by signal/);
  assert.match(html, /A <strong>work item<\/strong> is one service/);
  assert.doesNotMatch(html, /By rule/);
  // Nothing trails the direction table any more; the explanation is in the note.
  assert.doesNotMatch(html, /A period with one run is a point, not a trend\.<\/p>/);
});

test('a single period gets a number, not a chart', () => {
  const b = body();
  b.history.risk = b.history.risk.slice(-1);
  b.history.movement = b.history.movement.slice(-1);
  const html = render(b);
  assert.doesNotMatch(html, /chart-slot/);
});

test('two or more periods leave a slot for the interactive chart, and mounting without the library is a no-op', async () => {
  const html = render(body());
  assert.match(html, /data-chart="direction"/);
  assert.match(html, /data-chart="movement"/);
  const { mountCharts } = await import('./history.js');
  const root = document.createElement('div');
  root.innerHTML = html;
  mountCharts(root, body());
  // No uPlot in this environment: the slots stay empty and the tables stand.
  assert.equal(root.querySelector('[data-chart="direction"]').innerHTML, '');
});

test('ticketed resolutions are a subset of resolved, with the share stated', () => {
  const html = render(body());
  // 4 unticketed + 3 ticketed = 7 landed, 3 ticketed = 43%.
  assert.match(html, /<strong class="ok">7<\/strong> resolved with evidence, of which <strong>3<\/strong> \(43%\) were ticketed work/);
});

test('a ticket closed with the finding still open is flagged, not counted as done', () => {
  const html = render(body());
  assert.match(html, /<td class="warn">1<\/td>/);
  assert.match(html, /neither resolved nor lapsed/);
  assert.match(html, /not-running 3/);
  assert.match(html, /Closed by patchwright, by reason/);
});

test('the signal split classifies by the opening state and shows EPSS decay apart', () => {
  const html = render(body());
  assert.match(html, /Known exploited/);
  assert.match(html, /EPSS decayed below 0\.5<\/dt><dd>10/);
  // The signal table shows opened / resolved per period: 30 / 1 for KEV in August.
  assert.match(html, /30 \/ <strong class="ok">1<\/strong>/);
});

test('periods with nothing in them are dropped except the latest', () => {
  const html = render(body());
  // July had no events and is not the latest period, so it does not clutter the tables.
  const movementSection = html.slice(html.indexOf('<h3>Movement, in work items</h3>'), html.indexOf('<h3>Total remediation'));
  assert.doesNotMatch(movementSection, /2026-07/);
  assert.match(movementSection, /2026-09/);
});

test('the open summary shows items in the grace period as absent, not gone', () => {
  const html = render(body());
  assert.match(html, /280 · 50 ticketed · <span class="muted">4 absent from the latest run, inside the grace period<\/span>/);
});

test('closes are measured against the due date only once a ticket carried one', () => {
  const html = render(body());
  assert.doesNotMatch(html, /Closed on time \/ overdue/);
  assert.doesNotMatch(html, /Against the due date/);
  assert.doesNotMatch(html, /past their due date/);
});

test('closes against the due date are split per period, with the weighted mean', () => {
  const b = body();
  b.history.movement[1] = { ...b.history.movement[1], tickets_closed: 4, tickets_closed_on_time: 3, tickets_closed_overdue: 1, mean_days_to_due_at_close: 2 };
  b.history.movement[2] = { ...b.history.movement[2], tickets_closed_on_time: 1, tickets_closed_overdue: 1, mean_days_to_due_at_close: -5 };
  const html = render(b);
  assert.match(html, /Closed on time \/ overdue<\/th>/);
  assert.match(html, /<td class="warn">3 \/ 1<\/td>/);
  assert.match(html, /<td class="warn">1 \/ 1<\/td>/);
  // 4 of 6 on time. Weighted by closes, (2*4 - 5*2) / 6 = -0.3 days; the unweighted
  // mean of the two periods would be -1.5.
  assert.match(html, /Against the due date: 4 of 6 \(67%\) closed on time\. On average 0\.3 days late\./);
});

test('a period whose tickets all closed early reads as days to spare', () => {
  const b = body();
  b.history.movement[2] = { ...b.history.movement[2], tickets_closed_on_time: 2, tickets_closed_overdue: 0, mean_days_to_due_at_close: 3.25 };
  const html = render(b);
  assert.match(html, /<td class="">2 \/ 0<\/td>/);
  assert.match(html, /On average 3\.3 days to spare\./);
});

test('open tickets past their due date are called out in the open summary', () => {
  const b = body();
  b.history.open = { ...b.history.open, tickets_overdue_open: 5 };
  const html = render(b);
  assert.match(html, /<span class="warn">5 tickets past their due date<\/span>/);
});

test('without tracker data there is no cycle-time table and no closed-ticket ages', () => {
  const html = render(body());
  assert.doesNotMatch(html, /Cycle time/);
  assert.doesNotMatch(html, /Ticket closed, finding open/);
});

test('cycle time reads the tracker, including periods before the record, and only periods that have data', () => {
  const b = body();
  b.history.tracker = { source: 'tracker', tickets: 40, first_created: '2026-06-02T09:00:00Z', last_synced: '2026-09-21T23:00:00Z' };
  // July is before the record began: the tracker's counts are the backfill.
  b.history.movement[0] = { ...b.history.movement[0], tracker_tickets_raised: 4, tracker_tickets_closed: 2 };
  b.history.movement[1] = { ...b.history.movement[1], tracker_tickets_raised: 0, tracker_tickets_closed: 0 };
  b.history.movement[2] = { ...b.history.movement[2], tracker_tickets_raised: 6, tracker_tickets_closed: 5,
    median_days_told: 1.5, median_days_told_n: 2, median_days_to_start: 3, median_days_to_start_n: 5, median_days_worked: 12.5, median_days_worked_n: 1 };
  const html = render(b);
  const table = html.slice(html.indexOf('<h4>Cycle time, from the tracker</h4>'), html.indexOf('</table>', html.indexOf('<h4>Cycle time')));
  assert.ok(table.length > 0, 'the cycle-time table should render');
  assert.ok(html.indexOf('Cycle time') > html.indexOf('Total remediation against ticketed work'), 'it belongs in the ticketed panel');
  assert.match(table, /<td>2026-07<\/td><td>4<\/td><td>2<\/td>/);
  // August had nothing from the tracker, so no row.
  assert.doesNotMatch(table, /2026-08/);
  assert.match(table, /Finding to ticket, median days/);
  assert.match(table, /1\.5 <span class="sub">n=2<\/span>/);
  assert.match(table, /12\.5 <span class="sub">n=1<\/span>/);
  assert.match(table, /median over 5 tickets resolved in 2026-09/);
  // July resolved nothing with known endpoints: a dash, not a zero.
  assert.match(table, /<td>2026-07<\/td><td>4<\/td><td>2<\/td>\s*<td class="muted">-<\/td>/);
});

test('tracker counts without any cycle time leave the median columns out', () => {
  const b = body();
  b.history.tracker = { source: 'tracker', tickets: 3, last_synced: '2026-09-21T23:00:00Z' };
  b.history.movement[2] = { ...b.history.movement[2], tracker_tickets_raised: 3, tracker_tickets_closed: 1 };
  const html = render(b);
  assert.match(html, /Cycle time, from the tracker/);
  assert.doesNotMatch(html, /median days/);
});

test('the open summary dates tickets closed while the finding stayed open', () => {
  const b = body();
  b.history.open = { ...b.history.open, closed_ticket_finding_open: 3, closed_ticket_age_days: { '0-7': 1, '30-90': 2 } };
  const html = render(b);
  assert.match(html, /Ticket closed, finding open<\/dt>\s*<dd><span class="warn">3<\/span> · since the close: 0-7 days 1 · 30-90 days 2<\/dd>/);

  b.history.open = { ...b.history.open, closed_ticket_finding_open: 0, closed_ticket_age_days: undefined };
  assert.doesNotMatch(render(b), /Ticket closed, finding open/);
});
