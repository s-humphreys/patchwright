// The analytics page in a browser: the movement section, then what to fix first.
//
// Everything here needs a real DOM: charts drawn to a canvas, a details element
// that opens, a select that navigates. The rules under test are the same honesty
// rules as the unit tests, checked where they finally land, on the page.
import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const fixture = (name) => readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8').then(JSON.parse);

test.describe('analytics page', () => {
  test('opens with a collapsed note carrying the record start, then the movement panels, then what to fix', async ({ page }) => {
    await page.goto('/analytics');
    const note = page.locator('details.history-notes');
    await expect(note).toBeVisible();
    await expect(note).not.toHaveAttribute('open', '');
    await expect(note.locator('summary')).toContainText('the record begins 2026-09-21');

    await note.locator('summary').click();
    await expect(note).toHaveAttribute('open', '');
    await expect(note).toContainText('A work item is one service');

    // Order on the page: movement before "what to fix first".
    const headings = await page.locator('h2, h3').allTextContents();
    const movement = headings.findIndex((h) => h.startsWith('Movement'));
    const wins = headings.findIndex((h) => h.startsWith('Biggest wins'));
    expect(movement).toBeGreaterThan(-1);
    expect(wins).toBeGreaterThan(movement);
  });

  test('the direction panel says which way and draws an interactive chart for three periods', async ({ page }) => {
    await page.goto('/analytics');
    const direction = page.locator('section.panel', { hasText: 'Direction' });
    await expect(direction).toContainText('198,120');
    // 245739 -> 198120 is a 19% fall.
    await expect(direction.locator('.ok')).toContainText('down 19% since 2026-09');

    const chart = direction.locator('[data-chart="direction"]');
    await expect(chart.locator('canvas')).toHaveCount(1);
    await expect(chart.locator('.u-legend')).toContainText('risk sum');
    await expect(chart.locator('.u-legend')).toContainText('KEV items');

    // Hovering the plot moves the cursor and fills the legend with that period's
    // values: the interaction the tables cannot offer.
    const over = chart.locator('.u-over');
    const box = await over.boundingBox();
    await page.mouse.move(box.x + box.width * 0.5, box.y + box.height * 0.5);
    await expect(chart.locator('.u-legend .u-value').nth(1)).not.toHaveText('--');
  });

  test('movement keeps the baseline apart from opened and shows CVEs cleared beside the items', async ({ page }) => {
    await page.goto('/analytics');
    const movement = page.locator('section.panel', { hasText: 'Movement, in work items' });
    await expect(movement.locator('dt', { hasText: 'Already open when the record began' })).toHaveCount(0);
    await expect(movement).toContainText('303');
    // 42 + 31 + 18 opened; 9 + 47 + 33 fixed; 11710 CVEs cleared; 32 left without a fix.
    await expect(movement).toContainText('91 opened');
    await expect(movement).toContainText('89');
    await expect(movement).toContainText('clearing 11,710 CVEs (36 known-exploited)');
    await expect(movement).toContainText('32 left without a fix');
    // The unit is defined once, directly under the heading.
    await expect(movement.locator('h3 + p.unit')).toContainText('A work item is one service and the one upgrade that would fix it.');
    await expect(movement.locator('h3 + p.unit')).toContainText('Fixed (confirmed) means it left the queue with evidence the upgrade landed');
    await expect(movement.locator('[data-chart="movement"] .u-legend')).toContainText('fixed (confirmed)');
    await expect(movement.locator('[data-chart="movement"] .u-legend')).toContainText('left without a fix');
    await expect(movement.locator('[data-chart="movement"] canvas')).toHaveCount(1);

    const header = movement.locator('table.mini thead');
    await expect(header).toContainText('Baseline');
    await expect(header).toContainText('CVEs cleared');
    await expect(header).toContainText('Fixed (confirmed)');
    await expect(header).toContainText('Left without a fix');
    await expect(header).not.toContainText(/resolved|lapsed/i);
    // Lapse reasons live on the cell's tooltip rather than as a line under the table.
    const lapsedCell = movement.locator('tbody tr', { hasText: '2026-10' }).locator('td[title*="no longer reported"]');
    await expect(lapsedCell).toHaveCount(1);
  });

  test('the delineation shows ticketed resolutions as a subset and flags tickets closed with the finding open', async ({ page }) => {
    await page.goto('/analytics');
    const panel = page.locator('section.panel', { hasText: 'Total remediation against ticketed work' });
    // 49 unticketed + 40 ticketed = 89, 45% ticketed.
    await expect(panel).toContainText('89');
    await expect(panel).toContainText('40');
    await expect(panel).toContainText('(45%) were ticketed work');
    // Two closed with the finding open, and October's overdue closes.
    await expect(panel.locator('td.warn')).toHaveCount(3);
    await expect(panel).toContainText('upgrade-landed 27');
  });

  test('ticket closes are measured against the due date, and overdue open tickets are called out', async ({ page }) => {
    await page.goto('/analytics');
    const panel = page.locator('section.panel', { hasText: 'Total remediation against ticketed work' });
    await expect(panel.locator('th', { hasText: 'Closed on time / overdue' })).toHaveCount(1);
    await expect(panel.locator('table.mini:not(.cycle-time) tbody tr', { hasText: '2026-10' })).toContainText('19 / 3');
    // 34 of 37 on time; (4.5 * 22 + 9 * 15) / 37 = 6.3 days to spare.
    await expect(panel).toContainText('Against the due date: 34 of 37 (92%) closed on time. On average 6.3 days to spare.');
    const open = page.locator('section.panel', { hasText: 'Open now, as the record holds it' });
    await expect(open.locator('.stat.warn', { hasText: 'tickets past their due date' }).locator('.stat-value')).toHaveText('4');
  });

  test('cycle time from the tracker sits in the ticketed panel, reaches back before the record, and dates closes on open items', async ({ page }) => {
    await page.goto('/analytics');
    const panel = page.locator('section.panel', { hasText: 'Total remediation against ticketed work' });
    await expect(panel.locator('h4')).toHaveText(['Cycle time, from the tracker', 'Tickets created, per day']);
    const table = panel.locator('table.cycle-time');
    await expect(table.locator('th')).toHaveText([
      'Period', 'Tickets raised', 'Tickets closed',
      'Finding to ticket, median days', 'Ticket to In Progress, median days', 'In Progress to resolved, median days',
    ]);
    // August is before the record began: the tracker's own counts are the backfill,
    // with no cycle time because nothing it resolved had both endpoints known.
    const august = table.locator('tbody tr', { hasText: '2026-08' });
    await expect(august.locator('td')).toHaveText(['2026-08', '7', '5', '-', '-', '-']);
    const october = table.locator('tbody tr', { hasText: '2026-10' });
    await expect(october).toContainText('1.5 n=14');
    await expect(october).toContainText('9.5 n=20');
    await expect(october.locator('td[title="median over 20 tickets resolved in 2026-10"]')).toHaveCount(2);
    // The table adds nothing to the warnings the delineation already counts.
    await expect(panel.locator('td.warn')).toHaveCount(3);

    const open = page.locator('section.panel', { hasText: 'Open now, as the record holds it' });
    await expect(open).toContainText('ticket closed, finding open');
    const closed = open.locator('.stat', { hasText: 'ticket closed, finding open' });
    await expect(closed.locator('.stat-value')).toHaveText('3');
    await expect(closed.locator('.stat-sub')).toHaveText('since the close: 0-7 days 1 · 30-90 days 2');
  });

  test('tickets created per day: clicking a bar lists that day\'s tickets, and clicking it again hides them', async ({ page }) => {
    const { tickets } = await fixture('history-tickets.json');
    const day = tickets.days.findIndex((d) => d.date === '2026-10-06');
    await page.goto('/analytics');
    const panel = page.locator('section.panel', { hasText: 'Total remediation against ticketed work' });
    await expect(panel.locator('h4', { hasText: 'Tickets created, per day' })).toHaveCount(1);
    const chart = panel.locator('[data-chart="tickets-per-day"]');
    await expect(chart.locator('canvas')).toHaveCount(1);

    const list = panel.locator('#ticketDayList');
    await expect(list).toBeHidden();
    const over = chart.locator('.u-over');
    // The panel is below the fold, and the mouse only reaches what is on screen.
    await over.scrollIntoViewIfNeeded();
    const box = await over.boundingBox();
    // One bar per day across the plot, each centred in its slot.
    const x = box.x + box.width * ((day + 0.5) / tickets.days.length);
    await page.mouse.move(x, box.y + box.height * 0.8);
    // Hover names the day and its count, as the other charts do.
    await expect(chart.locator('.u-legend .u-value').nth(0)).toHaveText('2026-10-06');
    await expect(chart.locator('.u-legend .u-value').nth(1)).toHaveText('3');
    await page.mouse.click(x, box.y + box.height * 0.8);

    await expect(list).toBeVisible();
    await expect(list).toContainText('3 tickets created 6 Oct 2026');
    await expect(list.locator('tbody tr')).toHaveCount(3);
    const link = list.locator('a', { hasText: 'DVOP-4351' });
    await expect(link).toHaveAttribute('href', /\/browse\/DVOP-4351$/);
    await expect(link).toHaveAttribute('target', '_blank');
    await expect(link).toHaveAttribute('rel', 'noopener');
    await expect(list.locator('tbody tr', { hasText: 'DVOP-4352' })).toContainText('engineering|payments|payments-api|payments-api');
    await expect(panel.locator('.day-pick[data-day="2026-10-06"]')).toHaveAttribute('aria-pressed', 'true');

    await page.mouse.click(x, box.y + box.height * 0.8);
    await expect(list).toBeHidden();
    await expect(panel.locator('.day-pick[data-day="2026-10-06"]')).toHaveAttribute('aria-pressed', 'false');
  });

  test('tickets created per day can be reached from the keyboard, and Close hands focus back', async ({ page }) => {
    await page.goto('/analytics');
    const panel = page.locator('section.panel', { hasText: 'Total remediation against ticketed work' });
    const picks = panel.locator('.day-pick');
    // A button per day that had tickets, and none for the empty days.
    await expect(picks).toHaveCount(6);
    const pick = panel.locator('.day-pick[data-day="2026-10-20"]');
    await pick.focus();
    await page.keyboard.press('Enter');
    const list = panel.locator('#ticketDayList');
    await expect(list).toBeVisible();
    await expect(list).toContainText('Upgrade grafana to 12.3');
    await list.getByRole('button', { name: 'Close' }).press('Enter');
    await expect(list).toBeHidden();
    await expect(pick).toBeFocused();
  });

  test('no tickets in the range means no tickets chart, and a failed tickets request costs nothing else', async ({ page }) => {
    const { tickets } = await fixture('history-tickets.json');
    const empty = { status: { enabled: true }, tickets: { ...tickets, total: 0, days: tickets.days.map((d) => ({ ...d, created: 0, tickets: [] })) } };
    await page.route('**/api/v1/history/tickets*', (route) => route.fulfill({ json: empty }));
    await page.goto('/analytics');
    const panel = page.locator('section.panel', { hasText: 'Total remediation against ticketed work' });
    await expect(panel.locator('h4', { hasText: 'Cycle time' })).toHaveCount(1);
    await expect(panel.locator('[data-chart="tickets-per-day"]')).toHaveCount(0);

    await page.unroute('**/api/v1/history/tickets*');
    await page.route('**/api/v1/history/tickets*', (route) => route.fulfill({ status: 503, json: { error: 'history store: down' } }));
    await page.reload();
    await expect(panel.locator('h4', { hasText: 'Cycle time' })).toHaveCount(1);
    await expect(panel.locator('[data-chart="tickets-per-day"]')).toHaveCount(0);
    await expect(page.locator('#history')).not.toContainText('Could not load history');
  });

  test('by rule and by team are gone, and open work items by signal is a stacked chart with EPSS decay under it', async ({ page }) => {
    await page.goto('/analytics');
    await expect(page.locator('h3', { hasText: 'By rule' })).toHaveCount(0);
    await expect(page.locator('h3', { hasText: /by team/i })).toHaveCount(0);
    await expect(page.locator('h3', { hasText: /^Work items by signal$/ })).toHaveCount(0);
    const signals = page.locator('section.panel', { has: page.locator('h3', { hasText: 'Open work items by signal' }) });
    await expect(signals).toContainText('Each work item is counted once, under its most severe signal');
    const chart = signals.locator('[data-chart="signals"]');
    await expect(chart.locator('canvas')).toHaveCount(1);
    const legend = chart.locator('.u-legend');
    for (const label of ['open with a signal', 'Known exploited', 'EPSS above 0.5', 'Fixable critical', 'End-of-life base']) {
      await expect(legend).toContainText(label);
    }
    // Hover the last bar: the legend gives each band's own count and the bar's total,
    // which is the sum of the bands, not a double count.
    const over = chart.locator('.u-over');
    await over.scrollIntoViewIfNeeded();
    const box = await over.boundingBox();
    await page.mouse.move(box.x + box.width * (2.5 / 3), box.y + box.height * 0.9);
    await expect(legend.locator('.u-value').nth(0)).toHaveText('2026-11');
    await expect(legend.locator('.u-value').nth(1)).toHaveText('144');
    await expect(legend.locator('tr', { hasText: 'Known exploited' }).locator('.u-value')).toHaveText('22');
    await expect(legend.locator('tr', { hasText: 'End-of-life base' }).locator('.u-value')).toHaveText('9');

    await expect(signals.locator('dt', { hasText: 'EPSS decayed below 0.5' })).toHaveCount(1);
    await expect(signals.locator('dd').first()).toContainText('35');
    await expect(signals).toContainText('Became known-exploited while open');
    // Periods recorded before exposure was removed still carry the signal; the page
    // must not bring it back as a band.
    await expect(signals).not.toContainText(/exposed/i);
  });

  test('a single period gets numbers and no chart', async ({ page }) => {
    const body = await fixture('history.json');
    body.history.risk = body.history.risk.slice(-1);
    body.history.movement = body.history.movement.slice(-1);
    await page.route('**/api/v1/history*', (route) => route.fulfill({ json: body }));
    await page.goto('/analytics');
    await expect(page.locator('section.panel', { hasText: 'Direction' })).toContainText('a point, not a direction');
    // The tickets chart is per day, not per period, so it is the one chart left.
    await expect(page.locator('.chart-slot:not([data-chart="tickets-per-day"])')).toHaveCount(0);
    await expect(page.locator('[data-chart="direction"] canvas, [data-chart="movement"] canvas, [data-chart="signals"] canvas')).toHaveCount(0);
    await expect(page.locator('section.panel', { has: page.locator('h3', { hasText: 'Open work items by signal' }) }))
      .toContainText('At the end of 2026-11: Known exploited 22 · EPSS above 0.5 9 · Fixable critical 104 · End-of-life base 9, 144 in all.');
  });

  test('history switched off says so and leaves the rest of the page intact', async ({ page }) => {
    await page.route('**/api/v1/history*', (route) => route.fulfill({
      json: { status: { enabled: false }, history: { enabled: false, risk: [], movement: [], caveats: ['history is not enabled'] } },
    }));
    await page.goto('/analytics');
    await expect(page.locator('#history')).toContainText('History is not enabled');
    await expect(page.locator('#analytics')).toContainText('Biggest wins');
  });

  test('a history store outage is one line, and never hides what to fix first', async ({ page }) => {
    await page.route('**/api/v1/history*', (route) => route.fulfill({ status: 503, json: { error: 'history store: connection refused' } }));
    await page.goto('/analytics');
    await expect(page.locator('#history')).toContainText('Could not load history: Error: HTTP 503');
    await expect(page.locator('#analytics')).toContainText('Biggest wins');
    await expect(page.locator('#analytics')).toContainText('3664 of 4890');
  });

  test('the lookback selector carries the view in the URL', async ({ page }) => {
    await page.goto('/analytics');
    await page.locator('#historyRange select[name="since"]').selectOption('365d');
    await page.waitForURL(/since=365d/);
    await expect(page.locator('#historyRange select[name="since"]')).toHaveValue('365d');
    await page.locator('#historyRange select[name="bucket"]').selectOption('week');
    await page.waitForURL(/bucket=week/);
    expect(page.url()).toContain('since=365d');
  });

  test('the team table and the notes are gone, and the estate leverage is one line under the wins', async ({ page }) => {
    await page.goto('/analytics');
    await expect(page.locator('#analytics')).not.toContainText('not a ranking');
    await expect(page.locator('#analytics')).not.toContainText('What this page cannot tell you');
    await expect(page.locator('#analytics section.panel', { hasText: 'Biggest wins' })).toContainText('Across the estate a rebuild clears 3664 of 4890 CVEs (75%)');
  });

  test('light mode renders the charts too', async ({ browser }) => {
    const ctx = await browser.newContext({ colorScheme: 'light' });
    const page = await ctx.newPage();
    await page.goto('/analytics');
    await expect(page.locator('[data-chart="direction"] canvas')).toHaveCount(1);
    await expect(page.locator('[data-chart="signals"] canvas')).toHaveCount(1);
    await expect(page.locator('[data-chart="tickets-per-day"] canvas')).toHaveCount(1);
    await ctx.close();
  });
});
