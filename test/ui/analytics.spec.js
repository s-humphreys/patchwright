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
    await expect(movement).toContainText('Already open when the record began');
    await expect(movement).toContainText('303');
    // 42 + 31 + 18 opened; 9 + 47 + 33 resolved; 11710 CVEs cleared; 32 lapsed.
    await expect(movement).toContainText('91 opened');
    await expect(movement).toContainText('89');
    await expect(movement).toContainText('clearing 11,710 CVEs (36 known-exploited)');
    await expect(movement).toContainText('32 lapsed');
    await expect(movement.locator('[data-chart="movement"] canvas')).toHaveCount(1);

    const header = movement.locator('table.mini thead');
    await expect(header).toContainText('Baseline');
    await expect(header).toContainText('CVEs cleared');
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
    await expect(panel.locator('td.warn')).toHaveCount(2);
    await expect(panel).toContainText('upgrade-landed 27');
  });

  test('by rule is gone and the signal table is in work items with EPSS decay apart', async ({ page }) => {
    await page.goto('/analytics');
    await expect(page.locator('h3', { hasText: 'By rule' })).toHaveCount(0);
    const signals = page.locator('section.panel', { hasText: 'Work items by signal' });
    await expect(signals).toContainText('Known exploited');
    await expect(signals).toContainText('EPSS decayed below 0.5');
    await expect(signals.locator('dd').first()).toContainText('35');
  });

  test('a single period gets numbers and no chart', async ({ page }) => {
    const body = await fixture('history.json');
    body.history.risk = body.history.risk.slice(-1);
    body.history.movement = body.history.movement.slice(-1);
    await page.route('**/api/v1/history*', (route) => route.fulfill({ json: body }));
    await page.goto('/analytics');
    await expect(page.locator('section.panel', { hasText: 'Direction' })).toContainText('a point, not a direction');
    await expect(page.locator('.chart-slot')).toHaveCount(0);
    await expect(page.locator('canvas')).toHaveCount(0);
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
    await ctx.close();
  });
});
