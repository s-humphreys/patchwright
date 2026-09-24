// The queue page in a browser: it opens on the queue, not on a row of headline
// tiles, and the filters that could narrow to what the tiles counted are still there.
import { test, expect } from '@playwright/test';

test.describe('queue page', () => {
  test('has no summary tiles and still renders the queue', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#findings tbody tr')).toHaveCount(2);
    await expect(page.locator('#findings')).toContainText('payments-api');

    await expect(page.locator('#tiles')).toHaveCount(0);
    await expect(page.locator('.tile, .tilegroup')).toHaveCount(0);
    await expect(page.getByText('What the scan found, and what is left')).toHaveCount(0);
    await expect(page.getByText('The sharp end')).toHaveCount(0);
    await expect(page.getByText('what these mean')).toHaveCount(0);
  });

  test('known-exploited and end-of-life are still reachable through the signal filter', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('#findings tbody tr')).toHaveCount(2);
    const filter = page.locator('#signalFilter');
    await filter.locator('summary').click();
    const menu = filter.locator('.ms-menu');
    await expect(menu).toContainText('kev');
    await expect(menu).toContainText('end-of-life');
  });
});
