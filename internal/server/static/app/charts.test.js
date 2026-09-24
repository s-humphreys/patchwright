import { test } from 'node:test';
import assert from 'node:assert/strict';

test('a period is labelled by month for monthly buckets and by date for weekly ones', async () => {
  const { periodLabel } = await import('./charts.js');
  const month = [Date.UTC(2026, 8, 1), Date.UTC(2026, 9, 1)].map((t) => t / 1000);
  const week = [Date.UTC(2026, 8, 7), Date.UTC(2026, 8, 14)].map((t) => t / 1000);
  assert.equal(periodLabel(month[1], month), '2026-10');
  assert.equal(periodLabel(week[1], week), '2026-09-14');
});

test('the value axis is wide enough for its widest label', async () => {
  const { axisWidth } = await import('./charts.js');
  assert.ok(axisWidth(['245,739']) >= 7 * 8);
  assert.equal(axisWidth(null), 40);
});
