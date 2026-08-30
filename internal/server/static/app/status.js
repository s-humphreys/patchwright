import { nav } from './nav.js';
import { $ } from './util.js';

// The freshness line, for the pages that are not the queue.
//
// The queue renders it as part of a full reload. Tickets and analytics have no
// such loop, and without this their header carried an empty status area - which
// reads as "no data" rather than "this page does not refresh itself".
export async function showStatus() {
  const el = $("#freshness");
  if (!el) return;
  try {
    const res = await fetch("/api/v1/summary");
    const s = await res.json();
    const a = s.assessment;
    const { renderFreshness } = await import('./panels.js');
    renderFreshness(a);
    // An assessment already in progress when the page loads must disable the
    // control too, not only one this tab started.
    if (a?.running) nav()?.watch();
  } catch {
    el.textContent = "";
  }
}
