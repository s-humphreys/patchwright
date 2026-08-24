import { closeDetail } from './detail.js';
import { $ } from './util.js';

// Two views of one dataset. Which one is showing is part of the shareable URL, so
// "the CVEs, ranked" is a link somebody can send rather than a set of instructions.

const TABS = [
  { tab: '#tabQueue', panel: '#panelQueue', name: 'queue' },
  { tab: '#tabCVEs', panel: '#panelCVEs', name: 'cves' },
];

/** current names the visible view. */
export function current() {
  const on = TABS.find((t) => /** @type {any} */ ($(t.tab)).getAttribute('aria-selected') === 'true');
  return on ? on.name : 'queue';
}

/** show switches view. Closing the panel is deliberate: it describes one row of the
 *  view being left, and leaving it open over a different table is disorienting. */
export function show(name) {
  for (const t of TABS) {
    const selected = t.name === name;
    $(t.tab).setAttribute('aria-selected', String(selected));
    /** @type {any} */ ($(t.panel)).hidden = !selected;
  }
  closeDetail();
  const params = new URLSearchParams(location.search);
  if (name === 'queue') params.delete('view');
  else params.set('view', name);
  const q = params.toString();
  history.replaceState(null, '', q ? `?${q}` : location.pathname);
}

/** initTabs wires the switch and restores the view named in the URL. */
export function initTabs(onShow) {
  for (const t of TABS) {
    $(t.tab).addEventListener('click', () => {
      show(t.name);
      onShow(t.name);
    });
  }
  const want = new URLSearchParams(location.search).get('view');
  if (want && TABS.some((t) => t.name === want)) {
    show(want);
    onShow(want);
  }
}
