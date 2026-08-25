import { $ } from './util.js';

// Filter state in the URL, so a view can be shared.
//
// "The exposed, fixable findings owned by cpe" is the sentence somebody wants to send
// to somebody else, and until now the only way was a screenshot plus instructions.
// A link also survives the refresh, so an hourly poll does not quietly reset what the
// reader had narrowed down to.
//
// Written with replaceState rather than pushState: narrowing a filter is not
// navigation, and filling somebody's back button with twelve intermediate states makes
// the browser's back gesture useless for actually leaving the page.

/**
 * Controls that make up a shareable view, mapped to their query parameter. Checkboxes
 * are stored only when they differ from their default, so a plain link stays short.
 * @type {{id: string, param: string, kind: 'value'|'check', dflt?: boolean}[]}
 */
const CONTROLS = [
  { id: '#classFilter', param: 'class', kind: 'value' },
  { id: '#teamFilter', param: 'team', kind: 'value' },
  { id: '#fixFilter', param: 'fix', kind: 'value' },
  { id: '#signalFilter', param: 'signal', kind: 'value' },
  { id: '#search', param: 'q', kind: 'value' },
  { id: '#onlyFixable', param: 'fixable', kind: 'check', dflt: false },
  { id: '#onlyActionable', param: 'actionable', kind: 'check', dflt: true },
  { id: '#showSuppressed', param: 'suppressed', kind: 'check', dflt: false },
  { id: '#groupRows', param: 'grouped', kind: 'check', dflt: true },
];

/** writeURL reflects the current controls into the address bar. */
export function writeURL() {
  const params = new URLSearchParams();
  for (const c of CONTROLS) {
    const el = /** @type {HTMLInputElement} */ ($(c.id));
    if (!el) continue;
    if (c.kind === 'check') {
      if (el.checked !== c.dflt) params.set(c.param, String(el.checked));
    } else if (el.value) {
      params.set(c.param, el.value);
    }
  }
  const query = params.toString();
  history.replaceState(null, '', query ? `?${query}` : location.pathname);
}

/**
 * readURL applies the address bar to the controls. Returns true when it changed
 * anything, so the caller can avoid a pointless re-render on a plain load.
 *
 * A value naming an option that no longer exists (a team that has gone away, a signal
 * nothing carries today) is left unset rather than forced: a filter matching nothing
 * looks identical to an empty queue, and that is the wrong thing for a stale link to
 * do to somebody.
 */
export function readURL() {
  const params = new URLSearchParams(location.search);
  let changed = false;
  for (const c of CONTROLS) {
    if (!params.has(c.param)) continue;
    const el = /** @type {HTMLInputElement} */ ($(c.id));
    if (!el) continue;
    const raw = params.get(c.param);
    if (c.kind === 'check') {
      el.checked = raw === 'true';
      changed = true;
      continue;
    }
    if (el.tagName === 'SELECT') {
      const sel = /** @type {HTMLSelectElement} */ (/** @type {unknown} */ (el));
      const known = Array.from(sel.options).some((o) => o.value === raw);
      if (!known) continue;
    }
    el.value = raw;
    changed = true;
  }
  return changed;
}
