import { select, selected } from './filters.js';
import { $ } from './util.js';

// Filter state in the URL, so a view can be shared.
//
// "The exposed, fixable findings owned by the platform team" is the sentence somebody wants to send
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
 * Facets hold several values at once and travel as a comma-separated list, so
 * "signal=kev,exposed" is a link somebody can send.
 * @type {{id: string, param: string, kind: 'value'|'check'|'facet', dflt?: boolean}[]}
 */
const CONTROLS = [
  { id: '#classFilter', param: 'class', kind: 'facet' },
  { id: '#teamFilter', param: 'team', kind: 'facet' },
  { id: '#fixFilter', param: 'fix', kind: 'facet' },
  { id: '#signalFilter', param: 'signal', kind: 'facet' },
  { id: '#urgencyFilter', param: 'urgency', kind: 'facet' },
  { id: '#search', param: 'q', kind: 'value' },
  { id: '#onlyFixable', param: 'fixable', kind: 'check', dflt: false },
  { id: '#onlyActionable', param: 'actionable', kind: 'check', dflt: true },
  { id: '#showSuppressed', param: 'suppressed', kind: 'check', dflt: false },
  { id: '#groupRows', param: 'grouped', kind: 'check', dflt: true },
];

// What the address bar said when the page loaded, captured before anything writes to
// it. The controls reflect themselves into the URL as soon as the first render
// happens, so by the time a deep link is read the live URL has already been rewritten
// — which is how a shared link opened the queue and cleared itself.
const arrived = new URLSearchParams(location.search);

/** initialQuery is the link the page was opened with, not the one it has since written. */
export function initialQuery() {
  return new URLSearchParams(arrived.toString());
}

/** writeURL reflects the current controls into the address bar.
 *
 *  It edits the existing query rather than rebuilding it: parameters belonging to
 *  something else — which panel is open, which view — are not this function's to
 *  delete, and rebuilding silently dropped them.
 */
export function writeURL() {
  const params = new URLSearchParams(location.search);
  for (const c of CONTROLS) {
    const el = /** @type {HTMLInputElement} */ ($(c.id));
    if (!el) continue;
    if (c.kind === 'facet') {
      const chosen = selected(c.id);
      if (chosen.length) params.set(c.param, chosen.join(','));
      else params.delete(c.param);
      continue;
    }
    if (c.kind === 'check') {
      if (el.checked !== c.dflt) params.set(c.param, String(el.checked));
      else params.delete(c.param);
    } else if (el.value) {
      params.set(c.param, el.value);
    } else {
      params.delete(c.param);
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
export function readURL(params = initialQuery()) {
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
    if (c.kind === 'facet') {
      // Only the values that exist today. A link naming a team that has gone away
      // should open showing the rest of what it asked for, not nothing - and a
      // filter matching nothing looks identical to an empty queue.
      const known = new Set(Array.from(el.querySelectorAll("input[type=checkbox]"))
        .map((b) => /** @type {any} */ (b).value));
      const want = (raw || "").split(",").map((v) => v.trim()).filter((v) => known.has(v));
      if (!want.length) continue;
      select(c.id, want);
      changed = true;
      continue;
    }
    el.value = raw;
    changed = true;
  }
  return changed;
}
