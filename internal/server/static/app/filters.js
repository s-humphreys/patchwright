import { SIGNAL_ORDER } from './badges.js';
import { PRI_RANK, fixPath, ticketsFor, upgradeText } from './cells.js';
import { $, esc } from './util.js';

// The filter bar governs the page, not one table.
//
// It used to filter the queue and nothing else, while sitting above the tabs as though it
// governed both — so the CVE view silently ignored every control above it and showed the
// whole estate. Two things were wrong: the filtered set was computed inside the queue's
// renderer, so no other view could see it; and each dropdown counted its options over a
// different subset, so the numbers beside the options did not describe what picking them
// would do.
//
// One model now. A filter state is read from the controls, one predicate decides whether a
// finding survives it, and every view renders the same surviving set. Which means the CVE
// view, the queue, the grouped-by-service view and anything added later cannot disagree
// about what the reader asked for.
//
// The options are FACETED: each dropdown's options and counts are computed over the rows
// that pass every OTHER filter. So a count beside an option is what you would get by
// choosing it, an option that would return nothing is not offered at all, and narrowing
// one filter visibly narrows the rest.

// UNATTRIBUTED stands for findings no ownership rule could attribute to a team. The API
// treats an empty team parameter as "no filter", so this case cannot be expressed as a
// query and is filtered here instead. It is worth having: an unowned finding is a thing
// to fix in the cluster labels, and being able to list them is how that gets noticed.
//
// A printable token rather than a control character: this value goes into an HTML option
// and into the query string, and a NUL survives neither - it round-tripped as a
// replacement character and the option could not be selected again.
export const UNATTRIBUTED = "__unattributed__";

/**
 * The facets, in the order they appear. Each knows how to read its own value from a
 * finding, how to order its options, and what its "no filter" option says.
 *
 * `values` returns a list because a finding can carry several signals, and a facet that
 * assumed one value per finding would count them wrongly.
 * @type {any[]}
 */
export const FACETS = [
  { name: "class", id: "#classFilter", allLabel: "all classes",
    values: (f) => [f.owner?.class || "-"], order: "count" },
  { name: "team", id: "#teamFilter", allLabel: "all teams",
    values: (f) => [f.owner?.team ? f.owner.team : UNATTRIBUTED], order: "count",
    label: (v) => (v === UNATTRIBUTED ? "(unattributed)" : v) },
  { name: "urgency", id: "#urgencyFilter", allLabel: "any urgency",
    values: (f) => [f.priority || "none"],
    // A severity scale, so worst first. Sorted as text, "high" outranks "urgent" and the
    // first thing a reader reaches for is the wrong one.
    order: (a, b) => (PRI_RANK[b] ?? 0) - (PRI_RANK[a] ?? 0) },
  { name: "signal", id: "#signalFilter", allLabel: "any signal",
    values: (f) => f.signals || [],
    // Fixed order rather than by count: the list is ranked by how much each should
    // change what somebody does next, and that ranking should not move about.
    order: (a, b) => SIGNAL_ORDER.indexOf(a) - SIGNAL_ORDER.indexOf(b) },
  { name: "fix", id: "#fixFilter", allLabel: "all fixes",
    values: (f) => [fixPath(f)],
    order: (a, b) => ["direct", "managed", "none", "unknown", "?"].indexOf(a) -
      ["direct", "managed", "none", "unknown", "?"].indexOf(b) },
];

/** filterState reads every control into one object. */
export function filterState() {
  /** @type {any} */
  const st = { q: ($("#search")?.value || "").trim().toLowerCase(), fixable: false };
  for (const f of FACETS) {
    const el = /** @type {any} */ ($(f.id));
    st[f.name] = el ? el.value : "";
  }
  const fixable = /** @type {any} */ ($("#onlyFixable"));
  st.fixable = !!(fixable && fixable.checked);
  return st;
}

// haystack is what the search box matches against: the fields someone would plausibly
// type a fragment of. Ticket keys are included so "PROJ-12" finds every image a grouped
// ticket covers.
export function haystack(f) {
  const parts = [
    f.image, f.repository, f.registry, f.owner?.team, f.owner?.class, f.priority,
    (f.dimensions?.namespace || []).join(" "),
    (f.dimensions?.account || []).join(" "),
    upgradeText(f), fixPath(f),
    f.in_flight ? `${f.in_flight.title} ${f.in_flight.repository}` : "",
    (f.signals || []).join(" "), f.exposure,
    ticketsFor(f).map((t) => `${t.key} ${t.status}`).join(" "),
  ];
  return parts.filter(Boolean).join(" ").toLowerCase();
}

/**
 * matches decides whether a finding survives the filter state.
 *
 * `except` names one filter to ignore, which is what makes faceting possible: the options
 * for a facet are counted over the rows that pass everything else.
 */
export function matches(f, st, except) {
  for (const facet of FACETS) {
    if (facet.name === except) continue;
    const want = st[facet.name];
    if (!want) continue;
    if (!facet.values(f).includes(want)) return false;
  }
  if (except !== "fix" && st.fixable && !["direct", "managed"].includes(fixPath(f))) {
    return false;
  }
  if (except !== "q" && st.q && !haystack(f).includes(st.q)) return false;
  return true;
}

/** apply returns the findings surviving the filter state, ignoring `except` if given. */
export function apply(rows, st, except) {
  return (rows || []).filter((f) => matches(f, st, except));
}

/**
 * populate rebuilds every dropdown from the rows that pass the other filters.
 *
 * A selected value that no longer matches anything is kept and shown as "(0)" rather than
 * silently cleared: dropping somebody's filter changes what they are looking at without
 * telling them, and an empty table under a visible "(0)" is the honest version.
 */
export function populate(rows, st) {
  for (const facet of FACETS) {
    const sel = /** @type {any} */ ($(facet.id));
    if (!sel) continue;
    const available = apply(rows, st, facet.name);
    const counts = new Map();
    for (const f of available) {
      for (const v of facet.values(f)) counts.set(v, (counts.get(v) || 0) + 1);
    }
    let keys = [...counts.keys()];
    if (facet.order === "count") keys.sort((a, b) => counts.get(b) - counts.get(a));
    else keys.sort(facet.order);

    const chosen = st[facet.name];
    // The selection has to remain selectable even at zero, or the browser silently
    // resets it and the URL and the table stop agreeing.
    if (chosen && !counts.has(chosen)) {
      keys.push(chosen);
      counts.set(chosen, 0);
    }
    const text = (v) => (facet.label ? facet.label(v) : v);
    sel.innerHTML = [`<option value="">${esc(facet.allLabel)} (${available.length})</option>`]
      .concat(keys.map((k) =>
        `<option value="${esc(k)}">${esc(text(k))} (${counts.get(k)})</option>`))
      .join("");
    sel.value = chosen;
  }
}
