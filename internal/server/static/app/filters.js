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

/**
 * selected reads the values ticked in one facet.
 *
 * Facets are multi-select because the questions people ask are unions - "kev or
 * exposed", "urgent or high" - and a single-choice control makes those two
 * questions whose answers have to be added up by hand.
 *
 * @returns {string[]} the chosen values, empty meaning no filter.
 */
export function selected(id) {
  const el = $(id);
  if (!el) return [];
  return Array.from(el.querySelectorAll("input[type=checkbox]"))
    .filter((b) => /** @type {any} */ (b).checked)
    .map((b) => /** @type {any} */ (b).value);
}

/** select ticks exactly these values, for restoring a link. */
export function select(id, values) {
  const el = $(id);
  if (!el) return;
  const want = new Set(values || []);
  for (const b of Array.from(el.querySelectorAll("input[type=checkbox]"))) {
    /** @type {any} */ (b).checked = want.has(/** @type {any} */ (b).value);
  }
}

/** filterState reads every control into one object. */
export function filterState() {
  /** @type {any} */
  const st = { q: ($("#search")?.value || "").trim().toLowerCase(), fixable: false };
  for (const f of FACETS) {
    st[f.name] = selected(f.id);
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
    // Several values within one facet mean ANY of them. Across facets it is still
    // AND: "kev or exposed, owned by orders" is the sentence people say.
    if (!want || !want.length) continue;
    const have = facet.values(f);
    if (!want.some((w) => have.includes(w))) return false;
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
    const el = $(facet.id);
    if (!el) continue;
    const menu = el.querySelector(".ms-menu");
    if (!menu) continue;

    const available = apply(rows, st, facet.name);
    const counts = new Map();
    for (const f of available) {
      for (const v of facet.values(f)) counts.set(v, (counts.get(v) || 0) + 1);
    }
    let keys = [...counts.keys()];
    if (facet.order === "count") keys.sort((a, b) => counts.get(b) - counts.get(a));
    else keys.sort(facet.order);

    const chosen = st[facet.name] || [];
    // A chosen value that no longer matches anything stays on the list at zero
    // rather than vanishing: dropping somebody's filter changes what they are
    // looking at without telling them, and an empty table under a visible "(0)" is
    // the honest version.
    for (const c of chosen) {
      if (!counts.has(c)) {
        keys.push(c);
        counts.set(c, 0);
      }
    }

    const text = (v) => (facet.label ? facet.label(v) : v);
    menu.innerHTML = keys.map((k) => `<label class="ms-opt">
      <input type="checkbox" value="${esc(k)}"${chosen.includes(k) ? " checked" : ""}>
      <span>${esc(text(k))}</span><span class="ms-count">${counts.get(k)}</span>
    </label>`).join("") || `<div class="ms-empty">nothing to filter by</div>`;

    // The summary is the only part visible when the menu is shut, so it has to say
    // what is selected. "class: all" and "class: 3 selected" are both answers; a
    // control that looks identical whether or not it is filtering is not.
    const summary = el.querySelector("summary");
    if (summary) {
      const label = facet.allLabel.replace(/^(all|any) /, "").replace(/e?s$/, "");
      summary.textContent = chosen.length === 0
        ? `${facet.name}: all (${available.length})`
        : chosen.length === 1
          ? `${facet.name}: ${text(chosen[0])}`
          : `${facet.name}: ${chosen.length} selected`;
      summary.title = chosen.length ? chosen.map(text).join(", ") : `Filter by ${label}`;
    }

    // A facet with nothing behind it cannot change anything, so it is dimmed and
    // cannot be opened. They all look identical otherwise, and a reader who opens
    // one to find it empty reasonably concludes the filters are broken.
    const inert = keys.length === 0;
    el.classList.toggle("inert", inert);
    if (inert) /** @type {any} */ (el).open = false;
    el.toggleAttribute("data-inert", inert);
  }
}

/**
 * wireFacets makes the dropdowns behave: ticking a box filters, and clicking away
 * closes the menu.
 *
 * Called once. `onChange` is the page's filter-and-render, so this module does not
 * need to know what a view is.
 */
export function wireFacets(onChange) {
  for (const facet of FACETS) {
    const el = $(facet.id);
    if (!el) continue;
    el.addEventListener("change", (e) => {
      if (/** @type {any} */ (e.target)?.type === "checkbox") onChange();
    });
    // An inert facet must not open, and a details element opens on its own.
    el.addEventListener("toggle", () => {
      if (el.hasAttribute("data-inert")) /** @type {any} */ (el).open = false;
    });
  }
  document.addEventListener("click", (e) => {
    for (const facet of FACETS) {
      const el = $(facet.id);
      if (el && /** @type {any} */ (el).open && !el.contains(/** @type {any} */ (e.target))) {
        /** @type {any} */ (el).open = false;
      }
    }
  });
}
