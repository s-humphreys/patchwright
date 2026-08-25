import { signalsSort } from './badges.js';
import { FIX_RANK, PRI_RANK, SEVERITIES, actionCell, actionSort, cveColumns, fixCell, fixClass, fixPath, priorityClass, severityCell, sortState, sourceCell, upgradeTitle, urgencyCell } from './cells.js';
import { S } from './state.js';
import { $, UNKNOWN, countPct, esc, pct } from './util.js';

// The queue answers four questions at a glance: how urgent, what is it and whose,
// is there a fix, and is anything already happening. Five columns, and everything
// else in the detail panel a row opens.
//
// It had fourteen. Every one of them was defensible on its own and the whole was
// unreadable: a reader scanning for urgency had to skip eight columns to find it, and
// the columns that mattered least (EPSS, Risk, Live) were as wide as the ones that
// mattered most. Nothing has been dropped — the detail panel shows more than the
// table ever did, on demand, per finding.
/** @type {any[]} */
export const FINDING_COLUMNS = [
  { label: "Urgency", cls: (f) => priorityClass(f), get: (f) => urgencyCell(f),
    sort: (f) => (f.suppressed ? 0 : (PRI_RANK[f.priority] ?? 0) * 100 + signalsSort(f) / 100),
    help: "The policy verdict, with what drives it: an exposed or KEV-listed finding is a different proposition from a quiet critical. Sorting ranks the verdict first, then the weight of those signals.",
    title: (f) => (f.suppressed
      ? "Suppressed by policy: " + ((f.reasons || [])[0] || "no reason recorded")
      : (f.reasons || [])[0] || "") },
  { label: "Severity", num: true, get: (f) => severityCell(f),
    sort: (f) => (f.provider_assessed
      ? (f.counts?.critical ?? 0) * 1000 + (f.counts?.high ?? 0) : UNKNOWN),
    help: "Criticals and highs from the scan provider, as C/H. \"?\" means the provider never assessed this image, so nothing is known — which is not the same as zero.",
    title: (f) => (f.provider_assessed ? "" : "The scan provider never assessed this image; its counts are absent, not zero.") },
  { label: "Image", td: "clip", get: (f) => sourceCell(f), sort: (f) => f.image || "",
    help: "The image as deployed, with the owning team and the namespaces it runs in beneath it.",
    title: (f) => f.image },
  { label: "Fix", cls: fixClass, get: (f) => fixCell(f), sort: (f) => FIX_RANK[fixPath(f)] ?? 0,
    help: "Whether there is a version to move to and what kind of change it is. \"none\" means already latest, \"unknown\" means the lookup could not answer, \"?\" means detection did not run — three different things.",
    title: (f) => upgradeTitle(f) },
  { label: "Action", get: (f) => actionCell(f), sort: (f) => actionSort(f),
    help: "Whether anything is already happening: an open pull request that applies the upgrade, or an open ticket. \"-\" means neither; \"?\" means we could not look.",
    title: (f) => (f.in_flight ? f.in_flight.title : "") },
];

export function compare(col, dir) {
  return (a, b) => {
    const x = col.sort(a), y = col.sort(b);
    if (typeof x === "string" || typeof y === "string") {
      return dir * String(x).localeCompare(String(y));
    }
    // Unknowns sink to the bottom whichever way the column is sorted.
    if (x === UNKNOWN && y === UNKNOWN) return 0;
    if (x === UNKNOWN) return 1;
    if (y === UNKNOWN) return -1;
    return dir * (x - y);
  };
}

export function renderTable(id, columns, rows) {
  const state = sortState[id];
  let data = rows.slice();
  if (state) {
    data.sort(compare(columns[state.index], state.dir));
  }

  const head = document.querySelector(`#${id} thead tr`);
  head.innerHTML = columns.map((c, i) => {
    const active = state && state.index === i;
    const arrow = active ? `<span class="arrow">${state.dir > 0 ? "▲" : "▼"}</span>` : "";
    const help = c.help ? esc(c.help) + " (click to sort)" : `Sort by ${esc(c.label)}`;
    return `<th class="sortable${c.num ? " num" : ""}" data-i="${i}"
      title="${help}">${esc(c.label)} ${arrow}</th>`;
  }).join("");
  head.querySelectorAll("th").forEach((th) => {
    th.onclick = () => {
      const i = Number(th.dataset.i);
      // First click on a column sorts descending: for every numeric column here,
      // the interesting end is the top.
      sortState[id] = state && state.index === i
        ? (state.dir < 0 ? { index: i, dir: 1 } : null)
        : { index: i, dir: -1 };
      renderTable(id, columns, rows);
    };
  });

  // Rows in the findings table are openable: they carry the image so a click can find
  // the finding again, and a tabindex so the keyboard reaches them.
  const openable = id === "findings" || id === "cves";
  document.querySelector(`#${id} tbody`).innerHTML = data.map((row) => (openable
    ? `<tr class="openable" tabindex="0" ${id === "cves"
        ? `data-cve="${esc(row.id)}" aria-label="Show scope of ${esc(row.id)}"`
        : `data-image="${esc(row.image)}" aria-label="Show details for ${esc(row.image)}"`}>`
    : "<tr>") +
    columns.map((c) => {
      const cls = [c.num ? "num" : "", typeof c.td === "string" ? c.td : "",
                   c.cls ? c.cls(row) : ""].filter(Boolean).join(" ");
      const title = c.title ? ` title="${esc(c.title(row))}"` : "";
      return `<td${cls ? ` class="${cls}"` : ""}${title}>${c.get(row)}</td>`;
    }).join("") + "</tr>").join("");
}

// pct renders a share, and says "-" rather than "0%" when the denominator is zero:
// nought out of nought is not a measurement.

// Heterogeneous by design: a column is whatever pairs a label with a getter, and the
// severity slot expands into several. Annotated rather than narrowed, because the
// alternative is contorting the shape to satisfy inference.
/** @type {any[]} */
export const BREAKDOWN_COLUMNS = [
  { label: "Class / team", get: (r) => breakdownLabel(r), cls: (r) => (r.team ? "indent" : ""),
    help: "Owner class, with its teams beneath. Classes with more than one team expand. Percentages are of that row's own findings unless stated." },
  { label: "Findings", num: true, get: (r) => `${r.total} ${pct(r.total, r.estate)}`,
    help: "Findings owned, and the share of the whole estate they represent." },
  { label: "Assessed", num: true, get: (r) => countPct(r.total - r.unassessed, r.total),
    help: "Findings the scan provider actually assessed. A low share means the rest of this row's numbers describe a small sample." },
  { severitySlot: true },
  { label: "Actionable", num: true, get: (r) => countPct(r.actionable, r.total),
    help: "Findings policy marked for action, as a share of this row's findings." },
  { label: "Direct", num: true, get: (r) => countPct(r.direct, r.actionable),
    help: "Actionable findings this team can fix by bumping the image itself." },
  { label: "Managed", num: true, get: (r) => countPct(r.managed, r.actionable),
    help: "Actionable findings whose version is owned by a chart or operator, so the fix crosses a boundary." },
  { label: "Fixable", num: true, get: (r) => countPct(r.fixable, r.actionable),
    help: "Actionable findings with at least one critical CVE that has a fix available." },
  // "?" rather than "0%" when Jira is not configured: an unknown is not an absence,
  // and a column reading "0% ticketed" would say the work is untracked when the
  // truth is that nobody asked Jira.
  { label: "Ticketed", num: true,
    get: (r) => (S.ticketsByRepo ? countPct(r.ticketed, r.actionable)
      : '<span class="unknown" title="Jira is not configured, so ticket state is unknown">?</span>'),
    help: "Actionable findings with an open ticket. \"?\" when Jira is not configured, which is not the same as nothing being tracked." },
];

// expandedClasses survives a re-render, so an hourly refresh does not collapse a
// class someone had opened to read.
export const expandedClasses = new Set();

// breakdownLabel renders the row's name, and for a class with teams beneath it a
// caret plus the team count, so it is visible that there is more to see rather
// than the collapsed rollup looking like the whole story.
export function breakdownLabel(r) {
  if (r.team || !r.children) return r.label;
  const open = expandedClasses.has(r.key);
  return `<span class="caret">${open ? "\u25be" : "\u25b8"}</span>${r.label}` +
    ` <span class="pct">(${r.children} team${r.children === 1 ? "" : "s"})</span>`;
}

// breakdownColumns resolves the column set against the current severity state.
/** @returns {any[]} */
export function breakdownColumns() {
  return BREAKDOWN_COLUMNS.flatMap((c) => (c.severitySlot ? cveColumns() : [c]));
}

export function renderBreakdown(owners) {
  const rows = [];
  const estate = (owners || []).reduce((n, o) => n + o.total, 0);

  // Group by class, then roll the class up from its teams so the totals cannot
  // disagree with the rows beneath them.
  const byClass = new Map();
  for (const o of owners || []) {
    const cls = o.class || "-";
    if (!byClass.has(cls)) byClass.set(cls, []);
    byClass.get(cls).push(o);
  }
  const sum = (list, key) => list.reduce((n, o) => n + (o[key] || 0), 0);
  const sumCounts = (list) => list.reduce((acc, o) => {
    for (const sev of SEVERITIES) acc[sev] = (acc[sev] || 0) + (o.cves?.[sev] || 0);
    return acc;
  }, {});

  for (const [cls, teams] of [...byClass].sort((a, b) => sum(b[1], "actionable") - sum(a[1], "actionable"))) {
    rows.push({
      label: esc(cls), key: cls, estate, team: false,
      cves: sumCounts(teams), cvesFrom: sum(teams, "cves_from"),
      // Rows are only worth expanding when they say something the rollup does
      // not, so a class with a single team stays a leaf: the team row would be
      // a copy of the class row.
      children: teams.length > 1 ? teams.length : 0,
      total: sum(teams, "total"), unassessed: sum(teams, "unassessed"),
      actionable: sum(teams, "actionable"), direct: sum(teams, "direct"),
      managed: sum(teams, "managed"), fixable: sum(teams, "fixable"),
      ticketed: sum(teams, "ticketed"),
    });
    // Only break a class down when there is more than one team in it; a single
    // team repeated under its own class is noise.
    if (teams.length < 2 || !expandedClasses.has(cls)) continue;
    for (const o of [...teams].sort((a, b) => b.actionable - a.actionable)) {
      rows.push({
        label: esc(o.team || "(unattributed)"), key: cls, estate, team: true,
        cves: o.cves, cvesFrom: o.cves_from,
        total: o.total, unassessed: o.unassessed, actionable: o.actionable,
        direct: o.direct, managed: o.managed, fixable: o.fixable, ticketed: o.ticketed,
      });
    }
  }

  const columns = breakdownColumns();
  const head = document.querySelector("#breakdown thead tr");
  head.innerHTML = columns.map((c) => {
    const cls = [c.num ? "num" : "", c.expandSeverity ? "sev-toggle" : ""].filter(Boolean).join(" ");
    const label = c.expandSeverity
      ? `<span class="caret">${S.severityExpanded ? "\u25c2" : "\u25b8"}</span>${esc(c.label)}`
      : esc(c.label);
    return `<th class="${cls}"${c.expandSeverity ? ' role="button" tabindex="0"' +
      ` aria-expanded="${S.severityExpanded}"` : ""} title="${esc(c.help)}">${label}</th>`;
  }).join("");
  document.querySelector("#breakdown tbody").innerHTML = rows.map((r) => {
    const cells = columns.map((c) => {
      const cls = [c.num ? "num" : "", c.cls ? c.cls(r) : ""].filter(Boolean).join(" ");
      return `<td${cls ? ` class="${cls}"` : ""}>${c.get(r)}</td>`;
    }).join("");
    if (r.team) return `<tr>${cells}</tr>`;
    const expandable = r.children > 0;
    // The whole row is the control, so the click target is the size of the row
    // rather than a caret someone has to aim at.
    return `<tr class="rollup${expandable ? " expandable" : ""}"` +
      (expandable ? ` data-class="${esc(r.key)}" tabindex="0" role="button"` +
        ` aria-expanded="${expandedClasses.has(r.key)}"` : "") +
      `>${cells}</tr>`;
  }).join("");
  S.lastOwners = owners;
}

// S.lastOwners is kept so toggling re-renders from the same data instead of
// refetching: expanding a row is a display change, not a new question.

export function toggleBreakdownClass(key) {
  if (expandedClasses.has(key)) expandedClasses.delete(key);
  else expandedClasses.add(key);
  renderBreakdown(S.lastOwners);
}

export function toggleSeverityColumns() {
  S.severityExpanded = !S.severityExpanded;
  renderBreakdown(S.lastOwners);
}

// initTable wires the breakdown's interactions. A function rather than module-level
// code: importing a module must not require a page to exist, or the rendering cannot
// be tested without standing up the whole document — which is how this file went
// untested for as long as it did.
export function initTable() {
  const el = $("#breakdown");
  // Delegated, so the handlers survive the re-render that follows every toggle.
  el.addEventListener("click", (e) => {
    if (e.target.closest("th.sev-toggle")) return toggleSeverityColumns();
    const row = e.target.closest("tr.expandable");
    if (row) toggleBreakdownClass(row.dataset.class);
  });
  el.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    if (e.target.closest("th.sev-toggle")) {
      e.preventDefault();
      return toggleSeverityColumns();
    }
    const row = e.target.closest("tr.expandable");
    if (!row) return;
    e.preventDefault(); // Space would otherwise scroll the page.
    toggleBreakdownClass(row.dataset.class);
  });
}
