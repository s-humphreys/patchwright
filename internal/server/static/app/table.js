import { count, epss, signalsCell, signalsSort } from './badges.js';
import { FIX_HELP, FIX_RANK, PRI_RANK, SEVERITIES, cveColumns, fixClass, fixPath, fixcrit, isScanned, live, maxEPSS, maxRisk, priorityClass, priorityText, riskCell, sortState, ticketCell, ticketSort, upgradeCell, upgradeText, upgradeTitle } from './cells.js';
import { S } from './state.js';
import { $, UNKNOWN, cell, countPct, esc, pct } from './util.js';

export const FINDING_COLUMNS = [
  { label: "Priority", cls: (f) => priorityClass(f), get: (f) => priorityText(f),
    sort: (f) => (f.suppressed ? 0 : PRI_RANK[f.priority] ?? 0),
    help: "The policy verdict, set by your rules. urgent means a fixable CVE that is exploited or likely to be (KEV or high EPSS), which outranks severity alone. This is NOT the same as having something to upgrade to; see Fix.",
    title: (f) => (f.suppressed
      ? "Suppressed by policy: " + ((f.reasons || [])[0] || "no reason recorded")
      : (f.reasons || [])[0] || "") },
  { label: "Team", get: (f) => esc(f.owner?.team || "-"), sort: (f) => f.owner?.team || "",
    help: "The attributed owning team. \"-\" means no ownership rule could attribute this workload, which is usually a missing namespace label rather than a vulnerability.",
    title: (f) => (f.owner?.team ? `owner rule: ${f.owner.rule || "unknown"}` : "No ownership rule matched") },
  { label: "Namespace", td: "clip", get: (f) => cell(f.dimensions?.namespace),
    sort: (f) => (f.dimensions?.namespace || [])[0] || "",
    help: "Namespaces this image runs in. Click a \"+N\" to expand the full list." },
  { label: "Image", td: "clip", title: (f) => f.image,
    get: (f) => `<code>${esc(f.image)}</code>`, sort: (f) => f.image || "",
    help: "The image reference as deployed, digest included where pinned." },
  { label: "Crit", num: true, get: (f) => esc(count(f, "critical")),
    sort: (f) => (f.provider_assessed ? f.counts?.critical ?? 0 : UNKNOWN),
    help: "Critical count from the scan provider. \"?\" means the provider never assessed this image, so nothing is known about it. That is not the same as zero.",
    title: (f) => (f.provider_assessed ? "" : "The scan provider never assessed this image; its counts are absent, not zero.") },
  { label: "Fixcrit", num: true, get: (f) => esc(fixcrit(f)),
    sort: (f) => (isScanned(f) ? f.fixable_critical ?? 0 : UNKNOWN),
    help: "Critical CVEs with a fix available, from the vulnerability scanner. \"-\" means the image was not scanned.",
    title: (f) => (isScanned(f) ? "" : "Not scanned, so fix availability is unknown.") },
  // Kept even when nothing gathered it: a column of "-" says the signal was not
  // collected, whereas removing the column says the signal does not exist.
  { label: "EPSS", num: true, get: (f) => esc(epss(f)),
    sort: (f) => (f.exploit_checked ? maxEPSS(f) : UNKNOWN),
    help: "Highest EPSS across this image's CVEs: the predicted probability of exploitation in the next 30 days (0-1). A CVSS 10 at EPSS 0.008 is less urgent than a CVSS 5 at 0.93. \"-\" means exploit intel was not gathered." },
  { label: "Risk", num: true, get: (f) => riskCell(f),
    sort: (f) => (f.exploit_checked ? maxRisk(f) : UNKNOWN),
    help: "The scan provider's own composite risk score, highest across this image's CVEs (Rapid7's runs to roughly 1000). NOT comparable with EPSS, which is a probability: this is a severity-and-exposure weighting. \"-\" means the provider scored none of these CVEs; \"?\" means no exploit source ran." },
  { label: "Live", get: (f) => esc(live(f)),
    sort: (f) => (!f.liveness ? UNKNOWN : f.liveness.live ? 1 : 0),
    help: "Whether this image is running in a cluster right now. \"?\" means no live reconciliation ran." },
  { label: "Fix", cls: fixClass, get: (f) => fixPath(f),
    sort: (f) => FIX_RANK[fixPath(f)] ?? 0,
    help: "Whether there is a version to move to, and where the change is applied: direct, managed (via a chart or operator), none (already latest), unknown (could not resolve), ? (detection did not run).",
    title: (f) => FIX_HELP[fixPath(f)] || "" },
  { label: "Upgrade", cls: fixClass, get: (f) => upgradeCell(f), title: upgradeTitle,
    sort: (f) => upgradeText(f),
    help: "The version move available, badged by what kind of change it is: base image, Helm chart, or image tag. A second badge names whatever owns the version when it is not this image's own tag.", },
  { label: "Signals", get: (f) => signalsCell(f), sort: (f) => signalsSort(f),
    help: "What is notable about this finding, as badges: exposed to the internet, KEV-listed, a pull request already open (with its age), that pull request gone stale, never assessed by the provider, suppressed. Each badge is a positive statement — nothing here means \"internal\" or \"no pull request\", which are shown explicitly." },
  { label: "Ticket", get: (f) => ticketCell(f), sort: (f) => ticketSort(f),
    help: "Open Jira tickets covering this image. \"-\" means no open ticket; \"?\" means Jira is not configured, so ticket state is unknown." },
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

  document.querySelector(`#${id} tbody`).innerHTML = data.map((row) => "<tr>" +
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
