import { SIGNAL_BADGES, badge } from './badges.js';
import { esc } from './util.js';

// What the base image accounts for, and what upgrading it would actually fix.
//
// The queue could already say a newer base exists. It could not say what moving to
// it buys, so every row asked a team for an upgrade of unknown value. Scanning the
// base and the candidate answers that by subtraction, and the answer is usually
// dramatic: on this estate a typical application image gets three quarters of its
// CVEs cleared by a rebuild it has not been told to do.
//
// The counts are also the ownership answer. Most of a queue's mass is not the
// application team's work at all, and saying so is what stops this reading as a
// list of things somebody has been negligent about.

/** The CVE groups a security reader triages by, worst first. */
const GROUPS = [
  {
    key: "kev",
    label: "Known exploited",
    match: (v) => !!v.kev,
    help: "In CISA's Known Exploited Vulnerabilities catalogue: confirmed exploitation in the wild.",
  },
  {
    key: "critical",
    label: "Critical",
    // KEV is listed separately above, so a critical that is also KEV would appear
    // twice and the two counts would not add up to anything.
    match: (v) => v.severity === "critical" && !v.kev,
    help: "Critical severity, not already counted as known-exploited.",
  },
];

// How many un-cleared CVEs to name before summarising the rest. The list exists to
// be read and acted on; past a handful it stops being a list and starts being the
// table further down the panel.
const NAME_LIMIT = 6;

/**
 * splitGroup sorts one group's CVEs into those a base upgrade removes and those it
 * does not.
 *
 * `undetermined` is kept apart from `remaining` deliberately. "This upgrade will
 * not fix it" and "we did not check" are different statements, and an earlier
 * version of this feature shipped precisely because that distinction was collapsed.
 */
export function splitGroup(vulns, match) {
  const out = { cleared: [], remaining: [], undetermined: [] };
  for (const v of vulns || []) {
    if (!match(v)) continue;
    if (!v.origin_determined) out.undetermined.push(v);
    else if (v.fixed_by_upgrade) out.cleared.push(v);
    else out.remaining.push(v);
  }
  return out;
}

/** cveList names the CVEs that still need work, capped so the panel stays readable. */
function cveList(vulns) {
  const shown = vulns.slice(0, NAME_LIMIT).map((v) =>
    `<li><code class="cve-link" data-cve="${esc(v.id)}" tabindex="0" role="button"
       aria-label="Show every image affected by ${esc(v.id)}">${esc(v.id)}</code>
     ${v.origin === "app" ? '<span class="sub">yours</span>' : ""}</li>`).join("");
  const rest = vulns.length > NAME_LIMIT
    ? `<li class="muted">and ${vulns.length - NAME_LIMIT} more</li>` : "";
  return `<ul class="cve-brief">${shown}${rest}</ul>`;
}

/** groupLine renders one triage group: a count, a split, and only the work left. */
function groupLine(g, vulns) {
  const s = splitGroup(vulns, g.match);
  const total = s.cleared.length + s.remaining.length + s.undetermined.length;
  if (!total) return "";

  const head = g.key === "kev"
    ? badge(SIGNAL_BADGES.kev, "kev")
    : `<span class="sev-critical">${esc(g.label)}</span>`;

  // The cleared ones are a number, not a list. They need nobody to do anything,
  // and printing them is the information overload that hides the ones that do.
  const parts = [];
  if (s.cleared.length) parts.push(`<span class="ok">${s.cleared.length} cleared by the rebuild</span>`);
  if (s.remaining.length) parts.push(`<strong>${s.remaining.length} need separate work</strong>`);
  if (s.undetermined.length) {
    parts.push(`<span class="unknown" title="No candidate base was scanned for these, so whether an upgrade fixes them was never established.">${s.undetermined.length} not established</span>`);
  }

  return `<div class="dr"><dt title="${esc(g.help)}">${head} ${total}</dt>
    <dd>${parts.join(" · ")}${s.remaining.length ? cveList(s.remaining) : ""}</dd></div>`;
}

/**
 * baseDiffSection renders the base-image breakdown for one finding.
 *
 * Returns "" when no differential ran. An empty section is better than a section
 * full of zeroes: zeroes read as "the base accounts for nothing", which is the
 * opposite of what an absent scan means.
 */
export function baseDiffSection(f) {
  const d = f && f.base_diff;
  if (!d) return "";

  const pct = (n) => (d.total ? Math.round((n / d.total) * 100) : 0);
  const rows = [];

  rows.push(`<div class="dr"><dt title="Established by scanning the base image, not inferred from package names.">Where they come from</dt>
    <dd><strong>${d.from_base}</strong> from the base image <span class="sub">(${pct(d.from_base)}%)</span>
      · <strong>${d.from_app}</strong> from this image <span class="sub">(${pct(d.from_app)}%)</span>
      ${d.unknown ? `· <span class="unknown" title="Not attributed.">${d.unknown} unattributed</span>` : ""}</dd></div>`);

  if (d.determined) {
    const intro = d.introduces
      ? ` · <span class="warn">${d.introduces} new</span>`
      : "";
    rows.push(`<div class="dr"><dt>Rebuilding clears</dt>
      <dd><strong class="ok">${d.clears}</strong> of ${d.total}
        <span class="sub">(${pct(d.clears)}% of everything on this image)</span>
        · ${d.leaves} still from the base${intro}</dd></div>`);
  } else {
    rows.push(`<div class="dr"><dt>Rebuilding clears</dt><dd>${
      `<span class="unknown" title="No candidate base image was scanned, so this was never worked out. It does not mean an upgrade would fix nothing.">not established</span>`
    }</dd></div>`);
  }

  for (const g of GROUPS) rows.push(groupLine(g, f.vulns));

  rows.push(`<div class="dr"><dt>Compared</dt><dd><code>${esc(d.from_ref)}</code>${
    d.to_ref ? ` → <code>${esc(d.to_ref)}</code>` : ""
  }${d.os_family ? ` <span class="sub">${esc(d.os_family)}</span>` : ""}</dd></div>`);

  return `<section><h4>Base image</h4><dl>${rows.join("")}</dl></section>`;
}
