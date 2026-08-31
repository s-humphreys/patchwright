import { SIGNAL_BADGES, badge } from './badges.js';
import { PRI_RANK, actionCell, actionSort, fixCell, fixClass, fixPath, priorityText, upgradeTitle } from './cells.js';
import { FIX_RANK } from './cells.js';
import { UNKNOWN, esc } from './util.js';

// Grouping: one row per piece of work, not per finding.
//
// An application deployed to three environments on three tags is three findings and
// one change. On this estate that is not an edge case: 621 findings collapse to 370
// groups, so 70% of the queue was the same work listed again. A queue that says 621
// when there are 370 things to do overstates the work in the number people read first.
//
// The key matches how tickets group (team, repository, upgrade target), so a queue row
// and a ticket are the same unit. Two things the estate forces:
//
//   - The team is part of the key. Two repositories here are shared between teams
//     (ledger across payments and orders), and merging those would produce a row belonging
//     to nobody and break the team filter.
//   - Findings inside a group disagree. 159 of 181 multi-finding groups hold different
//     verdicts, because the same image is urgent in production and medium in
//     development. A group therefore reports the WORST of everything, and says where
//     the worst came from: "urgent (Production NA)". Collapsing to "urgent" alone
//     throws away the answer to "urgent where?", which is the whole point of an
//     environment-tiered policy.

/**
 * groupKey mirrors the ticket grouping: the same work, the same unit.
 *
 * JSON rather than a joined string. The key travels through a data attribute so a
 * click opens the row it actually is, and it used to be joined with NUL - which an
 * HTML attribute cannot carry. The browser substitutes U+FFFD, so the key read back
 * never matched any group and every grouped row quietly opened one of its images
 * instead of the work item.
 *
 * JSON is printable, survives the round trip, and cannot be forged by a value that
 * happens to contain the separator.
 */
function groupKey(f) {
  const u = f.upgrade || {};
  return JSON.stringify([f.owner?.team || "", f.owner?.class || "", f.repository,
                         u.name || "", u.latest || ""]);
}

/** worst returns the finding a group should be judged by. */
function worstFinding(findings) {
  return findings.reduce((a, b) =>
    (PRI_RANK[b.priority] ?? 0) > (PRI_RANK[a.priority] ?? 0) ? b : a);
}

/**
 * groupFindings collapses findings into work items.
 * @returns {any[]} one entry per group, each carrying its findings
 */
export function groupFindings(findings) {
  /** @type {Map<string, any[]>} */
  const byKey = new Map();
  for (const f of findings) {
    const k = groupKey(f);
    const at = byKey.get(k);
    if (at) at.push(f);
    else byKey.set(k, [f]);
  }

  const out = [];
  for (const [key, members] of byKey) {
    const lead = worstFinding(members);
    const signals = new Set();
    let critical = 0, high = 0, assessed = 0, exposedAny = false, internalKnown = false;
    let scanned = 0, exploitChecked = 0;
    for (const f of members) {
      for (const s of f.signals || []) signals.add(s);
      if (f.provider_assessed) {
        assessed++;
        critical = Math.max(critical, f.counts?.critical ?? 0);
        high = Math.max(high, f.counts?.high ?? 0);
      }
      if (f.scanned) scanned++;
      if (f.exploit_checked) exploitChecked++;
      if (f.exposure === "public") exposedAny = true;
      if (f.exposure === "internal") internalKnown = true;
    }
    out.push({
      key,
      // The lead finding backs every shared cell (fix, action, ticket): grouping is BY
      // upgrade target, so those are identical across members by construction.
      lead,
      findings: members,
      image: lead.image,
      repository: lead.repository,
      owner: lead.owner,
      upgrade: lead.upgrade,
      in_flight: lead.in_flight,
      in_flight_checked: members.every((f) => f.in_flight_checked),
      in_flight_reason: lead.in_flight_reason,
      priority: lead.priority,
      // Where the worst verdict came from, but ONLY when the environment is what
      // distinguishes it. One deployment running in six accounts is urgent in all of
      // them, and naming the alphabetically first ("Development EU") invented a
      // distinction the policy never drew. Empty means "the verdict is not about
      // where it runs", and the row shows the rule instead.
      worstWhere: discriminatingWhere(members, lead),
      counts: { critical, high },
      // Partial coverage is its own state: some tags assessed and some not means the
      // counts are the worst KNOWN, not the worst.
      assessedOf: [assessed, members.length],
      scannedOf: [scanned, members.length],
      exploitCheckedOf: [exploitChecked, members.length],
      exposure: exposedAny ? "public" : internalKnown ? "internal" : "unknown",
      signals: [...signals],
      tags: members.map((f) => f.tag || f.image),
      dimensions: {
        namespace: [...new Set(members.flatMap((f) => f.dimensions?.namespace || []))],
        account: [...new Set(members.flatMap((f) => f.dimensions?.account || []))],
      },
      workload_count: members.reduce((n, f) => n + (f.workload_count || 0), 0),
    });
  }
  return out;
}

function urgencyGroupCell(g) {
  const marks = g.signals
    .filter((s) => s === "exposed" || s === "kev")
    .map((s) => badge(SIGNAL_BADGES[s], s))
    .join(" ");
  // Name the environment only when it is what distinguishes this verdict from the
  // group's others. Otherwise show the rule: that is the honest answer to "why is
  // this urgent" when every deployment agrees.
  const where = g.worstWhere
    ? `<div class="sub">worst in ${esc(g.worstWhere)} of ${g.findings.length}</div>`
    : `<div class="sub">${esc(ruleOf(g))}</div>`;
  return `${priorityText(g.lead)}${marks ? ` ${marks}` : ""}${where}`;
}

function ruleOf(g) {
  const reason = (g.lead.reasons || [])[0] || "";
  const quoted = reason.match(/"([^"]+)"/);
  return quoted ? quoted[1] : reason || "no rule matched";
}

function severityGroupCell(g) {
  const [assessed, total] = g.assessedOf;
  if (assessed === 0) {
    return '<span class="unknown" title="The scan provider never assessed any image in this group; its counts are absent, not zero.">?</span>';
  }
  const { critical: c, high: h } = g.counts;
  const partial = assessed < total
    ? ` ${assessed} of ${total} images in this group were assessed, so these are the worst KNOWN counts rather than the worst.`
    : "";
  const body = !c && !h
    ? '<span class="muted">0</span>'
    : [c ? `<span class="urgent">${c}C</span>` : "", h ? `<span class="high">${h}H</span>` : ""]
        .filter(Boolean).join("/");
  const mark = partial ? '<span class="unknown" title="partial coverage">*</span>' : "";
  return `<span title="Worst counts across ${total} image${total === 1 ? "" : "s"} in this group.${partial}">${body}${mark}</span>`;
}

function imageGroupCell(g) {
  const team = g.owner?.team
    ? esc(g.owner.team)
    : '<span class="unknown" title="No ownership rule matched these workloads.">unattributed</span>';
  const n = g.findings.length;
  const tags = n === 1
    ? esc(g.lead.tag || "")
    : `<span title="${esc(g.tags.join(", "))}">${n} tags</span>`;
  const ns = g.dimensions.namespace;
  const where = ns.length === 0 ? "" : ns.length === 1 ? esc(ns[0]) : `${esc(ns[0])} +${ns.length - 1}`;
  return `<code>${esc(g.registry || "")}${esc(g.repository)}</code> ${tags}` +
    `<div class="sub">${team}${where ? ` · ${where}` : ""}</div>`;
}

export const GROUP_COLUMNS = [
  { label: "Urgency", cls: (g) => (g.lead.suppressed ? "act-unknown" : ""), get: urgencyGroupCell,
    sort: (g) => (g.lead.suppressed ? 0 : PRI_RANK[g.priority] ?? 0),
    help: "The worst verdict in this group, and where it came from. The same image is often urgent in production and medium in development; the row reports the worst and names its environment.",
    title: (g) => `${ruleOf(g)} — worst of ${g.findings.length} deployment${g.findings.length === 1 ? "" : "s"}` },
  { label: "Severity", num: true, get: severityGroupCell,
    sort: (g) => (g.assessedOf[0] ? g.counts.critical * 1000 + g.counts.high : UNKNOWN),
    help: "Worst criticals and highs across the group's images. \"*\" marks partial coverage: some images were never assessed, so these are the worst known rather than the worst. \"?\" means none were assessed." },
  { label: "Service", td: "clip", get: imageGroupCell, sort: (g) => g.repository || "",
    help: "The repository this group covers, how many deployed tags it has, and the owning team. One row is one change: rebuilding this service on the newer base and promoting it forward.",
    title: (g) => g.tags.join(", ") },
  { label: "Fix", cls: (g) => fixClass(g.lead), get: (g) => fixCell(g.lead),
    sort: (g) => FIX_RANK[fixPath(g.lead)] ?? 0,
    help: "The version move, shared by every tag in the group — grouping is by upgrade target, so they cannot differ.",
    title: (g) => upgradeTitle(g.lead) },
  { label: "Action", get: (g) => actionCell(g.lead), sort: (g) => actionSort(g.lead),
    help: "Whether anything is already happening. A pull request or ticket covers the repository, so it covers every tag in this group.",
    title: (g) => (g.in_flight ? g.in_flight.title : "") },
];

/**
 * discriminatingWhere names the environment behind the worst verdict, when the
 * environment is what makes it the worst.
 *
 * It is only meaningful when the group's deployments disagree: three tags where
 * production is urgent and development is medium. Where they agree — or where there is
 * one deployment running everywhere — the verdict is not about location, and naming a
 * place implies a distinction the policy did not make.
 */
function discriminatingWhere(members, lead) {
  if (members.length < 2) return "";
  const verdicts = new Set(members.map((f) => f.priority || ""));
  if (verdicts.size < 2) return "";
  const accounts = lead.dimensions?.account || [];
  if (accounts.length === 1) return accounts[0];
  if (accounts.length > 1) return `${accounts.length} accounts`;
  const ns = lead.dimensions?.namespace || [];
  return ns.length === 1 ? ns[0] : "";
}
