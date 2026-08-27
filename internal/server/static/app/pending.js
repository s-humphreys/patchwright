import { $, esc, get } from './util.js';

export const ACTION_LABELS = {
  create: "Raise a new ticket",
  extend: "Add more images to this ticket",
  update: "Rewrite the summary and description",
  close: "Close it",
  "note-stale": "Comment: the version it asks for has moved on",
  "note-done": "Comment: the work may already be done",
  hold: "Nothing yet — waiting on data",
};

export const PENDING_COLUMNS = [
  { label: "What will happen", title: (a) => `action: ${a.kind}`,
    get: (a) => `<span class="act act-${esc(a.kind)}">${esc(ACTION_LABELS[a.kind] || a.kind)}</span>` },
  // The project is in the issue key for anything that already exists, so it is only
  // worth stating for a ticket that does not exist yet.
  { label: "Ticket", get: (a) => {
      if (!a.ticket) {
        return a.route
          ? `<span class="pct">new (${esc(a.route)})</span>`
          : '<span class="pct">new</span>';
      }
      return a.url
        ? `<a href="${esc(a.url)}" target="_blank" rel="noreferrer">${esc(a.ticket)}</a>`
        : esc(a.ticket);
    } },
  { label: "Why", get: (a) => esc(a.why || a.summary || a.comment || "") },
];

export async function loadPending() {
  const el = $("#pending");
  let plan;
  try {
    plan = await get("/api/v1/tickets");
  } catch (e) {
    // Ticketing being unconfigured is a normal state, not a fault, and must not look
    // like one. "unavailable: 503" reads as something broken; the API says which it is,
    // so use its words.
    const why = /not configured/i.test(e.message)
      ? "Jira is not configured, so there is no ticket plan. The queue and the page are unaffected."
      : `Ticket reconciliation is unavailable: ${esc(e.message)}`;
    el.innerHTML = `<div class="meta">${why}</div>`;
    return;
  }

  const all = plan.actions || [];
  // Skips and holds are counted, not listed. One is already correct; the other writes
  // nothing and is waiting on data, so neither belongs in a list of pending writes —
  // that list is meant to answer "what is about to change?".
  const writes = all.filter((a) => a.kind !== "skip" && a.kind !== "hold");
  const skipped = all.filter((a) => a.kind === "skip").length;
  const held = all.filter((a) => a.kind === "hold").length;
  const context = [
    skipped ? (skipped === 1
      ? "1 ticket already covers its findings"
      : `${skipped} tickets already cover their findings`) : "",
    held ? `${held} cannot be judged yet, because an upgrade could not be resolved` : "",
  ].filter(Boolean).join("; ");

  if (writes.length === 0) {
    el.innerHTML = `<div class="meta">Nothing will be written.${context ? ` ${esc(context)}.` : ""}</div>`;
    return;
  }

  // Whether these will be applied is the difference between a plan and a warning.
  const fate = plan.auto_apply
    ? `<strong>These will be applied on the next scheduled refresh.</strong>`
    : `These are not applied automatically: auto-ticketing is off.`;

  el.innerHTML = `<div class="banner"><strong>${writes.length} change${
    writes.length === 1 ? "" : "s"} waiting</strong>. ${fate}${
    context ? `<div class="reasons-more">${esc(context)}.</div>` : ""}</div>
    <div class="scroll short"><table>
      <thead><tr>${PENDING_COLUMNS.map((c) => `<th>${esc(c.label)}</th>`).join("")}</tr></thead>
      <tbody>${writes.map((a) =>
        `<tr>${PENDING_COLUMNS.map((c) => `<td>${c.get(a)}</td>`).join("")}</tr>`).join("")}</tbody>
    </table></div>`;
}

// Manual, because computing the plan queries the tracker: doing that on every poll
// would put a Jira round trip behind an idle browser tab.
// initPending wires the manual refresh. See initTable on why this is not module-level.
export function initPending() {
  // Guarded because this module is also imported by the dashboard's bundle graph; only
  // the ticket plan page has the button.
  const btn = $("#ticketsRefresh");
  if (btn) btn.addEventListener("click", loadPending);
}

// The rules, on demand. Fetched on first open rather than with every refresh: they
// change when someone deploys, not hourly, and they are the largest payload here.
