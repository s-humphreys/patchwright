// Mutable page state, in one place.
//
// ES modules export bindings, not values: a `let` imported elsewhere cannot be
// reassigned by the importer. Rather than scatter setter functions, the handful of
// things that genuinely change live on one object — what the last refresh returned,
// and which panels the reader has expanded (which must survive the re-render an
// hourly poll triggers, or the detail folds away while somebody is reading it).
export const S = {
  // The findings the queue is showing, and the work items they collapse into. Both,
  // because a click has to find its way back from a rendered row to either one.
  groupRows: [],
  // The findings surviving the filter bar. Every view renders from this, so no two views
  // can disagree about what the reader asked for.
  filtered: [],
  queueRows: [],
  // Open tickets by image repository, from the API. Undefined means Jira is not
  // configured, which is NOT the same as "no ticket exists" and must not render as
  // if it were.
  ticketsByRepo: undefined,
  // When the loaded findings were assessed. Per-CVE detail is loaded separately and
  // has to be able to say which assessment it belongs to, or a refresh would leave
  // last hour's CVEs merged into this hour's findings.
  assessedAt: null,
  // Why per-CVE detail could not be loaded, when it could not. Rendered rather than
  // swallowed: an empty CVE table and a failed fetch look identical otherwise.
  vulnError: undefined,
  lastOwners: null,
  gapsExpanded: false,
  severityExpanded: false,
  configLoaded: false,
};
