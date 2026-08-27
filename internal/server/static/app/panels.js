import { S } from './state.js';
import { $, elapsed, esc, hasAssessment } from './util.js';

export function renderFreshness(a) {
  const el = $("#freshness");
  if (a && a.error) {
    el.textContent = `last refresh failed: ${a.error}`;
    el.className = "meta err";
    return;
  }
  if (!hasAssessment(a)) {
    // A first full assessment can take many minutes (every cluster, every image),
    // and showing zeros meanwhile would read as a clean estate.
    el.textContent = a && a.running
      ? `first assessment in progress${elapsed(a)}, this can take several minutes`
      : "no assessment yet";
    el.className = "meta";
    return;
  }
  let text = `assessed ${new Date(a.generated_at).toLocaleString()}`;
  if (a.running) text += ` (refresh in progress${elapsed(a)})`;
  el.textContent = text;
  el.className = "meta";
}

// renderDataAge states when the scan provider last looked, which is a different
// question from when this pipeline last ran. A server refreshing hourly over a
// mounted export reports a fresh assessment forever while the data underneath it
// ages; without this, a week-old export is indistinguishable from a current one.
export function renderDataAge(s) {
  const el = $("#dataAge");
  if (!s.provider_data_newest) {
    el.textContent = "";
    return;
  }
  const newest = new Date(s.provider_data_newest);
  const days = Math.floor((Date.now() - newest.getTime()) / 86400000);
  const age = days < 1 ? "today" : days === 1 ? "1 day old" : `${days} days old`;
  el.textContent = `· scan data ${newest.toLocaleDateString()} (${age})`;
  // Older than a couple of days is worth noticing rather than reading past: the
  // queue is only as current as the export behind it.
  el.className = days >= 2 ? "meta err" : "meta";
  el.title = "When the scan provider last assessed these images, as opposed to when"
    + " this assessment ran. A stale export produces a fresh-looking assessment of old data.";
}

// Data gaps: what this assessment cannot tell you, in one place.
//
// These were three stacked full-width banners of prose. Every one shouted equally, so
// the page led with several paragraphs of caveats and buried the queue — and one of
// them was good news dressed as a warning: 96% coverage is not the same alarm as 9%.
//
// One panel now. Each gap gets a single line stating the count and the consequence,
// and the explanation sits behind a toggle. The lines are never hidden: a gap nobody
// can see is the failure this whole section exists to prevent. Only the prose folds.
// Survives the re-render that follows every refresh, so an hourly poll does not fold
// the detail away while somebody is reading it.

export function renderCoverage(s) {
  const el = $("#coverage");
  const gaps = dataGaps(s);
  if (gaps.length === 0) {
    el.innerHTML = "";
    return;
  }
  const worst = gaps.some((g) => g.severe);
  const rows = gaps.map((g) => `
    <div class="gap${g.severe ? " gap-severe" : ""}">
      <span class="gap-count">${esc(g.count)}</span>
      <span class="gap-head">${g.headline}</span>
      <div class="gap-detail"${S.gapsExpanded ? "" : " hidden"}>${g.detail}</div>
    </div>`).join("");
  el.innerHTML = `<div class="gaps${worst ? " banner" : " gaps-quiet"}">
    <div class="gaps-title">
      <strong>${gaps.length} data gap${gaps.length === 1 ? "" : "s"}</strong>
      <button id="gapsToggle" class="linkish" aria-expanded="${S.gapsExpanded}">${
        S.gapsExpanded ? "hide detail" : "why this matters"}</button>
    </div>${rows}</div>`;

  $("#gapsToggle").addEventListener("click", () => {
    S.gapsExpanded = !S.gapsExpanded;
    renderCoverage(s);
  });
}

// dataGaps describes each gap once: a count, a one-line consequence, and the detail.
//
// severe marks the ones that change what the queue means rather than merely trimming
// it. A missing vuln source disables whole priority tiers, so nothing can be urgent
// however bad it is; 4% of images unassessed does not deserve the same colour as that.
export function dataGaps(s) {
  const gaps = [];
  // A source that FAILED and a source that was never configured produce the same empty
  // cells and need opposite responses. Telling somebody to add --exploit-source when
  // they already have it, and it 502'd, sends them to fix the wrong thing.
  const total = (s.provider_assessed || 0) + (s.provider_unassessed || 0);

  if (s.provider_unassessed > 0 && total > 0) {
    const share = s.provider_unassessed / total;
    gaps.push({
      // Proportion decides the alarm: most of an estate unassessed is a different
      // problem from a handful of unsupported registries.
      severe: share >= 0.25,
      count: `${s.provider_unassessed} of ${total}`,
      headline: `findings never assessed by the scan provider (${Math.round((1 - share) * 100)}% covered)`,
      detail: `Their severity counts are absent data rather than zero, so they cannot match a
        count-based rule.${s.actionable_unassessed
          ? ` ${s.actionable_unassessed} of the ${s.actionable} actionable findings are on images the
             provider never assessed, found by a vulnerability scanner alone.` : ""}
        ${reasonList(s.unassessed_reasons)}`,
    });
  }

  if (s.scanned === 0) {
    gaps.push({
      severe: true,
      count: "no",
      headline: "image was scanned for per-CVE detail, so no finding can reach the priorities that need it",
      detail: `Fix availability, EPSS and KEV are absent, and every rule requiring <code>vulns</code>
        is false — however bad a finding is. Counts from the scan provider still work. Add
        <code>--vuln-source trivy</code> (chart: <code>scan.enabled</code>) to populate it.`,
    });
  } else if (s.exploit_checked === 0 && !failed(s, "exploit")) {
    gaps.push({
      severe: false,
      count: `${s.scanned}`,
      headline: "findings have per-CVE detail but no exploit intelligence, so EPSS and KEV are unknown",
      detail: `Rules requiring exploitation pressure cannot fire, and the EPSS column reads "-"
        rather than 0. Add <code>--exploit-source public</code> (chart:
        <code>scan.exploitSource</code>).`,
    });
  }

  for (const f of s.source_failures || []) {
    // An enrichment that could not run, stated rather than inferred. Exploit intel gates
    // whole priority tiers, so its absence changes what the queue means — and the cells
    // that go quiet ("?" for EPSS, KEV, risk) give no clue why.
    gaps.push({
      severe: f.stage === "exploit",
      count: "no",
      headline: f.stage === "exploit"
        ? "exploit intelligence could be gathered, so nothing here can be ranked by exploitation pressure"
        : `${esc(f.stage)} data could be gathered`,
      detail: `The assessment completed without it — losing an enrichment does not lose
        the queue — but every signal it would have set reads "not checked" rather than
        "none found". The source reported: <code>${esc(shortReason(f.error))}</code>`,
    });
  }

  if (s.in_flight_unmatchable > 0) {
    gaps.push({
      severe: false,
      count: `${s.in_flight_unmatchable}`,
      headline: "findings can never be matched to a pull request, because their image records no build repository",
      detail: `These render as "n/a" rather than "-": nothing can tie them to remediation in
        flight, whoever opens it. The fix is in the build pipeline — set one of
        <code>remediation.base.repoLabels</code> on the image
        (e.g. <code>org.opencontainers.image.source</code>) so a pull request can be
        matched to what it rebuilds.`,
    });
  }

  if (s.remediation_unresolved > 0) {
    const share = total > 0 ? s.remediation_unresolved / total : 0;
    // When one cause accounts for most of it, name that cause in the headline rather
    // than behind the toggle. An expired registry credential has flattened this queue
    // three times, and each time it took someone deliberately expanding the detail to
    // find out why. A single fixable cause should not need a click.
    const top = (s.remediation_blockers || [])[0];
    const dominant = top && top.findings / s.remediation_unresolved >= 0.5 ? top : null;
    gaps.push({
      severe: share >= 0.25,
      count: `${s.remediation_unresolved}`,
      headline: dominant
        ? `findings have no resolvable upgrade, ${dominant.findings} of them for one reason: ${esc(shortReason(dominant.reason))}`
        : "findings have no resolvable upgrade — unknowns, not \"nothing to fix\"",
      detail: reasonList(s.remediation_blockers) ||
        "No reason was recorded, which is itself worth chasing.",
    });
  }
  return gaps;
}

// shortReason trims a provider or registry error to its point. These arrive as whole
// HTTP errors ("read image config for x: reading image x: POST https://… UNAUTHORIZED:
// authentication required, visit https://… for m…"), and a headline has to be readable
// at a glance or it is no better than the toggle it replaced.
/** @type {{pattern: RegExp, plain: string}[]} */
const REASON_PATTERNS = [
  { pattern: /UNAUTHORIZED|authentication required|401/i, plain: "cannot authenticate to the registry" },
  { pattern: /DENIED|forbidden|403/i, plain: "registry denied access" },
  { pattern: /no such host|dial tcp|timeout|deadline/i, plain: "cannot reach the registry" },
  { pattern: /not found|404|MANIFEST_UNKNOWN/i, plain: "image or tag not found in the registry" },
  { pattern: /records no base|no base image/i, plain: "image records no base image" },
];

export function shortReason(reason) {
  const r = String(reason || "");
  for (const { pattern, plain } of REASON_PATTERNS) {
    if (pattern.test(r)) return plain;
  }
  return r.length > 90 ? r.slice(0, 87) + "…" : r;
}

// reasonList renders provider- or source-supplied reasons, largest first.
//
// This is the difference between a statistic and a work list. A percentage invites
// resignation; "cannot authenticate to the registry, 734 findings" names something one
// person can fix in an afternoon. Absent when nothing states a reason, which is not the
// same as there being no cause.
export function reasonList(reasons) {
  if (!reasons || !reasons.length) return "";
  const top = reasons.slice(0, 4);
  const rest = reasons.length - top.length;
  const items = top.map((r) =>
    `<li><strong>${r.findings}</strong> ${esc(r.reason)}</li>`).join("");
  return `<div class="reasons"><ul>${items}</ul>
    ${rest > 0 ? `<div class="reasons-more">and ${rest} other reason${rest === 1 ? "" : "s"}.</div>` : ""}
    </div>`;
}

export function renderTiles(s) {
  const tiles = [
    ["Findings", s.findings], ["Actionable", s.actionable],
    ["Assessed", s.provider_assessed], ["Suppressed", s.suppressed],
    ["Upgradable", s.upgradable], ["Known exploited", s.known_exploited],
    ["Unique images", s.unique_images],
  ];
  // Only shown when detection ran. A "0 in flight" tile on a run without a
  // provider configured would claim nobody is working on any of this.
  if (s.in_flight_checked > 0) tiles.push(["In flight", s.in_flight]);
  $("#tiles").innerHTML = tiles.map(([l, n]) =>
    `<div class="tile"><div class="n">${n ?? "-"}</div><div class="l">${esc(l)}</div></div>`).join("");
}

// Column definitions drive both rendering and sorting, so the two cannot disagree
// about what a column contains.
//
// sort is the comparison key, not the displayed text: "urgent" must outrank
// "high" rather than sorting after it alphabetically, and a "?" count must not
// sort as if it were a number. Unknowns sort to the bottom in both directions,
// since "we do not know" is never the answer someone is looking for at the top.

/** failed reports whether an enrichment stage reported a failure this run. */
export function failed(summary, stage) {
  return (summary.source_failures || []).some((f) => f.stage === stage);
}
