import { S } from './state.js';
import { $, ago, elapsed, esc, hasAssessment } from './util.js';

export function renderFreshness(a) {
  // Which build is answering. Rendered from the same payload as the freshness line
  // because they are read together: "assessed 4 minutes ago, by v1.29.0" is one
  // fact about what you are looking at, and the version is the half that tells two
  // deployments apart when a rollout has only half happened.
  const ver = $("#version");
  if (ver) ver.textContent = a && a.version ? a.version : "";

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
  // Relative, because the question is "is this recent" and not "what time was it".
  // The exact timestamp stays in the tooltip for when somebody does need it.
  el.textContent = `assessed ${ago(a.generated_at)}`;
  el.title = new Date(a.generated_at).toLocaleString();
  if (a.running) el.textContent += ` · reassessing${elapsed(a)}`;
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
    // Stated whether or not a fallback covered them. The fallback compensating is not
    // the provider working, and a coverage gap that stops being reported the moment
    // something else papers over it is a gap nobody ever fixes.
    const recovered = s.fallback_scanned
      ? ` The fallback scanner supplied counts for ${s.fallback_scanned} of them, marked with a
         "~" in the report and from a different vendor feed than the rest of the column.`
      : "";
    gaps.push({
      // Proportion decides the alarm: most of an estate unassessed is a different
      // problem from a handful of unsupported registries.
      severe: share >= 0.25,
      count: `${s.provider_unassessed} of ${total}`,
      headline: `findings never assessed by the scan provider (${Math.round((1 - share) * 100)}% covered)`,
      detail: `Their severity counts are absent data rather than zero, so they cannot match a
        count-based rule.${s.actionable_unassessed
          ? ` ${s.actionable_unassessed} of the ${s.actionable} actionable findings are on images the
             provider never assessed, found by a vulnerability scanner alone.` : ""}${recovered}
        ${reasonList(s.unassessed_reasons)}`,
    });
  }

  // The residual, reported apart from the gap above. "6 unassessed" and "6 unassessed,
  // 5 of them recovered" call for different amounts of alarm, and the one number cannot
  // say which. Only when a fallback ran at all: without one, uncovered is just
  // provider_unassessed said twice.
  if (s.uncovered > 0 && (s.fallback_scanned || s.fallback_failed)) {
    gaps.push({
      severe: false,
      count: `${s.uncovered} of ${s.provider_unassessed}`,
      headline: "unassessed findings the fallback scanner could not cover either, so nothing has any data for them",
      detail: `${s.fallback_failed
        ? `The fallback was asked about ${s.fallback_failed} and could not read them — usually the
           same registry credential the provider failed on.`
        : "The fallback was never asked about them: scan policy skips these images."}
        ${reasonList(s.fallback_failures)}`,
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

// The headline is a story, not a scoreboard.
//
// It was eight equal-weight numbers in a row, which a security reviewer cannot read: 671
// findings beside 887 unique images beside 220 suppressed states no relationship between
// any of them, and the most important number on the page - how many are actually being
// exploited - sat between "upgradable" and "unique images" at the same size.
//
// Two groups instead. The funnel says what happened to the scanner's output: raised,
// suppressed by policy, left in the queue, needing action. Then the sharp end, which is
// what somebody escalates on. Each group carries an expandable explanation, because a
// number whose definition is a guess gets argued about rather than acted on.
export function renderTiles(s) {
  const raised = (s.findings ?? 0) + (s.suppressed ?? 0);
  const pct = (n, of) => (of > 0 ? Math.round((n / of) * 100) : null);

  // Deliberately arithmetic that closes: raised - suppressed = findings, and actionable
  // is a subset of those. Nothing here is a ratio of two different populations.
  const funnel = [
    { label: "raised", n: raised,
      help: "Every finding the scan provider reported, before any of this tool's rules ran." },
    { label: "suppressed", n: s.suppressed ?? 0, tone: "drop",
      of: raised,
      help: "Removed by a suppress rule: not running anywhere, owned by the cloud provider, or otherwise decided to be out of the queue. Each one is a decision somebody wrote down, not a finding that vanished." },
    { label: "in the queue", n: s.findings ?? 0, of: raised,
      help: "What is left to look at after suppression." },
    { label: "needs action", n: s.actionable ?? 0, of: s.findings ?? 0, tone: "focus",
      help: "Policy's verdict that this warrants action. Not the same as having a version to move to." },
  ];

  const sharp = [
    { label: "known exploited", n: s.known_exploited ?? 0, tone: "urgent",
      help: "Carries a CVE in CISA's Known Exploited Vulnerabilities catalogue: confirmed exploitation in the wild, not a prediction. The first thing to escalate on." },
    { label: "end of life", n: s.end_of_life, tone: "urgent",
      help: "Built on a runtime or distribution nobody maintains, so no future fix will ever reach it. Every other number here falls when somebody rebuilds; this one falls only when somebody migrates.",
      unchecked: "Support windows were not checked this run." },
    { label: "internet-facing", n: s.exposed ?? 0,
      // Zero exposed AND zero unknown is a claim that nothing in the estate is
      // reachable. Where the provider reports that uniformly it is a statement about
      // the provider, not the estate, and saying so is more useful than a bare 0.
      note: (s.exposed ?? 0) === 0 && (s.exposure_unknown ?? 0) === 0
        ? "none reported" : null,
      help: "Reported reachable from the internet. When every workload comes back as internal, that is usually a field the scan provider does not populate rather than an estate with nothing exposed." },
    { label: "fix in flight", n: s.in_flight,
      only: (s.in_flight_checked ?? 0) > 0,
      help: "An open pull request already applies the upgrade, so this is work somebody has started." },
  ];

  const tile = (t) => {
    if (t.only === false) return "";
    if (t.n === undefined || t.n === null) {
      // The hover goes on the whole tile, not just the "?": a reader aiming at a
      // question mark to find out why it is a question mark is a poor trade.
      const why = `${t.unchecked ? t.unchecked + " " : ""}${t.help}`;
      return `<div class="tile" title="${esc(why)}">` +
        `<div class="n unknown">?</div><div class="l">${esc(t.label)}</div>` +
        `<div class="tile-sub">not checked</div></div>`;
    }
    const share = t.of ? pct(t.n, t.of) : null;
    const sub = t.note
      ? `<div class="tile-sub">${esc(t.note)}</div>`
      : share !== null ? `<div class="tile-sub">${t.tone === "drop" ? "\u2212" : ""}${share}%</div>` : "";
    return `<div class="tile${t.tone ? ` tile-${t.tone}` : ""}" title="${esc(t.help)}">` +
      `<div class="n">${t.n}</div><div class="l">${esc(t.label)}</div>${sub}</div>`;
  };

  const explain = (items) => items.map((i) =>
    i.only === false ? "" : `<div class="dr"><dt>${esc(i.label)}</dt><dd>${esc(i.help)}</dd></div>`).join("");

  $("#tiles").innerHTML = `
    <div class="tilegroup">
      <div class="tilegroup-head">
        <span class="tilegroup-label">What the scan found, and what is left</span>
        <span class="tilegroup-meta">${s.unique_images ?? "-"} unique images</span>
      </div>
      <div class="tilerow funnel">${funnel.map(tile).join('<span class="chev" aria-hidden="true">\u203a</span>')}</div>
      <details class="tile-explain"><summary>what these mean</summary><dl>${explain(funnel)}</dl></details>
    </div>
    <div class="tilegroup">
      <div class="tilegroup-head">
        <span class="tilegroup-label">The sharp end</span>
      </div>
      <div class="tilerow">${sharp.map(tile).join("")}</div>
      <details class="tile-explain"><summary>what these mean</summary><dl>${explain(sharp)}</dl></details>
    </div>`;
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
