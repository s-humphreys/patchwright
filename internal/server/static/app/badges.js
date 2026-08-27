import { epssPercent, maxEPSS } from './cells.js';
import { esc } from './util.js';

export const KIND_BADGES = {
  base:  { glyph: "\u25a4", label: "base",  cls: "badge-base",
           help: "The fix is in the base image this is built on: rebuild on a newer base." },
  chart: { glyph: "\u2388", label: "chart", cls: "badge-chart",
           help: "The version comes from a Helm chart, so the bump is applied to the chart." },
  image: { glyph: "\u2b21", label: "image", cls: "badge-image",
           help: "A newer tag of this image itself." },
};

// Who owns the version, when it is not this image's own tag. Same vocabulary as the
// upgrade kinds so the two read as one system.
export const MANAGED_BADGES = {
  helm:      { glyph: "\u2388", label: "helm",      cls: "badge-helm",
               help: "A Helm chart owns this tag: bump the chart, not the image." },
  operator:  { glyph: "\u2699", label: "operator",  cls: "badge-operator",
               help: "An operator owns this tag: upgrade the operator or its custom resource." },
  kustomize: { glyph: "\u25c7", label: "kustomize", cls: "badge-other",
               help: "The tag is set in Kustomize overlays." },
  manifest:  { glyph: "\u25c7", label: "manifest",  cls: "badge-other",
               help: "The tag is set directly in a manifest." },
};

export function badge(spec, fallbackLabel) {
  const b = spec || { glyph: "\u25cb", label: fallbackLabel || "other", cls: "badge-other",
                      help: "Version owned elsewhere." };
  return `<span class="badge ${b.cls}" title="${esc(b.help)}">` +
         `<span class="g" aria-hidden="true">${b.glyph}</span>${esc(b.label)}</span>`;
}

// upgradeCell is the rendered form: badges for the kind and, where something else
// owns the version, for the owner. upgradeText stays the plain-text form, because it
// is also the sort key and what the search box matches.

export const SIGNAL_BADGES = {
  exposed:      { glyph: "\u25c9", label: "exposed", cls: "badge-exposed",
                  help: "Reachable from the internet, per the scan provider. An exposed critical is a different proposition from an internal one." },
  kev:          { glyph: "\u26a1", label: "kev", cls: "badge-kev",
                  help: "Carries a CVE in CISA's Known Exploited Vulnerabilities catalogue: confirmed exploitation in the wild, not a prediction." },
  "in-flight":  { glyph: "\u21c4", label: "pr", cls: "badge-inflight",
                  help: "An open pull request in the repository that builds this image applies the upgrade." },
  "stale-fix":  { glyph: "\u23f1", label: "stale", cls: "badge-stale",
                  help: "That pull request has been open past the configured threshold. The fix exists and nobody has merged it." },
  unassessed:   { glyph: "\u25cc", label: "unassessed", cls: "badge-unassessed",
                  help: "The scan provider never assessed this image, so its zero counts are absent data rather than a clean result." },
  suppressed:   { glyph: "\u2298", label: "suppressed", cls: "badge-other",
                  help: "A suppress rule matched, so this is out of the actionable queue." },
  "end-of-life": { glyph: "\u2620", label: "eol", cls: "badge-eol",
                  help: "The line this image is built on is no longer maintained, so no future fix will reach this tag. Today's CVE count is the lowest it will ever be, and the only remedy is moving off the line." },
};

// Ordered by how much each should change what somebody does next, so the badges read
// left to right in that order regardless of the order the API returns them.
// end-of-life sits above kev deliberately. A KEV is one exploited vulnerability that a
// rebuild can close today; an end-of-life base is every vulnerability from here on with
// no rebuild that closes any of them. Sorting it lower would bury the finding whose cost
// compounds under the ones that do not.
export const SIGNAL_ORDER = ["exposed", "end-of-life", "kev", "stale-fix", "in-flight", "unassessed", "suppressed"];
export const SIGNAL_WEIGHT = { exposed: 64, "end-of-life": 32, kev: 16, "stale-fix": 8, "in-flight": 4, unassessed: 2, suppressed: 1 };

export function signalsCell(f) {
  const set = new Set(f.signals || []);
  const out = [];
  for (const name of SIGNAL_ORDER) {
    if (!set.has(name)) continue;
    let spec = SIGNAL_BADGES[name];
    // The pull request badge earns its age: "pr" says someone started, "pr 340d"
    // says the fix has been sitting in review since last spring.
    if (name === "in-flight" && f.in_flight) {
      spec = { ...spec, label: `pr ${f.in_flight.open_days}d`,
               help: `${f.in_flight.title} — open ${f.in_flight.open_days}d in ${f.in_flight.repository}.` +
                     (f.in_flight.exact ? "" : " Bumps the same dependency to a different version, so it may not be this fix.") };
    }
    out.push(f.in_flight?.url && (name === "in-flight" || name === "stale-fix")
      ? `<a href="${esc(f.in_flight.url)}" target="_blank" rel="noreferrer" class="badge ${spec.cls}" title="${esc(spec.help)}"><span class="g" aria-hidden="true">${spec.glyph}</span>${esc(spec.label)}</a>`
      : badge(spec, name));
  }
  // Exposure is three-valued, and "nobody reported it" must not look like internal.
  if (!set.has("exposed")) {
    out.push(f.exposure === "internal"
      ? '<span class="muted" title="Not reachable from the internet, per the scan provider.">internal</span>'
      : '<span class="unknown" title="Nothing reported whether this is reachable from the internet. Not the same as internal.">?</span>');
  }
  if (!f.in_flight_checked && f.upgrade?.available) {
    out.push('<span class="unknown" title="In-flight detection did not run, so it is not known whether anyone has started this.">pr?</span>');
  }
  if (f.in_flight_reason) {
    out.push(`<span class="act-unknown" title="${esc(f.in_flight_reason)}">unmatchable</span>`);
  }
  return out.join(" ");
}

// Sort by the weight of what a finding carries, so the exposed, exploited and stalled
// rise together rather than alphabetically.
export function signalsSort(f) {
  let w = 0;
  for (const s of f.signals || []) w += SIGNAL_WEIGHT[s] || 0;
  return w;
}

// Provider counts are only meaningful if the provider actually assessed the image.
export const count = (f, sev) => (f.provider_assessed ? (f.counts?.[sev] ?? 0) : "?");
export const epss = (f) => (f.exploit_checked ? epssPercent(maxEPSS(f)) : "-");

// The scan provider's own composite ranking, highest across the image's CVEs.
// Deliberately its own column rather than folded into EPSS: Rapid7's scale runs to
// roughly 1000 and EPSS is a probability, so one column holding both would be a
// column of numbers that mean different things.
