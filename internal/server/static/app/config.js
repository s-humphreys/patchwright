import { S } from './state.js';
import { $, esc, get } from './util.js';

// Minimal YAML highlighting: comments, keys, quoted strings and literals.
//
// Deliberately not a parser. It never has to produce a value, only make structure
// visible, so a line it does not recognise is emitted verbatim rather than guessed
// at — the failure mode is plain text, not wrong text.
export function highlightYAML(text) {
  return text.split("\n").map(highlightYAMLLine).join("\n");
}

export function highlightYAMLLine(line) {
  const [code, comment] = splitComment(line);
  let out = "";

  // "  - name: platform" and "  name: platform" differ only by the marker.
  const m = code.match(/^(\s*)(-\s+)?([A-Za-z0-9_.\-\/]+)(\s*:)(\s*)(.*)$/);
  if (m) {
    const [, indent, dash, key, colon, gap, value] = m;
    out = esc(indent)
      + (dash ? `<span class="y-dash">${esc(dash)}</span>` : "")
      + `<span class="y-key">${esc(key)}</span>${esc(colon)}${esc(gap)}`
      + highlightValue(value);
  } else {
    // A bare list item, e.g. "  - cloud-provider".
    const li = code.match(/^(\s*)(-\s+)(.*)$/);
    out = li
      ? esc(li[1]) + `<span class="y-dash">${esc(li[2])}</span>` + highlightValue(li[3])
      : esc(code);
  }
  return out + (comment ? `<span class="y-com">${esc(comment)}</span>` : "");
}

// highlightValue marks quoted strings and scalars. An image reference or a CEL
// expression is left as plain text, which is what it should look like.
export function highlightValue(value) {
  if (value === "") return "";
  // Trailing whitespace before a comment would otherwise stop a quoted value
  // matching, so the same string was coloured on one line and not the next.
  const trimmed = value.replace(/\s+$/, "");
  const tail = value.slice(trimmed.length);
  const mark = (cls) => `<span class="${cls}">${esc(trimmed)}</span>` + esc(tail);
  if (/^(['"]).*\1$/.test(trimmed)) return mark("y-str");
  if (/^(true|false|null|~|-?\d+(\.\d+)?)$/.test(trimmed)) return mark("y-lit");
  return esc(value);
}

// splitComment separates a trailing comment, ignoring a "#" inside quotes — a CEL
// expression or an image tag can contain one, and colouring the rest of the line as
// a comment would misrepresent the config being explained.
export function splitComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') { quote = c; continue; }
    // A "#" only starts a comment at the start of the line or after whitespace,
    // so a URL fragment or a tag is not mistaken for one.
    if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) {
      return [line.slice(0, i), line.slice(i)];
    }
  }
  return [line, ""];
}

export async function loadConfig() {
  const el = $("#config");
  try {
    const cfg = await get("/api/v1/config");
    el.innerHTML = (cfg.sources || []).map((src) => `
      <div class="cfg-file">
        <div class="cfg-path">${esc(src.path)}${src.redacted
          ? ' <span class="pct">— a value was redacted</span>' : ""}</div>
        <pre class="cfg-yaml">${highlightYAML(src.content)}</pre>
      </div>`).join("");
  } catch (e) {
    // Says which question cannot be answered, rather than only that a fetch failed.
    el.innerHTML = `<div class="banner">Could not read the loaded rules: ${esc(e.message)}.
      This is what the assessment was run with, so without it the verdicts on this page
      cannot be explained.</div>`;
  }
}

// initConfig wires the rules viewer. See initTable on why this is not module-level.
export function initConfig() {
  $("#configToggle").addEventListener("click", async () => {
  const el = $("#config"), btn = $("#configToggle");
  const opening = el.hidden;
  el.hidden = !opening;
  btn.setAttribute("aria-expanded", String(opening));
  btn.textContent = opening ? "hide config" : "show config";
  if (opening && !S.configLoaded) {
    S.configLoaded = true;
    await loadConfig();
  }
});
}
