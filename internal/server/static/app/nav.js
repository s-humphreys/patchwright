import { $, elapsed } from './util.js';

// One header, defined once, used by every page.
//
// It used to be hand-written per page: three copies that drifted, a refresh button
// on two of them, and links that read as a run-on line rather than as somewhere you
// are. Worse, the header wrapped on a narrow window and the refresh control was the
// thing that dropped off the end - the one control people reach for.
//
// A custom element rather than a shared render function. The header has state
// (which page, is an assessment running), it lives on three pages with three
// different scripts, and connectedCallback/disconnectedCallback give it somewhere
// honest to start and stop its polling. Nothing here needs a framework.

const PAGES = [
  { id: "queue", href: "/", label: "Queue" },
  { id: "analytics", href: "/analytics", label: "Analytics" },
  { id: "tickets", href: "/tickets", label: "Ticket plan" },
];

// Defined inside the guard: importing this module must not require a DOM. It is
// pulled in transitively by page modules that unit tests import headlessly, and
// evaluating `extends HTMLElement` at import time broke every one of them.
if (typeof HTMLElement !== "undefined" && typeof customElements !== "undefined"
    && !customElements.get("pw-nav")) {
  class PatchwrightNav extends HTMLElement {
    connectedCallback() {
      const current = this.getAttribute("page") || "queue";
      const links = PAGES.map((p) => `<a href="${p.href}"${
        p.id === current ? ' aria-current="page"' : ""
      }>${p.label}</a>`).join("");

      this.innerHTML = `
        <header class="app-header">
          <a class="brand" href="/">
            <img class="logo" src="/favicon.png" alt="" width="24" height="24">
            <span class="brand-name">patchwright</span>
          </a>
          <nav class="pages" aria-label="Pages">${links}</nav>
          <div class="header-status">
            <span class="meta" id="freshness"></span>
            <span class="meta" id="dataAge"></span>
          </div>
          <button id="refresh" class="refresh" type="button"
            title="Ask the server to run a new assessment">
            <span class="spinner" aria-hidden="true"></span>
            <span class="refresh-label">Refresh</span>
          </button>
        </header>`;

      this.button = /** @type {HTMLButtonElement} */ (this.querySelector("#refresh"));
      this.button.addEventListener("click", () => this.refresh());
    }

    disconnectedCallback() {
      // Polling outlives the element otherwise, and on a page that is being replaced
      // it keeps firing against a DOM that no longer exists.
      this.stop();
    }

    stop() {
      if (this.poll) clearInterval(this.poll);
      this.poll = null;
      if (this.controller) this.controller.abort();
      this.controller = null;
    }

    /**
     * running switches the control between "you may ask for one" and "one is already
     * happening".
     *
     * Disabled rather than hidden. A control that vanishes takes its explanation with
     * it, and the reader is left wondering whether they mis-clicked; a disabled button
     * with a spinner says what is going on and where the button will be when it is
     * over.
     */
    running(on, since) {
      if (!this.button) return;
      this.button.disabled = on;
      this.button.classList.toggle("is-running", on);
      const label = this.querySelector(".refresh-label");
      if (label) label.textContent = on ? "Assessing" : "Refresh";
      this.button.title = on
        ? `An assessment has been running${since ? " " + since : ""}. This can take several minutes.`
        : "Ask the server to run a new assessment";
      this.setAttribute("aria-busy", on ? "true" : "false");
    }

    /** refresh asks for an assessment and follows it to completion. */
    async refresh() {
      if (this.button?.disabled) return;
      this.running(true);
      try {
        await fetch("/api/v1/assessments", { method: "POST" });
      } catch {
        // The request itself failing is not the same as the assessment failing, and
        // the status line will say so on the next poll.
        this.running(false);
        return;
      }
      this.watch();
    }

    /**
     * watch polls until the server stops reporting a run in progress.
     *
     * Each poll carries an AbortController so a page being torn down, or a second
     * watch starting, cannot leave a request in flight that resolves later and
     * re-enables a button that should still be disabled.
     */
    watch() {
      this.stop();
      this.poll = setInterval(async () => {
        this.controller = new AbortController();
        try {
          const res = await fetch("/api/v1/summary", { signal: this.controller.signal });
          const s = await res.json();
          const a = s.assessment;
          if (a?.running) {
            this.running(true, elapsed(a));
            this.dispatchEvent(new CustomEvent("pw:assessing", { bubbles: true, detail: a }));
            return;
          }
          this.stop();
          this.running(false);
          // The page owns what to reload; the header owns knowing when.
          this.dispatchEvent(new CustomEvent("pw:assessed", { bubbles: true, detail: a }));
        } catch (err) {
          if (/** @type {any} */ (err)?.name === "AbortError") return;
          this.stop();
          this.running(false);
        }
      }, 2000);
    }
  }

  customElements.define("pw-nav", PatchwrightNav);
}

/** nav returns the header element, for pages that need to drive it. */
export function nav() {
  return /** @type {any} */ ($("pw-nav"));
}
