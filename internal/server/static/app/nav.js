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
      // An assessment is a property of the SERVER, not of this tab. Somebody else
      // clicking refresh, or the hourly schedule firing, has to put every open page
      // into the same state - otherwise two people watch the same run and only one
      // of them is told it is happening, and the other can start a second.
      this.beat();
    }

    disconnectedCallback() {
      // Polling outlives the element otherwise, and on a page that is being replaced
      // it keeps firing against a DOM that no longer exists.
      this.stop();
    }

    stop() {
      if (this.timer) clearInterval(this.timer);
      this.timer = null;
      if (this.controller) this.controller.abort();
      this.controller = null;
    }

    /**
     * beat polls the server for whether an assessment is running.
     *
     * Two speeds. Idle it asks every fifteen seconds, which is cheap - the endpoint
     * serves a cached snapshot - and is what makes somebody else's run show up here
     * without a page reload. While one is running it asks every two seconds, because
     * that is when the answer is about to change and people are watching.
     */
    beat(fast = false) {
      const every = fast ? 2000 : 15000;
      if (this.timer && this.rate === every) return;
      this.stop();
      this.rate = every;
      this.check();
      this.timer = setInterval(() => this.check(), every);
    }

    async check() {
      if (typeof fetch !== "function") return;
      this.controller = new AbortController();
      try {
        const res = await fetch("/api/v1/summary", { signal: this.controller.signal });
        this.observe((await res.json()).assessment);
      } catch (err) {
        if (/** @type {any} */ (err)?.name === "AbortError") return;
        // A failed poll is not a finished assessment. Leaving the state alone is
        // the honest response: re-enabling on a network blip would invite a second
        // run against a server already doing one.
      }
    }

    /**
     * observe applies an assessment status from anywhere - this element's own poll,
     * or a page that has just fetched the summary for its own reasons.
     *
     * Exported so the queue's existing sixty-second reload does not need a second
     * request to tell the header what it already knows.
     */
    observe(a) {
      const isRunning = !!a?.running;
      const was = this.wasRunning === true;
      this.wasRunning = isRunning;
      // A changed timestamp is new data whether or not this page watched the run that
      // produced it. Without this, only a page that saw a run start and finish knew to
      // reload, so a run by another replica - or one already under way when the page
      // opened - was invisible until something else reloaded blindly.
      const stamp = a?.generated_at;
      const changed = !!stamp && !!this.lastStamp && stamp !== this.lastStamp;
      if (stamp) this.lastStamp = stamp;
      this.running(isRunning, isRunning ? elapsed(a) : "");
      if (isRunning) {
        this.dispatchEvent(new CustomEvent("pw:assessing", { bubbles: true, detail: a }));
        this.beat(true);
        return;
      }
      this.beat(false);
      // Only when there is something new. Firing on every idle poll would reload
      // every page every fifteen seconds.
      if (was || changed) {
        this.dispatchEvent(new CustomEvent("pw:assessed", { bubbles: true, detail: a }));
      }
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
      // Optimistic: the POST has been accepted, so go straight to the running
      // state rather than waiting up to two seconds to be told.
      this.wasRunning = true;
      this.beat(true);
    }

  }

  customElements.define("pw-nav", PatchwrightNav);
}

/** nav returns the header element, for pages that need to drive it. */
export function nav() {
  return /** @type {any} */ ($("pw-nav"));
}
