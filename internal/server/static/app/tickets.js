// Entry point for the ticket plan page.
//
// Deliberately tiny. It loads the plan and wires the refresh button, and nothing else:
// the dashboard's modules pull in the queue, the CVE aggregation, the detail panel and
// the URL state, none of which this page has any use for.
import { initPending, loadPending } from './pending.js';
import { showStatus } from './status.js';

initPending();
showStatus();
// A new assessment changes what reconciliation would do, so the plan follows it
// rather than describing the previous one.
document.addEventListener("pw:assessed", () => { loadPending(); showStatus(); });
loadPending();
