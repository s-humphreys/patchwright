// Entry point for the ticket plan page.
//
// Deliberately tiny. It loads the plan and wires the refresh button, and nothing else:
// the dashboard's modules pull in the queue, the CVE aggregation, the detail panel and
// the URL state, none of which this page has any use for.
import { initPending, loadPending } from './pending.js';

initPending();
loadPending();
