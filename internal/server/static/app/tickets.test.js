// The ticket plan, now a page of its own.
//
// It used to sit above the queue, where it was impossible to miss and, on a page whose
// subject is the estate, usually beside the point. What matters after moving it is that
// the plan still renders honestly - including the paths where the tracker cannot be read,
// which is the state this deployment is actually in.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body>' +
  '<button id="ticketsRefresh">Refresh plan</button>' +
  '<div id="pending">loading…</div>' +
  '</body></html>', { url: 'http://x/tickets' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;

/** @type {any} */
let reply = { actions: [] };
/** @type {any} */
let fail = null;
globalThis.fetch = async () => {
  if (fail) throw fail;
  return { ok: true, status: 200, json: async () => reply, text: async () => JSON.stringify(reply) };
};

const { initPending, loadPending } = await import('./pending.js');
const text = () => document.querySelector('#pending').textContent;

test('the plan lists what will be written, and counts what will not', async () => {
  reply = { auto_apply: false, actions: [
    { kind: 'create', why: 'new work' },
    { kind: 'close', ticket: 'OPS-1', url: 'https://example.invalid/OPS-1', why: 'done' },
    { kind: 'skip' }, { kind: 'hold' },
  ] };
  await loadPending();
  assert.match(text(), /2 changes waiting/);
  // Skips and holds are counted, not listed: one is already correct and the other
  // writes nothing, so neither answers "what is about to change?".
  assert.match(text(), /1 ticket already covers its findings/);
  assert.match(text(), /cannot be judged yet/);
  assert.match(text(), /Raise a new ticket/);
  assert.match(text(), /auto-ticketing is off/);
});

test('auto-apply is stated, because it is the difference between a plan and a warning', async () => {
  reply = { auto_apply: true, actions: [{ kind: 'create', why: 'x' }] };
  await loadPending();
  assert.match(text(), /will be applied on the next scheduled refresh/);
});

test('an unconfigured tracker is a normal state, not a fault', async () => {
  // "unavailable: 503" reads as something broken. Jira simply not being configured is
  // the state this deployment runs in, and the page says so in those words.
  fail = new Error('ticketing is not configured');
  await loadPending();
  assert.match(text(), /not configured/);
  assert.doesNotMatch(text(), /unavailable/);
  fail = null;
});

test('an unreachable tracker says so rather than showing an empty plan', async () => {
  // The dangerous rendering is "nothing will be written" when the truth is "nobody
  // could ask".
  fail = new Error('jira unreachable');
  await loadPending();
  assert.match(text(), /unavailable/i);
  assert.doesNotMatch(text(), /Nothing will be written/);
  fail = null;
});

test('the refresh button recomputes the plan', async () => {
  // The page is worth reloading on demand rather than on a timer: computing the plan
  // queries the tracker, and the answer only changes when somebody touches it.
  initPending();
  reply = { auto_apply: false, actions: [] };
  await loadPending();
  assert.match(text(), /Nothing will be written/);

  reply = { auto_apply: false, actions: [{ kind: 'update', ticket: 'OPS-9', why: 'moved on' }] };
  document.querySelector('#ticketsRefresh').dispatchEvent(new dom.window.Event('click'));
  await new Promise((r) => setTimeout(r, 20));
  assert.match(text(), /1 change waiting/);
});
