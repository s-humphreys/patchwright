// The page refreshes every 60 seconds and re-renders whatever panel is open. This is
// about that re-render keeping the panel the SAME KIND of thing.
//
// The bug: a work item panel records a representative image alongside its key, so a
// refresh that asks only "which image is open" gets an answer for a service panel too,
// and reopens it as that single image. A minute after opening a service, the panel
// silently narrowed to one of its tags.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body>' +
  '<table id="findings"><thead><tr></tr></thead><tbody></tbody></table>' +
  '<aside id="detail" hidden></aside>' +
  '</body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;
globalThis.location = dom.window.location;
globalThis.history = dom.window.history;

const { openDetail, openGroupDetail, closeDetail, shownImage, shownGroup, groupByKey } =
  await import('./detail.js');
const { groupFindings } = await import('./groups.js');
const { S } = await import('./state.js');

function finding(over = {}) {
  return {
    image: 'reg/app:1.0.0', repository: 'app', registry: 'reg', tag: '1.0.0',
    counts: { critical: 1, high: 2 }, provider_assessed: true, scanned: true,
    priority: 'high', reasons: [], signals: [], exposure: 'internal',
    liveness: { live: true }, upgrade: null, vulns: [], ...over,
  };
}

// Built by the real grouping code rather than hand-rolled, so this fixture cannot drift
// from the shape the panel actually consumes.
function workItem() {
  const rows = [
    finding({ image: 'reg/app:1.0.0', tag: '1.0.0' }),
    finding({ image: 'reg/app:1.0.1', tag: '1.0.1' }),
  ];
  const groups = groupFindings(rows);
  return { group: groups[0], rows };
}

test('a refresh keeps a service panel a service panel', () => {
  const { group: g, rows } = workItem();
  S.groupRows = [g];
  S.queueRows = rows;
  openGroupDetail(g);

  // What the panel reports about itself is what the refresh acts on.
  const key = shownGroup();
  assert.ok(key, 'a work item panel must identify itself as one');

  // Simulate the refresh decision in loadAll: group first, image only as fallback.
  const openGroup = shownGroup();
  const openImage = shownImage();
  if (openGroup) {
    const fresh = groupByKey(openGroup);
    assert.ok(fresh, 'the work item must be findable by key across a refresh');
    openGroupDetail(fresh);
  } else if (openImage) {
    openDetail(S.queueRows.find((f) => f.image === openImage));
  }

  assert.equal(shownGroup(), key, 'the panel changed kind under the reader');
  // The service panel lists every tag it covers; a single-image panel cannot.
  const text = document.querySelector('#detail').textContent;
  assert.ok(text.includes('1.0.1'), 'the refreshed panel is no longer showing the whole work item');
  closeDetail();
});

test('a single image panel is still restored as an image', () => {
  // The fallback must keep working: this is the path the fix reorders, not removes.
  const { group: g, rows } = workItem();
  S.groupRows = [g];
  S.queueRows = rows;
  openDetail(rows[1]);
  assert.equal(shownGroup(), null, 'an image panel must not claim to be a work item');
  assert.equal(shownImage(), 'reg/app:1.0.1');
  closeDetail();
});

test('a work item is found by key, not by its representative image', () => {
  // The representative tag can change between runs while the work item is the same
  // one, so matching on the image would lose the panel exactly when the queue moved.
  const { group: g } = workItem();
  S.groupRows = [g];
  openGroupDetail(g);
  const key = shownGroup();

  const moved = { ...workItem().group, image: 'reg/app:1.0.1' };
  S.groupRows = [moved];
  assert.ok(groupByKey(key), 'the work item must survive its representative tag changing');
  closeDetail();
});

test('a refresh does not steal focus', () => {
  // The panel focuses its close button when it OPENS, which is right. Doing it again on
  // a 60 second timer takes focus off whatever the reader was doing, once a minute.
  const { group: g, rows } = workItem();
  S.groupRows = [g];
  S.queueRows = rows;
  openGroupDetail(g);

  // The reader tabs onto something inside the panel and stays there.
  const target = document.querySelector('#detail .openable') ||
    document.querySelector('#detail button');
  assert.ok(target, 'no focusable element in the panel to test with');
  target.focus();
  assert.equal(document.activeElement, target);

  openGroupDetail(groupByKey(shownGroup())); // the refresh repaint
  assert.notEqual(document.activeElement?.id, 'detailClose',
    'the repaint pulled focus to the close button');
  closeDetail();
});

test('a refresh keeps the reader where they had scrolled to', () => {
  // Replacing innerHTML resets the scroll container. On a finding with hundreds of CVEs
  // that means being yanked to the top of the list every minute: the panel stays open,
  // which is not the same as staying usable.
  //
  // jsdom does no layout, so scrollTop is a stub that always reads 0 and ignores writes.
  // Backing it per-element on the prototype is what makes this test real: a repainted
  // panel gets FRESH elements, so the value can only be 420 afterwards if our code
  // carried it across. A closure-backed stub would have passed either way, which is
  // exactly how the first version of this test fooled me.
  const store = new WeakMap();
  const proto = dom.window.Element.prototype;
  const original = Object.getOwnPropertyDescriptor(proto, 'scrollTop');
  Object.defineProperty(proto, 'scrollTop', {
    configurable: true,
    get() { return store.get(this) || 0; },
    set(v) { store.set(this, v); },
  });

  try {
    const { group: g, rows } = workItem();
    S.groupRows = [g];
    S.queueRows = rows;
    const body = () => document.querySelector('#detail .detail-body');

    openDetail(rows[0]);
    body().scrollTop = 420;

    openDetail(rows[0]); // the refresh repaint of the same finding
    assert.equal(body().scrollTop, 420, "the repaint lost the reader's position");

    // A DIFFERENT subject is not a repaint, and must start at the top rather than
    // inheriting somebody else's scroll offset.
    openDetail(rows[1]);
    assert.equal(body().scrollTop, 0, 'a different subject must not inherit a scroll position');
    closeDetail();
  } finally {
    if (original) Object.defineProperty(proto, 'scrollTop', original);
    else delete proto.scrollTop;
  }
});
