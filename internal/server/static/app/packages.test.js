// The Fix column: what to upgrade, not just a version.
//
// It read "3.3.5-2.azl3" — a version with no subject, unactionable without knowing
// which of an image's hundreds of packages it meant. The package is named only
// where a scan measured it; the alternative, the provider's own per-CVE package
// field, names an ecosystem the image does not contain 66% of the time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;

const { vulnFixCell } = await import('./cells.js');

test('a measured package is named alongside the version that fixes it', () => {
  const out = vulnFixCell({
    fix_available: true, fixed_version: '3.3.5-2.azl3', origin: 'base',
    packages: [{ name: 'openssl', ecosystem: 'azurelinux', fixed_in: '3.3.5-2.azl3' }],
  });
  assert.match(out, /openssl/);
  assert.match(out, /3\.3\.5-2\.azl3/);
  assert.match(out, />base</, 'the reader needs to know whose package it is');
});

test('several packages collapse to the first plus a count', () => {
  // A CVE routinely affects openssl and openssl-libs. Listing every one turns the
  // column into a paragraph.
  const out = vulnFixCell({
    fix_available: true,
    packages: [
      { name: 'openssl', fixed_in: '1.2' },
      { name: 'openssl-libs', fixed_in: '1.2' },
      { name: 'openssl-devel', fixed_in: '1.2' },
    ],
  });
  assert.match(out, /openssl</);
  assert.match(out, /\+2/);
  assert.match(out, /openssl-libs, openssl-devel/, 'the rest belong in the tooltip');
});

test('an application CVE shows the version alone rather than a guessed package', () => {
  // Nothing scanned the application layer. Naming a package here would be the
  // 66%-wrong provider field, and a confidently wrong package is worse than none.
  const out = vulnFixCell({
    fix_available: true, fixed_version: '1.2.3', origin: 'app', packages: [],
  });
  assert.match(out, /1\.2\.3/);
  assert.doesNotMatch(out, />base</, 'an unmeasured CVE must not be labelled as the base\'s');
  assert.doesNotMatch(out, /<code>/, 'no package name should be invented');
});

test('no fix available still says so, with or without a package', () => {
  assert.match(vulnFixCell({ fix_available: false, packages: [] }), /no fix/);
  const named = vulnFixCell({
    fix_available: true,
    packages: [{ name: 'zlib', ecosystem: 'debian', fixed_in: '' }],
  });
  assert.match(named, /zlib/);
  assert.match(named, /no fix/, 'a named package with no fix version must not imply one exists');
});

test('the package name is escaped, since it comes from a scanner', () => {
  const out = vulnFixCell({
    fix_available: true,
    packages: [{ name: '<img src=x onerror=alert(1)>', fixed_in: '1' }],
  });
  assert.doesNotMatch(out, /<img/);
  assert.match(out, /&lt;img/);
});
