// "Fixed in 3.3.5-2.azl3" has no subject. These are about giving it one, and about the
// question that follows immediately: is that mine to fix, or does it come with the base?
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://x/' });
globalThis.document = dom.window.document;
globalThis.window = dom.window;

const { vulnFixCell, packageOrigin } = await import('./cells.js');

test('an OS package reads as the base image\'s, a language package as the app\'s', () => {
  // The distinction that decides who does the work: openssl arrives with the base, so a
  // rebuild carries the fix; golang.org/x/net is compiled in, so no rebuild of anyone
  // else's image will help.
  for (const os of ['debian', 'ubuntu', 'alpine', 'azurelinux', 'AzureLinux', 'rpm']) {
    assert.equal(packageOrigin(os), 'base', `${os} should read as the base image's`);
  }
  for (const app of ['gobinary', 'npm', 'pypi', 'gomod', 'maven', 'nuget']) {
    assert.equal(packageOrigin(app), 'app', `${app} should read as the application's`);
  }
  // Unknown ecosystem asserts nothing.
  assert.equal(packageOrigin(''), null);
  assert.equal(packageOrigin(undefined), null);
});

test('an ecosystem that could be either says so instead of guessing', () => {
  // A .NET runtime ships with the base image unless the application was published
  // self-contained, in which case it is baked into the app layer. On the sampled estate
  // that was 2,492 rows: calling it wrongly would send a lot of work to the wrong team.
  assert.equal(packageOrigin('dotnet-core'), 'either');

  const html = vulnFixCell({
    fix_available: true,
    packages: [{ name: 'Microsoft.NETCore.App', ecosystem: 'dotnet-core', fixed_in: '8.0.14' }],
  }, true);
  assert.match(html, /dotnet-core/, 'an ambiguous origin should be named by its ecosystem');
  assert.doesNotMatch(html, /pkg-base"|pkg-app"/, 'it must not claim a side it cannot know');
  assert.match(html, /Could be either/, 'and the hover has to explain why');
});

test('the cell names the package, where it lands, and the version', () => {
  const html = vulnFixCell({
    fix_available: true, fixed_version: '3.3.5-2.azl3',
    packages: [{ name: 'openssl', ecosystem: 'azurelinux', fixed_in: '3.3.5-2.azl3' }],
  }, true);
  assert.match(html, /openssl/);
  assert.match(html, /3\.3\.5-2\.azl3/);
  assert.match(html, /pkg-base/, 'an OS package should be marked as coming with the base');
});

test('several packages are counted rather than hidden behind the first', () => {
  // One CVE routinely implicates several packages in one image - up to seventeen in the
  // sampled data. Showing only the first would understate the work.
  const html = vulnFixCell({
    fix_available: true,
    packages: [
      { name: 'libwmf-0.2-7', ecosystem: 'debian', fixed_in: '0.2.13-1.1' },
      { name: 'libwmf-dev', ecosystem: 'debian', fixed_in: '0.2.13-1.1' },
      { name: 'libwmflite-0.2-7', ecosystem: 'debian', fixed_in: '' },
    ],
  }, true);
  assert.match(html, /libwmf-0\.2-7/);
  assert.match(html, /\+2/, 'the other packages should be counted');
  assert.match(html, /libwmf-dev/, 'and named in the hover');
});

test('a package with no fix says so rather than showing an empty version', () => {
  const html = vulnFixCell({
    fix_available: false,
    packages: [{ name: 'libwmf-dev', ecosystem: 'debian', fixed_in: '' }],
  }, true);
  assert.match(html, /libwmf-dev/);
  assert.match(html, /no fix/);
});

test('a fixed version with no package admits the package is unknown', () => {
  // What the old rendering did for every row: a version with no subject. It is honest
  // only if it says which half is missing.
  const html = vulnFixCell({ fix_available: true, fixed_version: '1.2.3', packages: [] }, true);
  assert.match(html, /1\.2\.3/);
  assert.match(html, /package unknown/);
});

test('no fix and no package is still just "no fix"', () => {
  const html = vulnFixCell({ fix_available: false, packages: [] }, true);
  assert.match(html, /no fix/);
  assert.doesNotMatch(html, /package unknown/);
});
