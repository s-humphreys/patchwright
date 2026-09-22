// A stand-in for `patchwright serve`, for the browser tests.
//
// It serves the embedded pages and modules exactly as the Go binary does, from the
// same files, and answers the API from fixtures under test/ui/fixtures. A test that
// needs a different answer overrides a route in the browser (page.route) rather than
// changing the fixture, so the fixtures stay the one realistic estate every test
// starts from.
//
// Node only; nothing here ships.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const staticDir = join(here, '..', '..', 'internal', 'server', 'static');
const fixtures = join(here, 'fixtures');
const port = Number(process.env.PORT || 4173);

const pages = { '/': 'index.html', '/analytics': 'analytics.html', '/tickets': 'tickets.html' };
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.json': 'application/json' };

// API paths map to a fixture file by name; the query string is ignored so a
// history request for any range gets the same three periods.
const api = {
  '/api/v1/summary': 'summary.json',
  '/api/v1/analytics': 'analytics.json',
  '/api/v1/history': 'history.json',
  '/api/v1/findings': 'findings.json',
  '/api/v1/items': 'items.json',
  '/api/v1/owners': 'owners.json',
  '/api/v1/tickets': 'tickets.json',
};

async function send(res, status, body, type) {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-cache' });
  res.end(body);
}

createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${port}`);
  const path = url.pathname;
  try {
    if (req.method === 'POST' && path === '/api/v1/assessments') {
      return send(res, 202, '{"status":"started"}', types['.json']);
    }
    if (api[path]) {
      const f = join(fixtures, api[path]);
      if (!existsSync(f)) return send(res, 200, '{}', types['.json']);
      return send(res, 200, await readFile(f), types['.json']);
    }
    if (pages[path]) {
      return send(res, 200, await readFile(join(staticDir, pages[path])), types['.html']);
    }
    if (path === '/favicon.png') {
      return send(res, 200, await readFile(join(staticDir, 'favicon.png')), types['.png']);
    }
    if (path.startsWith('/static/app/')) {
      const rel = normalize(path.slice('/static/'.length));
      if (rel.includes('..')) return send(res, 404, 'not found', 'text/plain');
      const f = join(staticDir, rel);
      if (!existsSync(f)) return send(res, 404, 'not found', 'text/plain');
      return send(res, 200, await readFile(f), types[extname(f)] || 'application/octet-stream');
    }
    return send(res, 404, 'not found', 'text/plain');
  } catch (err) {
    return send(res, 500, String(err), 'text/plain');
  }
}).listen(port, () => {
  console.log(`ui fixture server on http://localhost:${port}`);
});
