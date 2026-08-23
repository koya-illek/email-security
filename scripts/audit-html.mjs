#!/usr/bin/env node
// Read-only audit of the public shell and machine-readable contracts.
// Iterations 4-5 cited an uncommitted scratch script by this name; this
// committed version makes the claim reproducible with one command:
//
//   node scripts/audit-html.mjs https://email.illek.ie/
//   npm run audit:html -- http://127.0.0.1:8787/
//
// Every check fetches over HTTP and exits non-zero on the first failure
// category it cannot satisfy.
import assert from 'node:assert/strict';
import yaml from 'js-yaml';

const base = process.argv[2] && /^https?:\/\//.test(process.argv[2])
  ? process.argv[2].replace(/\/$/, '')
  : null;
if (!base) {
  console.error('Usage: node scripts/audit-html.mjs <https://base-url>');
  process.exit(2);
}

const results = [];
function check(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      results.push(['pass', name]);
      return true;
    })
    .catch(error => {
      results.push(['fail', `${name}: ${error.message}`]);
      return false;
    });
}

async function get(path) {
  const response = await fetch(`${base}${path}`, { redirect: 'follow' });
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${path}`);
  return response;
}

const htmlResponse = await get('/');
const html = await htmlResponse.text();
const origin = new URL(htmlResponse.url).origin;

await Promise.all([
  check('document basics: doctype, lang, charset, viewport', () => {
    assert.match(html, /<!doctype html>/i);
    assert.match(html, /<html[^>]*\slang="en"/i);
    assert.match(html, /<meta\s+charset="utf-8"/i);
    assert.match(html, /<meta\s+name="viewport"\s+content="[^"]*width=device-width/i);
  }),

  check('title and meta description are present and descriptive', () => {
    const title = html.match(/<title>([^<]+)<\/title>/i)?.[1]?.trim();
    assert.ok(title && title.length >= 20, 'title missing or too short');
    assert.match(title, /SPF|DKIM|DMARC/i, 'title should name the controls');
    const description = html.match(/<meta\s+name="description"\s+content="([^"]+)"/i)?.[1];
    assert.ok(description && description.length >= 50, 'description missing or too short');
  }),

  check('canonical link is absolute HTTPS on the served origin', () => {
    const canonical = html.match(/<link\s+rel="canonical"\s+href="([^"]+)"/i)?.[1];
    assert.ok(canonical, 'canonical link missing');
    const url = new URL(canonical);
    assert.equal(url.protocol, 'https:', 'canonical must be https');
    if (new URL(base).protocol === 'https:') {
      assert.equal(url.origin, origin, 'canonical origin must match the served host');
    }
  }),

  check('Open Graph and Twitter card metadata are complete', () => {
    for (const property of ['og:title', 'og:description', 'og:type', 'og:url', 'og:image', 'og:image:width', 'og:image:height', 'og:image:alt']) {
      assert.match(html, new RegExp(`<meta\\s+property="${property}"`), `${property} missing`);
    }
    assert.match(html, /<meta\s+name="twitter:card"/);
    assert.match(html, /<meta\s+name="twitter:image"/);
    const image = html.match(/<meta\s+property="og:image"\s+content="([^"]+)"/i)?.[1];
    assert.match(image || '', /^https:\/\//, 'og:image must be absolute https');
  }),

  check('JSON-LD structured data parses and describes a web application', () => {
    const block = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/i)?.[1];
    assert.ok(block, 'JSON-LD block missing');
    const parsed = JSON.parse(block);
    assert.equal(parsed['@context'], 'https://schema.org');
    assert.equal(parsed['@type'], 'WebApplication');
    assert.ok(parsed.name && parsed.description);
  }),

  check('skip link targets a real landmark id', () => {
    const target = html.match(/class="skip-link"[^>]*href="#([^"]+)"/i)?.[1]
      ?? html.match(/href="#([^"]+)"[^>]*class="skip-link"/i)?.[1];
    assert.ok(target, 'skip link missing');
    assert.match(html, new RegExp(`id="${target}"`), `skip target #${target} missing`);
  }),

  check('noscript notice explains where submissions go', () => {
    assert.match(html, /<noscript><p class="noscript-note">[\s\S]+?<\/noscript>/i);
  }),

  check('nested record-builder tabs expose selection and panel relationships', () => {
    assert.match(html, /class="builder-tabs"[^>]*role="tablist"[^>]*aria-label="Record type"/i);
    for (const name of ['spf', 'dmarc']) {
      assert.match(html, new RegExp(`<button[^>]*id="tab-builder-${name}"[^>]*role="tab"[^>]*aria-controls="builder-${name}"`));
      assert.match(html, new RegExp(`<section[^>]*id="builder-${name}"[^>]*role="tabpanel"[^>]*aria-labelledby="tab-builder-${name}"`));
    }
    assert.match(html, /id="tab-builder-spf"[^>]*aria-selected="true"/i);
    assert.match(html, /id="tab-builder-dmarc"[^>]*aria-selected="false"[^>]*tabindex="-1"/i);
  }),

  check('favicon and social card resolve', async () => {
    const favicon = html.match(/<link\s+rel="icon"\s+href="([^"]+)"/i)?.[1];
    assert.ok(favicon, 'favicon missing');
    const iconUrl = new URL(favicon, htmlResponse.url).toString();
    assert.equal((await fetch(iconUrl)).status, 200, `favicon ${iconUrl} not reachable`);
    const image = html.match(/<meta\s+property="og:image"\s+content="([^"]+)"/i)?.[1];
    const imageUrl = new URL(image, htmlResponse.url).toString();
    const imageResponse = await fetch(imageUrl);
    assert.equal(imageResponse.status, 200, `social card ${imageUrl} not reachable`);
    assert.match(imageResponse.headers.get('content-type') || '', /^image\//);
  }),

  check('robots.txt advertises a reachable single-URL sitemap', async () => {
    const robots = await (await get('/robots.txt')).text();
    const sitemapLine = robots.match(/^Sitemap:\s*(\S+)$/mi)?.[1];
    assert.ok(sitemapLine, 'robots.txt lacks a Sitemap directive');
    const sitemap = await (await get('/sitemap.xml')).text();
    assert.match(sitemap, /<urlset/, 'sitemap.xml is not a urlset');
    const urls = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map(match => match[1]);
    const canonical = html.match(/<link\s+rel="canonical"\s+href="([^"]+)"/i)?.[1];
    assert.deepEqual(urls, [canonical], 'sitemap must list exactly the canonical page');
  }),

  check('openapi.yaml parses and covers every published route', async () => {
    const spec = yaml.load(await (await get('/openapi.yaml')).text());
    assert.match(String(spec.openapi), /^3\./, 'openapi must be a 3.x document');
    assert.ok(spec.info?.title && spec.info?.version);
    for (const path of [
      '/api/health', '/api/check', '/api/v2/domain-check', '/api/v2/header-analysis',
      '/api/batch', '/api/spf/inspect', '/api/spf/evaluate', '/api/records/validate',
      '/api/v2/record-build', '/api/header/enrich', '/api/reports/{reportId}',
      '/api/reports/{reportId}/export', '/mcp/v2'
    ]) {
      assert.ok(spec.paths[path], `openapi is missing ${path}`);
    }
    assert.ok(spec.paths['/api/health'].get, 'health must document GET');
    assert.ok(spec.paths['/api/health'].head, 'health must document HEAD');
    const reportGet = spec.paths['/api/reports/{reportId}'].get;
    assert.ok(reportGet.responses['404'] && reportGet.responses['503'],
      'report retrieval must document absence (404) and storage failure (503)');
    for (const path of ['/api/check', '/api/batch', '/api/records/validate']) {
      assert.ok(spec.paths[path].post.responses['413'], `${path} must document the body-cap 413`);
    }
  }),

  check('MCP connector manifest parses', async () => {
    const manifest = yaml.load(await (await get('/mcp-copilot.yaml')).text());
    assert.ok(manifest && typeof manifest === 'object', 'mcp-copilot.yaml did not parse');
  }),
]);

let failed = 0;
for (const [status, name] of results) {
  console.log(`${status === 'pass' ? 'ok  ' : 'FAIL'} ${name}`);
  if (status === 'fail') failed += 1;
}
console.log(`\n${results.length - failed}/${results.length} audit checks passed for ${base}`);
process.exit(failed ? 1 : 0);
