import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const worker = await readFile(new URL("../worker.js", import.meta.url), "utf8");
const wrangler = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");

test("public UI has hardened headers and explicit discovery routes", () => {
  assert.match(worker, /Content-Security-Policy/);
  assert.match(worker, /Strict-Transport-Security/);
  assert.ok(worker.includes("static.cloudflareinsights.com"));
  // robots.txt and sitemap.xml are now served as static assets from web/
  assert.ok(worker.includes("env.ASSETS"));
  // Security headers are defined for API responses
  assert.ok(worker.includes("X-Content-Type-Options"));
  assert.ok(worker.includes("Referrer-Policy"));
});

test("unknown routes do not fall through to the application HTML", () => {
  // Non-API GET requests are served via ASSETS binding; everything else gets 404
  assert.ok(worker.includes("!url.pathname.startsWith('/api/')"));
  assert.ok(worker.includes("env.ASSETS.fetch(request)"));
  assert.ok(worker.includes("new Response('Not found', { status: 404"));
});

test("API JSON parsing uses bounded stream reads", () => {
  assert.doesNotMatch(worker, /request\.json\(\)/);
  assert.match(worker, /async function readJsonBody\(request, maxBytes\)/);
  assert.match(worker, /const NORMAL_JSON_BODY_MAX_BYTES = 16 \* 1024/);
  assert.match(worker, /const HEADER_JSON_BODY_MAX_BYTES = 256 \* 1024/);
  assert.match(worker, /await reader\.cancel\(\)/);
});

test("MTA-STS policy reads are byte-bounded and abortable", () => {
  assert.match(worker, /const MTA_STS_POLICY_MAX_BYTES = 16 \* 1024/);
  assert.match(worker, /readBodyBytes\(response\.body, MTA_STS_POLICY_MAX_BYTES, controller\.signal/);
  assert.match(worker, /reader\.cancel\(signal\.reason\)/);
});

test("Cloudflare Rate Limiting bindings define separate standard and expensive budgets", () => {
  assert.match(wrangler, /\[\[ratelimits\]\][\s\S]*?name = "STANDARD_RATE_LIMITER"[\s\S]*?namespace_id = "1001"[\s\S]*?limit = 60[\s\S]*?period = 60/);
  assert.match(wrangler, /\[\[ratelimits\]\][\s\S]*?name = "EXPENSIVE_RATE_LIMITER"[\s\S]*?namespace_id = "1002"[\s\S]*?limit = 10[\s\S]*?period = 60/);
  assert.match(worker, /fetch\(request, env\)/);
  assert.match(worker, /handleRequest\(request, env\)/);
  assert.doesNotMatch(worker, /rateLimitBuckets|RATE_LIMIT_WINDOW_MS/);
});

test("POST rate limiting classifies expensive paths, preserves CORS, and bypasses health and OPTIONS", () => {
  for (const path of [
    "/api/check",
    "/api/header/enrich",
    "/api/spf/inspect",
    "/api/spf/evaluate"
  ]) {
    assert.match(worker, new RegExp(`['"]${path.replaceAll('/', '\\/')}['"]`));
  }
  assert.match(worker, /request\.method === 'POST' && url\.pathname\.startsWith\('\/api\/'\) && url\.pathname !== '\/api\/health'/);
  assert.match(worker, /await limiter\.limit\(\{ key: client \}\)/);
  assert.match(worker, /429,\s*\{ \.\.\.corsHeaders, 'Retry-After': String\(retryAfter\) \}/);
  assert.match(worker, /if \(request\.method === 'OPTIONS'\)/);
  assert.match(worker, /url\.pathname === '\/api\/health' && request\.method === 'GET'/);
  assert.match(worker, /CF-Connecting-IP.*anonymous/);
});
