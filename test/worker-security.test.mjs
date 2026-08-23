import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const worker = await readFile(new URL("../worker.js", import.meta.url), "utf8");
const wrangler = await readFile(new URL("../wrangler.toml", import.meta.url), "utf8");
const html = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
const favicon = await readFile(new URL("../web/favicon.svg", import.meta.url), "utf8");

test("public shell includes share metadata, structured data and accessible copy", () => {
  assert.match(html, /property="og:image"/);
  assert.match(html, /<script type="application\/ld\+json">/);
  assert.match(html, /rel="icon"/);
  assert.match(favicon, /Email Security Checker/);
  assert.doesNotMatch(html, /class="(?:eyebrow|section-label)"/);
  assert.doesNotMatch(html, /—/);
});

test("public UI has hardened headers and explicit discovery routes", () => {
  assert.match(worker, /Content-Security-Policy/);
  assert.match(worker, /Strict-Transport-Security/);
  assert.ok(worker.includes("static.cloudflareinsights.com"));
  // robots.txt and sitemap.xml are now served as static assets from web/
  assert.ok(worker.includes("env.ASSETS"));
  // Security headers are defined for API responses
  assert.ok(worker.includes("X-Content-Type-Options"));
  assert.ok(worker.includes("Referrer-Policy"));
  assert.ok(worker.includes("X-Robots-Tag"));
  assert.match(wrangler, /run_worker_first\s*=\s*true/);
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

test("MTA-STS policy reads are byte-bounded, abortable, and cache only durable observations", () => {
  assert.match(worker, /const MTA_STS_POLICY_MAX_BYTES = 16 \* 1024/);
  assert.match(worker, /readBodyBytes\(response\.body, MTA_STS_POLICY_MAX_BYTES, controller\.signal/);
  assert.match(worker, /reader\.cancel\(signal\.reason\)/);
  // workerd rejects redirect:'error' before sending anything (every policy
  // fetch failed in production), so the fetch must use 'manual' and then
  // refuse any 3xx or off-origin final URL itself.
  assert.doesNotMatch(worker, /redirect:\s*'error'/);
  assert.match(worker, /redirect:\s*'manual'/);
  assert.match(worker, /response\.status >= 300 && response\.status < 400/);
  assert.match(worker, /did not remain on the expected mta-sts origin/);
  // Transient failures (timeout/abort/network) must not be pinned into the
  // edge cache; only fetched policies or definitive HTTP answers are cached.
  assert.match(worker, /const durableObservation = result\.fetched \|\| \(result\.status !== null && !result\.error\)/);
  assert.match(worker, /if \(durableObservation\) \{\s*await cache\.put/);
});

test("P0 analysis keeps DNS uncertainty, score confidence, and SPF flatten proofs explicit", () => {
  assert.match(worker, /const REQUEST_SUBREQUEST_LIMIT = 45/);
  assert.match(worker, /status === 'budget_exceeded'/);
  assert.match(worker, /score_confidence/);
  assert.match(worker, /unknown_controls/);
  assert.match(worker, /function findSpfRecord\(records\)/);
  assert.match(worker, /findSpfRecord/);
  assert.match(worker, /safeToPublish: context\.proof/);
  assert.match(worker, /include terminal .* proven -all subset/);
});

test("analysis schedules scored controls before the unscored PTR observation", () => {
  // PTR carries no score weight but can fan out across every MX host address;
  // if it is scheduled before DKIM discovery it starves scored controls of
  // subrequest budget and domains read as poorly configured.
  const dkimCall = worker.indexOf("checkDKIMSelectors(domain, spf.providers");
  const ptrCall = worker.indexOf("await checkPTR(");
  assert.ok(dkimCall > -1 && ptrCall > -1, "both call sites must exist");
  assert.ok(dkimCall < ptrCall, "DKIM discovery must be scheduled before PTR");
  assert.match(worker, /const MAX_PTR_OBSERVATIONS = 4/);
  // The selector scan must reach the whole catalogue: truncating below its
  // size excluded the date-based entries Google publishes.
  assert.doesNotMatch(worker, /DKIM_SELECTORS\]\)\]\.slice\(0,/);
});

test("API contract rejects null and wrong-type JSON payloads", () => {
  assert.match(worker, /Request body must be a JSON object/);
  assert.match(worker, /ips must contain up to 10 unique public/);
  assert.match(worker, /A batch may contain at most/);
  assert.match(worker, /validation, request_budget/);
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
  assert.match(worker, /request\.method === 'POST'.*MCP_PATHS\.has\(url\.pathname\)/);
  assert.match(worker, /await limiter\.limit\(\{ key: client \}\)/);
  assert.match(worker, /429,\s*\{ \.\.\.corsHeaders, 'Retry-After': String\(retryAfter\) \}/);
  assert.match(worker, /if \(request\.method === 'OPTIONS'\)/);
  assert.match(worker, /url\.pathname === '\/api\/health' && \(request\.method === 'GET' \|\| request\.method === 'HEAD'\)/);
  assert.match(worker, /CF-Connecting-IP.*anonymous/);
});
