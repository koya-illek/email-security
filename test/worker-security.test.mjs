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

test("a budget-exhausted DKIM scan with findings stays inconclusive, not complete", () => {
  // Reproduced on microsoft.com: 45/45 subrequests consumed mid-scan, only
  // selector2 found, yet the report scored excellent with high confidence and
  // an empty unknown_controls list. A scan that stopped early must land in
  // unknown_controls regardless of how many selectors it did find; only the
  // zero-findings branch may keep its own status handling.
  const analyzeDkimBody = worker.slice(worker.indexOf("function analyzeDKIM("), worker.indexOf("function estimateDkimKeyBits("));
  assert.ok(analyzeDkimBody.length > 0, "analyzeDKIM must exist");
  assert.match(
    analyzeDkimBody,
    /results\.dnsStatus === 'partial' \|\| results\.dnsStatus === 'budget_exceeded'/,
    "findings-present branch must treat budget exhaustion like a partial scan"
  );
  assert.match(analyzeDkimBody, /DNS budget ran out; the remaining selectors were never checked/);
  assert.match(analyzeDkimBody, /unknown: partial/);
});

test("PTR forward confirmation compares addresses, not textual spellings", () => {
  // Equivalent IPv6 forms across two lookups (2001:db8::1 vs
  // 2001:db8:0:0:0:0:0:1) must confirm rather than warn.
  const checkPtrBody = worker.slice(worker.indexOf("async function checkPTR("), worker.indexOf("async function analyzeSPF("));
  assert.ok(checkPtrBody.length > 0, "checkPTR must exist");
  assert.match(checkPtrBody, /normalizedAddresses/);
  assert.match(checkPtrBody, /ipaddr\.parse\(candidate\)\.toString\(\) === normalizedIp/);
  assert.doesNotMatch(checkPtrBody, /matches:\s*Boolean\(ptr && forward\.includes\(ip\)\)/);
  // A budget that dies before the first observation is a different cause from
  // hosts publishing no addresses; the fallback reason must not fabricate one
  // from the other (live-reproduced on gmail.com under a constrained budget).
  assert.match(checkPtrBody, /budget ran out before any inbound MX host address could be observed/);
});

test("the DKIM key estimator reports RSA-3072 instead of warning to rotate it", () => {
  // Base64 SPKI lengths: 1024 ≈ 200, 2048 ≈ 360-392, 3072 ≈ 533, 4096 ≈ 707;
  // the previous 550 cutoff classified real 3072-bit keys as 2048.
  const estimator = worker.slice(worker.indexOf("function estimateDkimKeyBits("), worker.indexOf("function analyzeMX("));
  assert.ok(estimator.length > 0, "estimateDkimKeyBits must exist");
  assert.match(estimator, /length < 300\) return 1024/);
  assert.match(estimator, /length < 450\) return 2048/);
  assert.match(estimator, /length < 650\) return 3072/);
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

test("the release flow pins the deployed source revision instead of a stale placeholder", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.scripts.deploy, "node scripts/deploy.mjs");
  // The static fallback must be an honest marker, not a plausible-looking lie.
  assert.match(wrangler, /SOURCE_REVISION = "unpinned"/);
  const deployScript = await readFile(new URL("../scripts/deploy.mjs", import.meta.url), "utf8");
  assert.match(deployScript, /rev-parse/, "revision must come from git");
  assert.match(deployScript, /status.+--porcelain/s, "dirty worktrees must be marked");
  assert.match(deployScript, /--var/, "wrangler must receive the revision override");
  assert.match(deployScript, /SOURCE_REVISION:\$\{revision\}/);
});

test("the shell/metadata audit is committed and wired as a runnable command", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.scripts["audit:html"], "node scripts/audit-html.mjs");
  const audit = await readFile(new URL("../scripts/audit-html.mjs", import.meta.url), "utf8");
  // The checks earlier rounds cited must live in the repo, not in scratch:
  // canonical metadata, structured data, robots/sitemap consistency, and
  // machine-readable contract validity.
  for (const topic of ["canonical", "JSON-LD structured data", "robots.txt", "sitemap.xml", "openapi.yaml", "mcp-copilot.yaml"]) {
    assert.ok(audit.includes(topic), `audit must cover ${topic}`);
  }
});
