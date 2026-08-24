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
  // Analysis-output changes invalidate edge-cached reports; a stale version
  // would keep serving superseded verdicts for up to a day after deploy.
  assert.match(worker, /const CACHE_VERSION = 'v11-dmarc-reporting'/);
});

test("PTR observations keep transient DNS trouble distinct from authoritative absence", () => {
  // A SERVFAIL or timeout on the PTR query is not an observation about the
  // host; rendering it as "No PTR record" would pin resolver trouble onto a
  // mail host for as long as the report lives. Same discipline enrichIp
  // already follows for hop enrichment.
  const checkPtrBody = worker.slice(worker.indexOf("async function checkPTR("), worker.indexOf("async function analyzeSPF("));
  assert.ok(checkPtrBody.length > 0, "checkPTR must exist");
  assert.match(checkPtrBody, /const ptrDefinitive = \['ok', 'nodata', 'nxdomain'\]\.includes\(ptrDns\.status\)/);
  assert.match(checkPtrBody, /ptrUnknown: !ptrDefinitive/);
  const analyzePtrBody = worker.slice(worker.indexOf("function analyzePTR("), worker.indexOf("async function fetchMtaStsPolicy("));
  assert.ok(analyzePtrBody.length > 0, "analyzePTR must exist");
  assert.match(analyzePtrBody, /result\.ptrUnknown/);
  assert.match(analyzePtrBody, /did not complete authoritatively/);
  assert.match(analyzePtrBody, /result\.forwardUnknown/);
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
    "/api/spf/evaluate",
    "/api/records/validate",
    "/api/v2/record-build"
  ]) {
    assert.match(worker, new RegExp(`['"]${path.replaceAll('/', '\\/')}['"]`));
  }
  // The builders run recursive DNS validation plus a full RFC 7208 evaluation;
  // they must sit behind the expensive limiter like inspect, not the cheap one.
  const expensiveSet = worker.slice(worker.indexOf("const EXPENSIVE_POST_PATHS = new Set(["), worker.indexOf("]);", worker.indexOf("const EXPENSIVE_POST_PATHS = new Set([")));
  for (const path of ["/api/records/validate", "/api/v2/record-build", "/api/spf/inspect"]) {
    assert.ok(expensiveSet.includes(`'${path}'`), `${path} must be classified expensive`);
  }
  assert.match(worker, /request\.method === 'POST' && \(POST_API_PATHS\.has\(routePathname\) \|\| MCP_PATHS\.has\(routePathname\)\)/);
  assert.match(worker, /await limiter\.limit\(\{ key: client \}\)/);
  assert.match(worker, /429,\s*\{ \.\.\.corsHeaders, 'Retry-After': String\(retryAfter\) \}/);
  assert.match(worker, /if \(request\.method === 'OPTIONS' && !MCP_PATHS\.has\(routePathname\)\)/);
  assert.match(worker, /routePathname === '\/api\/health' && \(request\.method === 'GET' \|\| request\.method === 'HEAD'\)/);
  assert.match(worker, /CF-Connecting-IP.*anonymous/);
});

test("unmatched machine surfaces answer with the JSON error envelope and 405 on wrong verbs", () => {
  const fallback = worker.slice(worker.indexOf("// Machine surfaces must never receive an unparseable plain-text failure."), worker.indexOf("return new Response('Not found', { status: 404, headers: securityHeaders });"));
  assert.ok(fallback.length > 0, "API fallback must exist");
  assert.match(fallback, /Method \$\{request\.method\} is not allowed for \$\{routePathname\}/);
  assert.match(fallback, /405,\s*\{ \.\.\.corsHeaders, Allow: apiRoute\[1\]\.join\(', '\) \}/);
  assert.match(fallback, /jsonResponse\(\{ error: 'Not found' \}, 404, corsHeaders\)/);
});

test("DMARC honours sp= for inherited records instead of scoring by the parent's p=", async () => {
  // RFC 7489 §6.6.3: p=reject; sp=none at the ancestor means receivers enforce
  // nothing against this subdomain; reporting "maximum protection" would be a
  // materially false verdict.
  const tags = await readFile(new URL("../policy-tags.js", import.meta.url), "utf8");
  const helper = tags.slice(tags.indexOf("function effectiveDmarcPolicy(tags, inherited)"), tags.indexOf("module.exports"));
  assert.ok(helper.length > 0, "effectiveDmarcPolicy must exist");
  assert.match(helper, /inherited && DMARC_POLICY_VALUES\.includes\(tags\.sp\)\) return tags\.sp;/);
  assert.match(helper, /return tags\.p \|\| null;/);
  assert.match(worker, /require\('\.\/policy-tags'\)/);
  const analyze = worker.slice(worker.indexOf("function analyzeDMARC(records, discovery"), worker.indexOf("function parseTagRecord(record)"));
  assert.match(analyze, /= effectiveDmarcPolicy\(tags, inheritedRecord\)/);
  assert.match(analyze, /\$\{usingSp \? 'sp' : 'p'\}=none/);
  // Scoring consumes dmarc.policy, which now carries the effective value.
  assert.match(worker, /score \+= dmarc\.policy === 'reject' \? 35 : 30/);
});

test("duplicate DMARC tags fail live analysis before any policy value is read", () => {
  // parseTagRecord silently keeps the last duplicate, so "p=none;p=reject"
  // was analyzed as whichever came last while the validator refused the same
  // record outright. The live path must fail the record like receivers do.
  const analyze = worker.slice(worker.indexOf("function analyzeDMARC(records, discovery"), worker.indexOf("function parseTagRecord(record)"));
  const duplicateAt = analyze.indexOf("const duplicateTags = []");
  const failAt = analyze.indexOf("if (duplicateTags.length)");
  const policyAt = analyze.indexOf("const publishedPolicy = tags.p || null;");
  assert.ok(duplicateAt > -1, "duplicate-tag detection must exist in analyzeDMARC");
  assert.ok(failAt > -1, "a duplicate-tag failure branch must exist in analyzeDMARC");
  assert.ok(policyAt > -1, "policy parsing must exist in analyzeDMARC");
  assert.ok(failAt < policyAt, "duplicates must fail the record before any tag value is consumed");
});

test("DMARC report-destination parsing treats the mailto scheme case-insensitively", () => {
  // RFC 3986 §3.1: schemes are case-insensitive. The validator accepts
  // MAILTO:, so the authorisation loop must too — uppercase spellings used
  // to silently skip external-destination verification.
  const parser = worker.slice(worker.indexOf("function parseMailtoList("), worker.indexOf("function analyzeDKIM("));
  assert.match(parser, /\/\^mailto:\/i\.test\(item\)/);
  assert.doesNotMatch(parser, /startsWith\('mailto:'\)/);
});

test("malformed MX priorities cannot poison the primary-host sort", () => {
  // DNS data is external input; a NaN priority made Array.sort's comparator
  // meaningless, letting any record render as "Primary:". Unparsable values
  // must sort last behind every real priority.
  const analyzer = worker.slice(worker.indexOf("function analyzeMX("), worker.indexOf("function analyzeCAA("));
  assert.match(analyzer, /Number\.isFinite\(parsed\) \? parsed : 65535/);
  assert.match(analyzer, /Number\.isFinite\(a\.priority\) \? a\.priority : 65535/);
});

test("domain analysis checks external DMARC report authorisation after scored controls", () => {
  const analysis = worker.slice(worker.indexOf("async function analyzeDomain("), worker.indexOf("async function discoverDmarcPolicy("));
  const dkim = analysis.indexOf("await checkDKIMSelectors(");
  const reporting = analysis.indexOf("await addDmarcReportAuthorisation(dmarc, budget)");
  const ptr = analysis.indexOf("await checkPTR(");
  assert.ok(dkim > -1 && reporting > dkim && ptr > reporting, "unscored report authorisation must not starve DKIM");
  assert.match(analysis, /status === 'authorised'/);
  assert.match(analysis, /status === 'unauthorised'/);
  assert.match(analysis, /authorisation is inconclusive/);
});

test("SPF redirect strength is judged from the redirect target's terminal policy", () => {
  const recursion = worker.slice(worker.indexOf("async function countSpfDnsLookupsRecursive("), worker.indexOf("async function buildSpfFlattenPreview("));
  assert.ok(recursion.length > 0, "recursion must exist");
  // The last write to finalAll must belong to the deepest followed target.
  assert.match(recursion, /let followedRedirect = false/);
  assert.match(recursion, /followedRedirect = true;\s*await countSpfDnsLookupsRecursive\(redirect/);
  assert.match(recursion, /if \(!followedRedirect\) state\.finalAll = ownAll;/);
  const analyzeSpf = worker.slice(worker.indexOf("async function analyzeSPF("), worker.indexOf("function findDuplicateSpfIncludes("));
  assert.match(analyzeSpf, /Hard fail via redirect \(-all\)/);
  assert.match(analyzeSpf, /Permissive policy behind redirect/);
  assert.match(analyzeSpf, /SPF redirect points nowhere/, "an unresolvable target is a permanent error, never a pass");
  assert.match(analyzeSpf, /Redirected policy strength unconfirmed/);
});

test("macro-bearing SPF targets are disclosed as unverifiable, not queried literally", () => {
  const recursion = worker.slice(worker.indexOf("async function countSpfDnsLookupsRecursive("), worker.indexOf("async function buildSpfFlattenPreview("));
  assert.match(recursion, /hasSpfMacro\(includeDomain\)/);
  assert.match(recursion, /state\.macroLookups\.push\(includeDomain\)/);
  assert.match(recursion, /state\.macroLookups\.push\(redirect\)/);
  // In the include loop the macro branch must come before any DNS spend.
  const macroBranch = recursion.indexOf("if (hasSpfMacro(includeDomain))");
  const dnsSpend = recursion.indexOf("const nestedRecords = await queryDNS(includeDomain");
  assert.ok(macroBranch > -1 && dnsSpend > -1, "both branches must exist");
  assert.ok(macroBranch < dnsSpend, "macro targets must be classified before querying DNS");
});

test("hop enrichment caches only authoritative PTR outcomes and discloses DNS trouble", () => {
  const enrich = worker.slice(worker.indexOf("async function enrichIp("), worker.indexOf("async function analyzeDomain("));
  assert.ok(enrich.length > 0, "enrichIp must exist");
  assert.match(enrich, /const definitive = \['ok', 'nodata', 'nxdomain'\]\.includes\(dns\.status\)/);
  assert.match(enrich, /result\.dns = dns;/);
  // cache.put must be reachable only on the definitive path.
  assert.doesNotMatch(enrich, /await cache\.put[\s\S]*const definitive/);
  assert.match(enrich, /if \(!definitive\) \{\s*result\.dns = dns;\s*return result;\s*\}/);
});

test("the release flow pins the deployed source revision instead of a stale placeholder", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.scripts.deploy, "node scripts/deploy.mjs");
  // The static fallback must be an honest marker, not a plausible-looking lie.
  assert.match(wrangler, /SOURCE_REVISION = "unpinned"/);
  const deployScript = await readFile(new URL("../scripts/deploy.mjs", import.meta.url), "utf8");
  assert.match(deployScript, /rev-parse/, "revision must come from git");
  assert.match(deployScript, /status.+--porcelain/s, "release cleanliness must come from git");
  assert.match(deployScript, /Refusing to deploy a dirty worktree/, "dirty worktrees must not be released");
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

test("the page CSP serves styles from the stylesheet alone, with no inline style sinks", async () => {
  // Dropping 'unsafe-inline' only holds while no shipped markup or generated
  // DOM carries a style attribute; this pins both halves of that contract.
  assert.match(worker, /style-src 'self';/);
  assert.doesNotMatch(worker, /style-src[^]*?'unsafe-inline'/);
  const app = await readFile(new URL("../web/app.js", import.meta.url), "utf8");
  for (const [name, source] of [["index.html", html], ["app.js", app]]) {
    assert.doesNotMatch(source, / style="/, `${name} must not carry inline style attributes`);
  }
});

test("malformed report ids are refused before spending daily retrieval quota", () => {
  // /api/reports/<garbage> can never reach storage, so it must answer 404
  // without consuming one of the caller's daily retrievals.
  const retrieval = worker.slice(worker.indexOf("// GET /api/reports/:id"), worker.indexOf("// POST /api/batch"));
  const validateAt = retrieval.indexOf("REPORT_ID_RE.test(candidate)");
  const quotaAt = retrieval.indexOf("consumeDailyRateLimit");
  assert.ok(validateAt !== -1, "report id validation must exist in the retrieval path");
  assert.ok(quotaAt !== -1, "daily quota accounting must exist in the retrieval path");
  assert.ok(validateAt < quotaAt, "id validation must precede quota consumption");
});

test("the POST rate-limit gate charges only paths a POST can actually reach", () => {
  // An unknown path must answer 404 without burning daily or per-minute
  // quota; the gate therefore matches routed POST paths explicitly instead
  // of any /api/* prefix.
  const gate = worker.slice(
    worker.indexOf("if (request.method === 'POST' && (POST_API_PATHS.has(routePathname)"),
    worker.indexOf("if (MCP_PATHS.has(routePathname))")
  );
  assert.ok(gate.length > 0, "rate-limit gate must exist");
  assert.match(gate, /POST_API_PATHS\.has\(routePathname\) \|\| MCP_PATHS\.has\(routePathname\)/);
  assert.doesNotMatch(gate, /startsWith\('\/api\/'\)/);
});

test("per-minute rejections never spend a daily quota slot", () => {
  // A burst that trips the per-minute limiter must not also burn one of the
  // caller's few hundred daily requests — otherwise nine minutes of 429s
  // become an all-day lockout for everyone behind a shared IP.
  const gate = worker.slice(
    worker.indexOf("if (request.method === 'POST' && (POST_API_PATHS.has(routePathname)"),
    worker.indexOf("if (MCP_PATHS.has(routePathname))")
  );
  const perMinuteAt = gate.indexOf("await consumePostRateLimit(request");
  const dailyAt = gate.indexOf("await consumeDailyRateLimit(request");
  assert.ok(perMinuteAt > -1, "the per-minute limiter must guard POST paths");
  assert.ok(dailyAt > -1, "the daily counter must still guard POST paths");
  assert.ok(perMinuteAt < dailyAt, "the per-minute limiter must answer before the daily counter is spent");
});

test("daily-limit Retry-After names the real reset instead of a flat day", () => {
  assert.doesNotMatch(worker, /DAILY_RATE_LIMIT_RETRY_AFTER_SECONDS/);
  assert.match(worker, /function secondsUntilDailyReset\(\)/);
  const uses = worker.match(/'Retry-After': String\(secondsUntilDailyReset\(\)\)/g) || [];
  assert.ok(uses.length >= 2, "both daily 429 sites (POST and retrieval) must use the honest countdown");
});

test("quota keys survive IPv6 /64 rotation and IPv4 spelling drift", () => {
  // An IPv6 client controls a /64; per-address counters let one user mint
  // fresh quotas forever, while CGNAT IPv4 users legitimately share theirs.
  assert.match(worker, /function quotaClientKey\(rawIp\)/);
  assert.match(worker, /parsed\.parts\.slice\(0, 4\)\.concat\(\[0, 0, 0, 0\]\)/);
  const limiter = worker.slice(worker.indexOf("async function consumePostRateLimit("), worker.indexOf("async function consumeDailyRateLimit("));
  const daily = worker.slice(worker.indexOf("async function consumeDailyRateLimit("), worker.indexOf("function isValidDomain("));
  for (const [name, source] of [["per-minute limiter", limiter], ["daily counter", daily]]) {
    assert.match(source, /quotaClientKey\(/, `${name} must key on the normalized client`);
    assert.doesNotMatch(source, /headers\.get\('CF-Connecting-IP'\)\?\.trim/, `${name} must not key on the raw spelling`);
  }
});

test("unexpected faults answer opaque references; crafted errors keep their copy", () => {
  const fault = worker.slice(worker.indexOf("function requestErrorResponse("), worker.indexOf("async function readJsonBody("));
  assert.ok(fault.length > 0, "the shared fault responder must exist");
  // Only errors crafted for the client (exposed marker or explicit status)
  // may echo their message; everything else gets an opaque reference and a
  // server-side log line, never engine text like a TypeError's stack hint.
  assert.match(fault, /const intentional = error\?\.exposed === true \|\| Number\.isInteger\(error\?\.status\);/);
  assert.match(fault, /jsonResponse\(\{ error: `Internal error \(\$\{reference\}\)\.` \}, 500, corsHeaders\)/);
  assert.match(fault, /console\.error\(JSON\.stringify/);
  assert.match(worker, /function exposedError\(message\)/);
});

test("the MCP tool-call catch mirrors the REST fault discipline", async () => {
  const mcp = await readFile(new URL("../mcp.js", import.meta.url), "utf8");
  const caught = mcp.slice(mcp.indexOf("} catch (error) {"), mcp.lastIndexOf("}"));
  assert.match(caught, /const intentional = error\?\.exposed === true \|\| Number\.isInteger\(error\?\.status\);/);
  assert.match(caught, /failed internally \(\$\{reference\}\)/);
  assert.match(caught, /console\.error\(JSON\.stringify/);
});

test("crafted validation errors are marked exposed at their throw sites", async () => {
  const analyzer = await readFile(new URL("../header-analyzer.js", import.meta.url), "utf8");
  assert.match(analyzer, /empty\.exposed = true;/);
  assert.match(analyzer, /oversized\.exposed = true;/);
  const dispatcher = worker.slice(worker.indexOf("if (MCP_PATHS.has(routePathname))"), worker.indexOf("// API endpoint"));
  const throwCount = (dispatcher.match(/throw exposedError\(/g) || []).length;
  assert.ok(throwCount >= 10, `MCP dispatch must mark its validation throws (${throwCount} found)`);
  assert.doesNotMatch(dispatcher, /throw new Error\(/, "unmarked plain Errors would mask as internal faults");
});

test("edge-cached analyses carry no per-requester share state", () => {
  // A cache hit used to replay the first requester's bearer id and expiry
  // (and a baked available:false after a storage blip) to everyone for a
  // day. The shared entry must hold analysis only; each response stores its
  // own row and attaches fresh share metadata.
  const create = worker.slice(worker.indexOf("async function createDomainReport("), worker.indexOf("function validateBatchDomains("));
  const stripAt = create.indexOf("delete storedAnalysis.id;");
  const putAt = create.indexOf("await cache.put(cacheKey");
  const storeAt = create.indexOf("const reportId = await storeReport(env, analysis);");
  const shareAt = create.indexOf("analysis.share = reportShareMetadata(reportId");
  assert.ok(stripAt > -1, "cache hits must be stripped of foreign share state");
  assert.ok(putAt > -1 && storeAt > -1 && shareAt > -1, "store-then-attach flow must exist");
  assert.ok(stripAt < storeAt, "foreign share state must be gone before a response is built");
  assert.ok(putAt < storeAt, "the shared entry must be written before this request's id exists");
});

test("a trailing slash on a routed API path answers the resource's own contract", () => {
  // POST /api/batch/ used to miss the exact-path gate and fall through to a
  // generic 404 — skipping quota and the 405 grammar every other wrong-verb
  // answer follows. Routing decisions now normalize one trailing slash.
  const handler = worker.slice(worker.indexOf("async function handleRequest(request, env) {"), worker.indexOf("function makeSpfRecordResolver("));
  assert.match(handler, /let routePathname = url\.pathname;/);
  const routeUses = (handler.match(/routePathname/g) || []).length;
  assert.ok(routeUses > 15, `machine routing must decide on the normalized path (${routeUses} uses)`);
  // Static asset serving keeps the raw spelling.
  assert.match(handler, /!url\.pathname\.startsWith\('\/api\/'\)/);
});

test("a shared wall-clock deadline converts degraded-DNS marathons into timeouts", () => {
  // The subrequest budget caps count, not duration; sequential DNS phases
  // over failing resolvers could stretch one request toward minutes. Every
  // budget must carry a deadline and queryDNS must honor it before spending
  // an attempt.
  assert.match(worker, /const ANALYSIS_WALL_MS = 20000;/);
  const budget = worker.slice(worker.indexOf("function createRequestBudget("), worker.indexOf("async function createDomainReport("));
  assert.match(budget, /outOfTime\(\) \{\s*return this\.deadline !== null && Date\.now\(\) >= this\.deadline;\s*\}/s);
  const query = worker.slice(worker.indexOf("async function queryDNS("), worker.indexOf("function dnsState("));
  const timeAt = query.indexOf("if (requestBudget.outOfTime())");
  const reserveAt = query.indexOf("if (!requestBudget.reserve('dns'))");
  assert.ok(timeAt > -1 && reserveAt > -1, "queryDNS must check both budgets");
  assert.ok(timeAt < reserveAt, "the deadline is checked before any attempt is spent");
  // Batch rows inherit the shared deadline instead of minting their own.
  const batchRow = worker.slice(worker.indexOf("const domainBudget = createRequestBudget(perDomainLimit"), worker.indexOf("try {"));
  assert.match(batchRow, /requestBudget\?\.deadline \?\? Date\.now\(\) \+ ANALYSIS_WALL_MS/);
});

test("unexpected analysis failures answer 500 while dependency outages keep 503", () => {
  // Status policy: an unexpected exception is a server fault (500); 503 is
  // reserved for the named dependency outages (rate limiter, D1 accounting,
  // report storage). The batch and SPF-inspect fallbacks once answered 503
  // for plain bugs, blurring that distinction.
  assert.match(
    worker,
    /routePathname === '\/api\/batch' && request\.method === 'POST'[\s\S]{0,600}requestErrorResponse\(err, corsHeaders, 500\)/
  );
  const inspectBlock = worker.slice(
    worker.indexOf("routePathname === '/api/spf/inspect' && request.method === 'POST'"),
    worker.indexOf("routePathname === '/api/spf/evaluate'")
  );
  assert.ok(inspectBlock.includes("requestErrorResponse(err, corsHeaders, 500)"), "inspect fallback must be a server-fault 500");
});

test("the MCP enrich tool enforces the same unique-public-IP contract as REST", () => {
  // The schema promises uniqueItems and public addresses; the dispatch must
  // reject rather than silently dedupe, matching POST /api/header/enrich.
  const branch = worker.slice(worker.indexOf("'enrich_email_hops'"), worker.indexOf("'get_email_security_report'"));
  assert.ok(branch.length > 0, "MCP enrich branch must exist");
  assert.match(branch, /ips\.length > 10 \|\| args\.ips\.some\(ip => typeof ip !== 'string' \|\| !isPublicIpAddress\(ip\)\)/);
  assert.match(branch, /ips must not contain duplicates/);
});
