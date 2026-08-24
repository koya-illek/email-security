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
  assert.match(worker, /request\.method === 'POST'.*MCP_PATHS\.has\(url\.pathname\)/);
  assert.match(worker, /await limiter\.limit\(\{ key: client \}\)/);
  assert.match(worker, /429,\s*\{ \.\.\.corsHeaders, 'Retry-After': String\(retryAfter\) \}/);
  assert.match(worker, /if \(request\.method === 'OPTIONS' && !MCP_PATHS\.has\(url\.pathname\)\)/);
  assert.match(worker, /url\.pathname === '\/api\/health' && \(request\.method === 'GET' \|\| request\.method === 'HEAD'\)/);
  assert.match(worker, /CF-Connecting-IP.*anonymous/);
});

test("unmatched machine surfaces answer with the JSON error envelope and 405 on wrong verbs", () => {
  const fallback = worker.slice(worker.indexOf("// Machine surfaces must never receive an unparseable plain-text failure."), worker.indexOf("return new Response('Not found', { status: 404, headers: securityHeaders });"));
  assert.ok(fallback.length > 0, "API fallback must exist");
  assert.match(fallback, /Method \$\{request\.method\} is not allowed for \$\{url\.pathname\}/);
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
    worker.indexOf("if (request.method === 'POST' && (POST_API_PATHS.has(url.pathname)"),
    worker.indexOf("if (MCP_PATHS.has(url.pathname))")
  );
  assert.ok(gate.length > 0, "rate-limit gate must exist");
  assert.match(gate, /POST_API_PATHS\.has\(url\.pathname\) \|\| MCP_PATHS\.has\(url\.pathname\)/);
  assert.doesNotMatch(gate, /startsWith\('\/api\/'\)/);
});

test("unexpected analysis failures answer 500 while dependency outages keep 503", () => {
  // Status policy: an unexpected exception is a server fault (500); 503 is
  // reserved for the named dependency outages (rate limiter, D1 accounting,
  // report storage). The batch and SPF-inspect fallbacks once answered 503
  // for plain bugs, blurring that distinction.
  assert.match(
    worker,
    /url\.pathname === '\/api\/batch' && request\.method === 'POST'[\s\S]{0,600}requestErrorResponse\(err, corsHeaders, 500\)/
  );
  const inspectBlock = worker.slice(
    worker.indexOf("url.pathname === '/api/spf/inspect' && request.method === 'POST'"),
    worker.indexOf("url.pathname === '/api/spf/evaluate'")
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
