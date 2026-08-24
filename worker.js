// Email Security Checker — Cloudflare Workers
// Optimized for 10ms CPU limit with parallel DoH lookups

const { spf: evaluateSpf } = require('mailauth/lib/spf');
const ipaddr = require('ipaddr.js');
const { analyzeEmailHeaders } = require('./header-analyzer');
const { redirectForRequest } = require('./redirects');
const {
  isPublicIpAddress,
  isValidDomain,
  normalizeDomain,
  quotaClientKey,
  secondsUntilDailyReset
} = require('./domain-validation');
const { runScheduledCleanup } = require('./retention');
const {
  REPORT_ID_RE,
  REPORT_RETENTION_DAYS,
  generateReportId,
  loadReport,
  reportExpiry,
  reportShareMetadata,
  storeReport
} = require('./report-store');
const { handleMcp } = require('./mcp');
const {
  assessReportAuthorisation,
  isExternalReportDestination,
  reportAuthorisationName
} = require('./dmarc-reporting');
const {
  stripSpfQualifier,
  spfTerminalTerm,
  countVisibleSpfLookups,
  hasSpfMacro,
  isDmarcVersionRecord,
  parseTagRecord,
  DMARC_POLICY_VALUES,
  effectiveDmarcPolicy
} = require('./policy-tags');
const {
  isValidMtaStsMxPattern,
  mtaStsMxMatches,
  parsePolicyLines
} = require('./mta-sts');
const { calculateScore, estimateDkimKeyBits } = require('./scoring');



const DOH_PROVIDERS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/resolve',
  'https://dns.quad9.net/dns-query'
];

const CACHE_TTL = 86400; // 24 hour edge cache
const POLICY_CACHE_TTL = 86400; // 24 hour cache for policy HTTP fetches
// Bump this key whenever report semantics change so a release cannot replay a
// 24-hour row produced by older analysis code. v11 adds external DMARC report
// authorisation evidence and RFC 9989 version-token handling.
const CACHE_VERSION = 'v11-dmarc-reporting';
const DNS_TIMEOUT_MS = 4500;
// Wall-clock ceiling for one analysis: sequential phases over slow or
// failing resolvers must degrade to inconclusive evidence instead of
// stretching the request toward minutes while technically inside the
// subrequest-count budget.
const ANALYSIS_WALL_MS = 20000;
const NORMAL_JSON_BODY_MAX_BYTES = 16 * 1024;
const HEADER_JSON_BODY_MAX_BYTES = 256 * 1024;
const MTA_STS_POLICY_MAX_BYTES = 16 * 1024;
// Workers Free allows 50 external subrequests. Keep headroom for the
// request itself and make the limit explicit in every report instead of
// allowing a batch or recursive SPF walk to fail at the platform boundary.
const REQUEST_SUBREQUEST_LIMIT = 45;
const RATE_LIMIT_RETRY_AFTER_SECONDS = 60;
const STANDARD_RATE_LIMITER_BINDING = 'STANDARD_RATE_LIMITER';
const EXPENSIVE_RATE_LIMITER_BINDING = 'EXPENSIVE_RATE_LIMITER';
// Batch rows share one platform subrequest cap, so each domain only receives
// an even slice of the 45-subrequest budget. Live verification showed four
// well-configured domains exhausted the whole budget and later rows scored
// falsely "poor"; three domains is the realistic ceiling for honest scores.
const BATCH_MAX_DOMAINS = 3;
// PTR observation carries no score weight, so it runs after scored controls
// and is capped well below its theoretical fan-out of 8 hosts x 8 addresses;
// the UI renders only the first observation, but every collected one ships
// in the stored, exported, and MCP JSON payloads.
const MAX_PTR_OBSERVATIONS = 4;
const EXPENSIVE_POST_PATHS = new Set([
  '/api/check',
  '/api/v2/domain-check',
  '/api/batch',
  '/api/header/enrich',
  '/api/spf/inspect',
  '/api/spf/evaluate',
  // Both builders run recursive DNS validation plus a full RFC 7208
  // evaluation, so they cost as much as inspect and belong behind the same
  // expensive limiter.
  '/api/records/validate',
  '/api/v2/record-build',
  '/mcp',
  '/mcp/v2'
]);
const MCP_PATHS = new Set(['/mcp', '/mcp/v2']);
// Every REST path a POST can actually reach. The rate-limit gate matches
// against this set so an unknown path answers 404 without spending any of
// the caller's daily or per-minute budget — the same ordering the report
// retrieval route applies to its own quota.
const POST_API_PATHS = new Set([
  '/api/check',
  '/api/v2/domain-check',
  '/api/header/analyze',
  '/api/v2/header-analysis',
  '/api/header/enrich',
  '/api/spf/inspect',
  '/api/spf/evaluate',
  '/api/records/validate',
  '/api/v2/record-build',
  '/api/batch'
]);

// Every routed API path with the methods it serves. Anything else claiming
// to be an API surface gets a parseable JSON failure instead of falling
// through to the plain-text static 404, and a known path hit with the wrong
// verb answers 405 with Allow like any well-behaved HTTP resource.
const API_ROUTE_METHODS = [
  ['/api/health', ['GET', 'HEAD']],
  ['/api', ['GET']],
  ['/api/', ['GET']],
  ['/api/v2', ['GET']],
  ['/api/check', ['POST']],
  ['/api/v2/domain-check', ['POST']],
  ['/api/header/analyze', ['POST']],
  ['/api/v2/header-analysis', ['POST']],
  ['/api/header/enrich', ['POST']],
  ['/api/spf/inspect', ['POST']],
  ['/api/spf/evaluate', ['POST']],
  ['/api/records/validate', ['POST']],
  ['/api/v2/record-build', ['POST']],
  ['/api/batch', ['POST']]
];

const API_SECURITY_HEADERS = {
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Robots-Tag': 'noindex, nofollow'
};

// Cloudflare Rate Limiting bindings share counters across Worker isolates within
// each serving location; these are not strict global quotas.

// Common DKIM selectors to check

function createRequestBudget(limit = REQUEST_SUBREQUEST_LIMIT, deadline = null) {
  return {
    limit,
    used: 0,
    exhausted: false,
    deadline,
    // The subrequest budget caps how many DNS calls run, not for how long;
    // on a degraded-DNS day the retry ladder could otherwise stretch one
    // request toward minutes. Once past the deadline, remaining work is
    // converted to honest timeout states by queryDNS.
    outOfTime() {
      return this.deadline !== null && Date.now() >= this.deadline;
    },
    reserve(kind = 'dns') {
      if (this.used >= this.limit) {
        this.exhausted = true;
        return false;
      }
      this.used += 1;
      return true;
    },
    snapshot() {
      return { limit: this.limit, used: this.used, remaining: Math.max(0, this.limit - this.used), exhausted: this.exhausted };
    }
  };
}

async function createDomainReport(domain, env, budget = createRequestBudget(REQUEST_SUBREQUEST_LIMIT, Date.now() + ANALYSIS_WALL_MS)) {
  const cacheKey = new Request(`https://cache.internal/${CACHE_VERSION}/${domain}`);
  const cache = caches.default;
  let analysis;
  const cached = await cache.match(cacheKey);
  if (cached) {
    const storedAnalysis = await cached.json();
    // The edge cache carries the analysis only. A previous requester's
    // bearer id, expiry, and storage outcome must never serve to someone
    // else: stripping them here also repairs entries written by older
    // revisions that embedded per-request share blocks.
    delete storedAnalysis.id;
    delete storedAnalysis.share;
    analysis = storedAnalysis;
  } else {
    analysis = await analyzeDomain(domain, budget);
    if (analysis.overall_score > 0) {
      await cache.put(cacheKey, new Response(JSON.stringify(analysis), {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': `public, max-age=${CACHE_TTL}, stale-while-revalidate=86400`
        }
      }));
    }
  }

  analysis._reportType = 'domain';
  const reportId = await storeReport(env, analysis);
  if (reportId) analysis.id = reportId;
  // Every response stores its own row, so each requester receives a share
  // link whose expiry starts now and whose availability reflects storage
  // as of this request — a D1 blip cannot pin available:false into the
  // shared cache entry for a day.
  analysis.share = reportShareMetadata(reportId, reportId ? reportExpiry() : null, Boolean(reportId));
  analysis.request_budget = budget.snapshot();
  return analysis;
}

function validateBatchDomains(domains) {
  if (!Array.isArray(domains) || !domains.length) throw new InvalidRequestError('domains must be a non-empty array');
  if (domains.length > BATCH_MAX_DOMAINS) throw new RequestTooLargeError(`A batch may contain at most ${BATCH_MAX_DOMAINS} domains.`);
  const seen = new Set();
  const accepted = [];
  const rejected = [];
  domains.forEach((value, index) => {
    const domain = normalizeDomain(value);
    if (!domain || !isValidDomain(domain)) {
      rejected.push({ index, input: String(value ?? ''), error: 'Invalid public domain' });
      return;
    }
    if (seen.has(domain)) {
      rejected.push({ index, input: String(value), domain, error: 'Duplicate domain' });
      return;
    }
    seen.add(domain);
    accepted.push(domain);
  });
  return { accepted, rejected };
}

async function createBatchReport(domains, env, requestBudget = null) {
  const validation = validateBatchDomains(domains);
  const uniqueDomains = validation.accepted;
  if (!uniqueDomains.length) throw new InvalidRequestError('At least one valid public domain is required');
  // Every analysis draws from the same platform subrequest cap, so a single
  // shared budget let early domains starve later ones. Slice the budget
  // evenly instead and carry each row's own snapshot so a truncated analysis
  // stays visible instead of reading as a legitimate low score.
  const perDomainLimit = Math.max(1, Math.floor(REQUEST_SUBREQUEST_LIMIT / uniqueDomains.length));
  // At most 3 domains run, so one parallel wave covers every row; each still
  // draws only from its own slice of the shared platform budget.
  const results = await Promise.all(uniqueDomains.map(async domain => {
    const domainBudget = createRequestBudget(perDomainLimit, requestBudget?.deadline ?? Date.now() + ANALYSIS_WALL_MS);
    try {
      const report = await analyzeDomain(domain, domainBudget);
      return {
        domain, overall_score: report.overall_score, overall_status: report.overall_status,
        spf: { status: report.spf.status, record: report.spf.record || null },
        dkim: { status: report.dkim.status, selectors: (report.dkim.selectors || []).map(selector => selector.selector) },
        dmarc: { status: report.dmarc.status, policy: report.dmarc.policy || null },
        mx: { status: report.mx.status, records: (report.mx.records || []).map(record => record.host) },
        transport: { status: report.transport?.status || 'info' },
        request_budget: domainBudget.snapshot(),
      };
    } catch (error) {
      // An analysis error is not evidence about the domain; report every
      // control as inconclusive so the row cannot read as a failing setup.
      // The fault's engine text stays in the logs — the row carries only a
      // readable instruction.
      console.error(JSON.stringify({
        level: 'error',
        message: 'Batch row analysis fault',
        domain,
        errorName: error?.name || 'Unknown',
        detail: String(error?.message || error)
      }));
      const unavailable = { status: 'info' };
      return {
        domain, overall_score: 0, overall_status: 'error', error: 'Analysis failed unexpectedly. Retry this domain as a single check.',
        spf: unavailable, dkim: unavailable, dmarc: unavailable, mx: unavailable, transport: unavailable,
        request_budget: domainBudget.snapshot(),
      };
    }
  }));
  const usedSubrequests = results.reduce((total, row) => total + (row.request_budget?.used || 0), 0);
  const report = {
    _reportType: 'batch', domains: uniqueDomains, results, created_at: new Date().toISOString(),
    source_revision: requestBudget?.sourceRevision || 'unknown',
    validation, request_budget: {
      limit: REQUEST_SUBREQUEST_LIMIT,
      per_domain_limit: perDomainLimit,
      used: usedSubrequests,
      exhausted: results.some(row => row.request_budget?.exhausted)
    }
  };
  const reportId = await storeReport(env, report);
  if (reportId) report.id = reportId;
  report.share = reportShareMetadata(reportId, reportId ? reportExpiry() : null, Boolean(reportId));
  return report;
}

const SPF_ALL_POLICIES = ['~all', '-all', '?all', '+all', ''];

async function buildEmailRecord(input, budget = null) {
  const type = String(input.type || '').toLowerCase();
  const domain = normalizeDomain(input.domain);
  if (!domain || !isValidDomain(domain)) throw exposedError('A valid domain is required');
  if (type === 'spf') {
    const mechanisms = Array.isArray(input.mechanisms) ? input.mechanisms.map(value => String(value).trim()).filter(Boolean) : [];
    // Whitespace is forgiven, but an explicit value the planner does not
    // know must fail loudly: silently substituting ~all once produced a
    // publishReady record different from the one the caller asked for.
    const requestedPolicy = typeof input.policy === 'string' ? input.policy.trim() : input.policy;
    if (requestedPolicy !== undefined && requestedPolicy !== null && !SPF_ALL_POLICIES.includes(requestedPolicy)) {
      throw exposedError(`policy must be one of ${SPF_ALL_POLICIES.filter(Boolean).join(', ')}, or an empty string to omit the all mechanism`);
    }
    const policy = SPF_ALL_POLICIES.includes(requestedPolicy) ? requestedPolicy : '~all';
    const record = ['v=spf1', ...mechanisms, policy].filter(Boolean).join(' ');
    const validation = await validateSpfRecord(domain, record, budget);
    const safetyWarnings = [];
    if (policy === '-all' && input.rolloutStage !== 'confirmed') safetyWarnings.push('Use ~all until every legitimate sender is confirmed.');
    if (!mechanisms.length && policy === '-all' && input.confirmsNoSenders !== true) safetyWarnings.push('An empty -all record rejects every sender and requires explicit confirmation that the domain sends no mail.');
    return { type, host: domain, record, validation, safetyWarnings, publishReady: validation.valid && !safetyWarnings.length };
  }
  if (type === 'dmarc') {
    const requestedPolicy = typeof input.policy === 'string' ? input.policy.trim() : input.policy;
    if (requestedPolicy !== undefined && requestedPolicy !== null && !DMARC_POLICY_VALUES.includes(requestedPolicy)) {
      throw exposedError(`policy must be one of ${DMARC_POLICY_VALUES.join(', ')}`);
    }
    const policy = DMARC_POLICY_VALUES.includes(requestedPolicy) ? requestedPolicy : 'none';
    const testing = input.testing === 'y' ? 'y' : 'n';
    const parts = ['v=DMARC1', `p=${policy}`, `t=${testing}`];
    if (input.rua) parts.push(`rua=mailto:${String(input.rua).replace(/^mailto:/i, '')}`);
    if (['none', 'quarantine', 'reject'].includes(input.subdomainPolicy)) parts.push(`sp=${input.subdomainPolicy}`);
    const alignment = input.alignment === 'strict' ? 's' : 'r';
    parts.push(`adkim=${alignment}`, `aspf=${alignment}`);
    const record = `${parts.join('; ')};`;
    const validation = await validateDmarcRecord(domain, record, budget);
    const safetyWarnings = [];
    if (!input.rua) safetyWarnings.push('Add a controlled aggregate-report mailbox before publishing.');
    if (policy !== 'none' && input.reviewedReports !== true) safetyWarnings.push('Review DMARC aggregate reports before requesting quarantine or rejection.');
    return { type, host: `_dmarc.${domain}`, record, validation, safetyWarnings, publishReady: validation.valid && !safetyWarnings.length };
  }
  throw exposedError('type must be spf or dmarc');
}

const DKIM_SELECTORS = [
  'default', 'google', 'selector1', 'selector2', 'mail', 'email',
  'dkim', 'k1', 's1', 's2', 'sig1', 'smtp', 'mandrill', 'mailgun',
  'sendgrid', 'amazonses', 'zendesk', 'freshdesk', 'cm', 'mta',
  '20230601', '20221208', '20210112', '20161025'
];

const PROVIDER_DKIM_SELECTORS = {
  'Microsoft 365': ['selector1', 'selector2'],
  'Google Workspace': ['google'],
  'Mailgun': ['smtp', 'mailgun', 'k1'],
  'SendGrid': ['s1', 's2'],
  'Amazon SES': ['amazonses'],
  'Mailchimp': ['k1', 'dkim'],
  'Zendesk': ['zendesk'],
  'Postmark': ['pm', 'pm-bounces', 'postmark'],
  'Mandrill': ['mandrill']
};

// Common email providers for SPF detection
const PROVIDERS = {
  'spf.protection.outlook.com': 'Microsoft 365',
  '_spf.google.com': 'Google Workspace',
  'mailgun.org': 'Mailgun',
  'sendgrid.net': 'SendGrid',
  'amazonses.com': 'Amazon SES',
  'servers.mcsv.net': 'Mailchimp',
  'zendesk.com': 'Zendesk',
  'freshdesk.com': 'Freshdesk',
  'spf.mtasv.net': 'Postmark',
  'include:_spf.salesforce.com': 'Salesforce',
  'spf.mandrillapp.com': 'Mandrill'
};

const MX_PROVIDERS = {
  'protection.outlook.com': 'Microsoft 365',
  'mail.protection.outlook.com': 'Microsoft 365',
  'google.com': 'Google Workspace',
  'googlemail.com': 'Google Workspace',
  'mimecast.com': 'Mimecast',
  'pphosted.com': 'Proofpoint',
  'barracudanetworks.com': 'Barracuda',
  'zoho.com': 'Zoho Mail',
  'messagingengine.com': 'Fastmail',
  'secureserver.net': 'GoDaddy',
  'emailsrvr.com': 'Rackspace',
  'mailgun.org': 'Mailgun',
  'sendgrid.net': 'SendGrid'
};

export default {
  fetch(request, env) {
    return handleRequest(request, env);
  },
  async scheduled(_controller, env) {
    await runScheduledCleanup(env);
  }
};


async function handleRequest(request, env) {
  const url = new URL(request.url);
  // Machine surfaces name exact resources; one trailing slash names the same
  // resource, so every routing decision below uses the normalized form and a
  // wrong verb still answers 405+Allow instead of slipping through to the
  // generic 404 without its quota or contract. Static asset serving keeps
  // the raw spelling.
  let routePathname = url.pathname;
  if (routePathname.startsWith('/api') && routePathname.length > 1 && routePathname.endsWith('/')) {
    routePathname = routePathname.slice(0, -1);
  }
  const requestBudget = createRequestBudget(REQUEST_SUBREQUEST_LIMIT, Date.now() + ANALYSIS_WALL_MS);
  requestBudget.sourceRevision = env?.SOURCE_REVISION || 'unknown';
  const securityHeaders = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self' https://static.cloudflareinsights.com; style-src 'self'; connect-src 'self' https://cloudflareinsights.com; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
  };

  const redirect = redirectForRequest(request, securityHeaders);
  if (redirect) return redirect;
  
  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, MCP-Protocol-Version, MCP-Session-Id',
    // Retry-After and Allow are part of the documented 429/405 contract, so
    // cross-origin browser clients must be allowed to read them.
    'Access-Control-Expose-Headers': 'MCP-Protocol-Version, X-Report-Retention-Days, Retry-After, Allow'
  };

  // MCP paths answer their own preflight with the narrower header contract
  // mcp.js advertises (POST, OPTIONS only); everything else shares the
  // global preflight below.
  if (request.method === 'OPTIONS' && !MCP_PATHS.has(routePathname)) {
    return new Response(null, { headers: { ...securityHeaders, ...corsHeaders, 'Access-Control-Max-Age': '600' } });
  }

  // HEAD shares the GET response; the runtime strips the body, so uptime
  // probes that default to HEAD see a healthy service instead of a 404.
  if (routePathname === '/api/health' && (request.method === 'GET' || request.method === 'HEAD')) {
    // CORS applies here too: uptime dashboards and browser-based monitors
    // outside this origin read the health answer just like any API client.
    return jsonResponse({ ok: true, service: 'email-security-checker', version: '2.0.0', source_revision: env.SOURCE_REVISION || 'unknown', liveness: true }, 200, { ...securityHeaders, ...corsHeaders });
  }

  if ((routePathname === '/api' || routePathname === '/api/' || routePathname === '/api/v2') && request.method === 'GET') {
    return jsonResponse({
      service: 'Email Security Checker API', version: '2.0.0', source_revision: env.SOURCE_REVISION || 'unknown', website: 'https://email.illek.ie',
      endpoints: {
        domainCheck: 'POST /api/v2/domain-check', headerAnalysis: 'POST /api/v2/header-analysis',
        batchCheck: 'POST /api/batch', spfInspect: 'POST /api/spf/inspect', spfEvaluate: 'POST /api/spf/evaluate',
        recordValidate: 'POST /api/records/validate', recordBuild: 'POST /api/v2/record-build', headerEnrich: 'POST /api/header/enrich',
        getReport: 'GET /api/reports/:id', exportReport: 'GET /api/reports/:id/export',
        legacyDomainCheck: 'POST /api/check', mcp: 'POST /mcp (also /mcp/v2)',
      },
    }, 200, { ...securityHeaders, ...corsHeaders });
  }

  if (request.method === 'POST' && (POST_API_PATHS.has(routePathname) || MCP_PATHS.has(routePathname))) {
    let retryAfter;
    // The per-minute limiter runs first: every request it rejects must not
    // also consume a non-renewable daily slot, or one burst of 429s converts
    // into an all-day lockout for whoever shares the client IP.
    try {
      retryAfter = await consumePostRateLimit(request, routePathname, env);
    } catch {
      return jsonResponse({ error: 'Rate limiting is unavailable.' }, 503, corsHeaders);
    }
    if (retryAfter !== null) {
      return jsonResponse(
        { error: 'Too many requests. Please retry later.' },
        429,
        { ...corsHeaders, 'Retry-After': String(retryAfter) }
      );
    }
    try {
      const dailySuccess = await consumeDailyRateLimit(request, env, 'post', Number(env.DAILY_POST_LIMIT) || 500);
      if (!dailySuccess) return jsonResponse({ error: 'Daily API request limit reached.' }, 429, { ...corsHeaders, 'Retry-After': String(secondsUntilDailyReset()) });
    } catch {
      // A D1 outage must not take stateless endpoints down with report
      // storage; degrade to stateless service.
    }
  }

  if (MCP_PATHS.has(routePathname)) {
    return handleMcp(request, async (tool, args) => {
      if (tool === 'analyze_email_headers') {
        if (typeof args.headers !== 'string') throw exposedError('headers must be a string');
        if (new TextEncoder().encode(args.headers).byteLength > HEADER_JSON_BODY_MAX_BYTES) throw exposedError('headers exceeds the 256 KiB limit');
        return analyzeEmailHeaders(args.headers);
      }
      if (tool === 'analyze_email_domains_batch') {
        if (!Array.isArray(args.domains)) throw exposedError('domains must be an array');
        return createBatchReport(args.domains, env, requestBudget);
      }
      if (tool === 'inspect_spf') {
        const domain = normalizeDomain(args.domain);
        if (!domain || !isValidDomain(domain)) throw exposedError('A valid public domain is required');
        const txtRecords = await queryDNS(domain, 'TXT', requestBudget);
        const spf = await analyzeSPF(domain, txtRecords, requestBudget);
        return { domain, spf, flatten: await buildSpfFlattenPreview(domain, spf.record, requestBudget), request_budget: requestBudget.snapshot() };
      }
      if (tool === 'evaluate_spf') {
        const domain = normalizeDomain(args.domain || String(args.sender || '').split('@').pop());
        if (!domain || !isValidDomain(domain) || typeof args.ip !== 'string') throw exposedError('A valid domain (or sender) and client IP are required');
        const result = await evaluateSpf({
          ip: args.ip, sender: args.sender || `postmaster@${domain}`, helo: args.helo || domain,
          mta: 'email-security-checker', resolver: args.record ? makeSpfRecordResolver(domain, args.record, requestBudget) : (name, type) => spfDnsResolver(name, type, requestBudget),
          maxResolveCount: 10, maxVoidCount: 2,
        });
        return { ...result, request_budget: requestBudget.snapshot() };
      }
      if (tool === 'validate_email_record') {
        const domain = normalizeDomain(args.domain);
        if (domain && !isValidDomain(domain)) return { valid: false, errors: ['Enter a valid domain name.'], warnings: [], request_budget: requestBudget.snapshot() };
        if (args.type === 'spf') return { ...(await validateSpfRecord(domain, args.record, requestBudget)), request_budget: requestBudget.snapshot() };
        if (args.type === 'dmarc') return { ...(await validateDmarcRecord(domain, args.record, requestBudget)), request_budget: requestBudget.snapshot() };
        throw exposedError('type must be spf or dmarc');
      }
      if (tool === 'build_email_record') return { ...(await buildEmailRecord(args, requestBudget)), request_budget: requestBudget.snapshot() };
      if (tool === 'enrich_email_hops') {
        // Same contract as POST /api/header/enrich and the tool's own
        // uniqueItems schema: reject rather than silently dedupe, so agents
        // see one behavior across both surfaces.
        if (!Array.isArray(args.ips) || args.ips.length > 10 || args.ips.some(ip => typeof ip !== 'string' || !isPublicIpAddress(ip))) {
          throw exposedError('ips must contain up to 10 unique public IPv4 or IPv6 addresses');
        }
        const cleanIps = [...new Set(args.ips)];
        if (cleanIps.length !== args.ips.length) throw exposedError('ips must not contain duplicates');
        return { enriched: await Promise.all(cleanIps.map(ip => enrichIp(ip, requestBudget))), limit: 10, request_budget: requestBudget.snapshot() };
      }
      if (tool === 'get_email_security_report') {
        const reportId = String(args.reportId || '');
        if (!REPORT_ID_RE.test(reportId)) throw exposedError('A valid 16-character report ID is required');
        const report = await loadReport(env, reportId);
        if (!report) throw exposedError('Report not found or expired');
        return report;
      }
      const cleanDomain = normalizeDomain(args.domain);
      if (!cleanDomain || !isValidDomain(cleanDomain)) throw exposedError('A valid public domain is required');
      return createDomainReport(cleanDomain, env, requestBudget);
    });
  }

  // API endpoint
  if ((routePathname === '/api/check' || routePathname === '/api/v2/domain-check') && request.method === 'POST') {
    try {
      const { domain } = await readJsonBody(request, NORMAL_JSON_BODY_MAX_BYTES);
      if (!domain) {
        return jsonResponse({ error: 'Domain required' }, 400, corsHeaders);
      }
      
      const cleanDomain = normalizeDomain(domain);
      
      if (!isValidDomain(cleanDomain)) {
        return jsonResponse({ error: 'Invalid domain' }, 400, corsHeaders);
      }

      const report = await createDomainReport(cleanDomain, env, requestBudget);
      return jsonResponse(report, 200, corsHeaders);
    } catch (err) {
      const limited = bodyLimitResponse(err, corsHeaders);
      if (limited) return limited;
      return requestErrorResponse(err, corsHeaders, 500);
    }
  }

  if ((routePathname === '/api/header/analyze' || routePathname === '/api/v2/header-analysis') && request.method === 'POST') {
    try {
      const { headers } = await readJsonBody(request, HEADER_JSON_BODY_MAX_BYTES);
      if (typeof headers !== 'string' || !headers.trim()) throw new InvalidRequestError('headers must be a non-empty string');
      return jsonResponse(analyzeEmailHeaders(headers), 200, corsHeaders);
    } catch (err) {
      const limited = bodyLimitResponse(err, corsHeaders);
      if (limited) return limited;
      return requestErrorResponse(err, corsHeaders, 400);
    }
  }

  if (routePathname === '/api/header/enrich' && request.method === 'POST') {
    try {
      const { ips } = await readJsonBody(request, NORMAL_JSON_BODY_MAX_BYTES);
      if (!Array.isArray(ips) || ips.length > 10 || ips.some(ip => typeof ip !== 'string' || !isPublicIpAddress(ip))) {
        throw new InvalidRequestError('ips must contain up to 10 unique public IPv4 or IPv6 addresses');
      }
      const cleanIps = [...new Set(ips)];
      if (cleanIps.length !== ips.length) throw new InvalidRequestError('ips must not contain duplicates');

      const enriched = await Promise.all(cleanIps.map(ip => enrichIp(ip, requestBudget)));
      return jsonResponse({ enriched, limit: 10, request_budget: requestBudget.snapshot() }, 200, corsHeaders);
    } catch (err) {
      const limited = bodyLimitResponse(err, corsHeaders);
      if (limited) return limited;
      return requestErrorResponse(err, corsHeaders, 400);
    }
  }

  if (routePathname === '/api/spf/inspect' && request.method === 'POST') {
    try {
      const { domain } = await readJsonBody(request, NORMAL_JSON_BODY_MAX_BYTES);
      const cleanDomain = normalizeDomain(domain);
      if (!cleanDomain || !isValidDomain(cleanDomain)) {
        return jsonResponse({ error: 'Valid domain required' }, 400, corsHeaders);
      }

      const txtRecords = await queryDNS(cleanDomain, 'TXT', requestBudget);
      const spf = await analyzeSPF(cleanDomain, txtRecords, requestBudget);
      const flatten = await buildSpfFlattenPreview(cleanDomain, spf.record, requestBudget);
      return jsonResponse({ domain: cleanDomain, spf, flatten, request_budget: requestBudget.snapshot() }, 200, corsHeaders);
    } catch (err) {
      const limited = bodyLimitResponse(err, corsHeaders);
      if (limited) return limited;
      // Unexpected exceptions are server faults (500); 503 is reserved for
      // the known dependency outages that name themselves elsewhere.
      return requestErrorResponse(err, corsHeaders, 500);
    }
  }

  if (routePathname === '/api/spf/evaluate' && request.method === 'POST') {
    try {
      const { ip, sender, helo, domain, record } = await readJsonBody(request, NORMAL_JSON_BODY_MAX_BYTES);
      const cleanDomain = normalizeDomain(domain || String(sender || '').split('@').pop());
      if (!cleanDomain || !isValidDomain(cleanDomain) || !ip) {
        return jsonResponse({ error: 'A valid domain (or sender) and client IP are required.' }, 400, corsHeaders);
      }
      const envelopeSender = sender || `postmaster@${cleanDomain}`;
      const result = await evaluateSpf({
        ip,
        sender: envelopeSender,
        helo: helo || cleanDomain,
        mta: 'email-security-checker',
        resolver: record ? makeSpfRecordResolver(cleanDomain, record, requestBudget) : (name, type) => spfDnsResolver(name, type, requestBudget),
        maxResolveCount: 10,
        maxVoidCount: 2
      });
      return jsonResponse({ ...result, request_budget: requestBudget.snapshot() }, 200, corsHeaders);
    } catch (err) {
      const limited = bodyLimitResponse(err, corsHeaders);
      if (limited) return limited;
      return requestErrorResponse(err, corsHeaders, 400);
    }
  }

  if (routePathname === '/api/records/validate' && request.method === 'POST') {
    try {
      const { type, domain, record } = await readJsonBody(request, NORMAL_JSON_BODY_MAX_BYTES);
      if (typeof type !== 'string' || typeof record !== 'string') throw new InvalidRequestError('type and record are required strings');
      const cleanDomain = normalizeDomain(domain);
      if (cleanDomain && !isValidDomain(cleanDomain)) {
        return jsonResponse({ valid: false, errors: ['Enter a valid domain name.'], warnings: [], request_budget: requestBudget.snapshot() }, 200, corsHeaders);
      }
      if (type === 'spf') {
        return jsonResponse({ ...(await validateSpfRecord(cleanDomain, record, requestBudget)), request_budget: requestBudget.snapshot() }, 200, corsHeaders);
      }
      if (type === 'dmarc') {
        return jsonResponse({ ...(await validateDmarcRecord(cleanDomain, record, requestBudget)), request_budget: requestBudget.snapshot() }, 200, corsHeaders);
      }
      return jsonResponse({ error: 'Record type must be spf or dmarc' }, 400, corsHeaders);
    } catch (err) {
      const limited = bodyLimitResponse(err, corsHeaders);
      if (limited) return limited;
      return requestErrorResponse(err, corsHeaders, 400);
    }
  }

  if (routePathname === '/api/v2/record-build' && request.method === 'POST') {
    try {
      return jsonResponse({ ...(await buildEmailRecord(await readJsonBody(request, NORMAL_JSON_BODY_MAX_BYTES), requestBudget)), request_budget: requestBudget.snapshot() }, 200, corsHeaders);
    } catch (err) {
      const limited = bodyLimitResponse(err, corsHeaders);
      if (limited) return limited;
      return requestErrorResponse(err, corsHeaders, 400);
    }
  }

  // GET /api/reports/:id — load a stored report. The id shape is validated
  // before any quota accounting: a malformed path can never reach storage,
  // so it must not spend one of the caller's daily retrievals. HEAD shares
  // the GET response; the runtime strips the body.
  const reportMatch = routePathname.match(/^\/api\/reports\/([A-Za-z0-9_-]+)(\/export)?$/);
  let validReportId = null;
  if ((request.method === 'GET' || request.method === 'HEAD') && reportMatch) {
    const candidate = reportMatch[1];
    if (!REPORT_ID_RE.test(candidate)) {
      return jsonResponse({ error: 'Report not found' }, 404, corsHeaders);
    }
    validReportId = candidate;
  }

  if (validReportId) {
    try {
      const success = await consumeDailyRateLimit(request, env, 'report', Number(env.REPORT_DAILY_LIMIT) || 120);
      if (!success) return jsonResponse({ error: 'Daily report retrieval limit reached.' }, 429, { ...corsHeaders, 'Retry-After': String(secondsUntilDailyReset()) });
    } catch {
      // Daily accounting is a quota guard, not the service itself; say what
      // actually happened instead of blaming rate limiting.
      return jsonResponse({ error: 'Report retrieval is temporarily unavailable. Try again shortly.' }, 503, corsHeaders);
    }
  }

  if (validReportId) {
    const reportId = validReportId;
    let stored;
    try {
      stored = await loadReport(env, reportId);
    } catch (err) {
      // A storage failure is not evidence that the report is gone; answering
      // 404 here would tell every share-link visitor their report expired.
      return requestErrorResponse(err, corsHeaders, 503);
    }
    if (!stored) {
      return jsonResponse({ error: 'Report not found or expired' }, 404, corsHeaders);
    }
    if (reportMatch[2]) {
      // Export JSON download
      const filename = stored.domain ? `email-security-${stored.domain}.json` : `email-security-${reportId}.json`;
      return new Response(JSON.stringify(stored, null, 2), {
        headers: {
          ...API_SECURITY_HEADERS,
          ...corsHeaders,
          'Content-Type': 'application/json; charset=utf-8',
          'Content-Disposition': `attachment; filename="${filename}"`,
          'Cache-Control': 'private, no-store',
          'X-Report-Retention-Days': String(REPORT_RETENTION_DAYS)
        }
      });
    }
    return jsonResponse(stored, 200, { ...corsHeaders, 'Cache-Control': 'private, no-store', 'X-Report-Retention-Days': String(REPORT_RETENTION_DAYS) });
  }

  // POST /api/batch — batch domain check
  if (routePathname === '/api/batch' && request.method === 'POST') {
    try {
      const { domains } = await readJsonBody(request, NORMAL_JSON_BODY_MAX_BYTES);
      const batchReport = await createBatchReport(domains, env, requestBudget);
      return jsonResponse(batchReport, 200, corsHeaders);
    } catch (err) {
      // Same status policy as every analysis route: validation failures keep
      // their 400/413, unexpected exceptions are a server fault (500).
      return requestErrorResponse(err, corsHeaders, 500);
    }
  }

  // Serve static assets (index.html, styles.css, app.js, robots.txt, sitemap.xml, etc.)
  // HEAD is served like GET with the body stripped by the runtime, so uptime
  // probes and link checkers do not see the site as a 404.
  if ((request.method === 'GET' || request.method === 'HEAD') && !url.pathname.startsWith('/api/')) {
    if (env.ASSETS) {
      const response = await env.ASSETS.fetch(request);
      const headers = new Headers(response.headers);
      Object.entries(securityHeaders).forEach(([key, value]) => headers.set(key, value));
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    }
    // Fallback during local dev without assets binding
    return new Response('Static assets not configured. Set [assets] in wrangler.toml.', {
      status: 503,
      headers: securityHeaders
    });
  }

  // Machine surfaces must never receive an unparseable plain-text failure.
  const apiRoute = API_ROUTE_METHODS.find(([path]) => path === routePathname);
  if (apiRoute) {
    return jsonResponse({ error: `Method ${request.method} is not allowed for ${routePathname}` }, 405, { ...corsHeaders, Allow: apiRoute[1].join(', ') });
  }
  // Report routes are dynamic, so they sit outside the static method table;
  // wrong verbs still answer 405 with Allow like every other resource.
  if (/^\/api\/reports\/[A-Za-z0-9_-]+(\/export)?$/.test(routePathname) && request.method !== 'GET' && request.method !== 'HEAD') {
    return jsonResponse({ error: `Method ${request.method} is not allowed for ${routePathname}` }, 405, { ...corsHeaders, Allow: 'GET, HEAD' });
  }
  if (routePathname.startsWith('/api/') || MCP_PATHS.has(routePathname)) {
    return jsonResponse({ error: 'Not found' }, 404, corsHeaders);
  }

  return new Response('Not found', { status: 404, headers: securityHeaders });
}

function makeSpfRecordResolver(domain, record, budget = null) {
  const normalized = normalizeDomain(domain);
  return async (name, type) => {
    if (type === 'TXT' && normalizeDomain(name) === normalized) return [[String(record)]];
    return spfDnsResolver(name, type, budget);
  };
}

function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...API_SECURITY_HEADERS, 'Content-Type': 'application/json', ...headers }
  });
}

class RequestBodyTooLargeError extends Error {
  constructor(maxBytes, label = 'Request body') {
    super(`${label} exceeds the ${maxBytes / 1024} KiB limit.`);
    this.name = 'RequestBodyTooLargeError';
  }
}

class RequestTooLargeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RequestTooLargeError';
    this.status = 413;
  }
}

class InvalidRequestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidRequestError';
    this.status = 400;
  }
}

// Marks a thrown error's message as intentional client-facing copy so
// requestErrorResponse echoes it verbatim; unmarked errors are treated as
// unexpected faults and answered with an opaque reference instead.
function exposedError(message) {
  const error = new Error(message);
  error.exposed = true;
  return error;
}

function requestErrorResponse(error, corsHeaders, fallbackStatus) {
  const limited = bodyLimitResponse(error, corsHeaders);
  if (limited) return limited;
  // Errors crafted for the client carry intentional copy (their own status
  // or an exposed marker). Anything else is an unexpected fault: its engine
  // text must not reach the wire, and it is a server fault (500) even on a
  // route whose validation failures answer 400.
  const intentional = error?.exposed === true || Number.isInteger(error?.status);
  if (!intentional) {
    const reference = [...crypto.getRandomValues(new Uint8Array(4))].map(byte => byte.toString(16).padStart(2, '0')).join('');
    console.error(JSON.stringify({
      level: 'error',
      message: 'Unhandled request fault',
      reference,
      errorName: error?.name || 'Unknown',
      detail: String(error?.message || error)
    }));
    return jsonResponse({ error: `Internal error (${reference}).` }, 500, corsHeaders);
  }
  const status = Number.isInteger(error?.status) ? error.status : fallbackStatus;
  return jsonResponse({ error: error?.message || 'Request failed' }, status, corsHeaders);
}

async function readJsonBody(request, maxBytes) {
  const bytes = await readBodyBytes(request.body, maxBytes);
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new InvalidRequestError('Request body must contain valid JSON.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new InvalidRequestError('Request body must be a JSON object.');
  }
  return parsed;
}

async function readBodyBytes(body, maxBytes, signal, label = 'Request body') {
  if (!body) return new Uint8Array();

  const reader = body.getReader();
  const chunks = [];
  let totalBytes = 0;
  const onAbort = () => {
    reader.cancel(signal.reason).catch(() => {});
  };

  if (signal) {
    if (signal.aborted) throw signal.reason;
    signal.addEventListener('abort', onAbort, { once: true });
  }

  try {
    while (true) {
      if (signal?.aborted) throw signal.reason;
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        throw new RequestBodyTooLargeError(maxBytes, label);
      }
      chunks.push(value);
    }
  } finally {
    signal?.removeEventListener('abort', onAbort);
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function bodyLimitResponse(error, corsHeaders) {
  return error instanceof RequestBodyTooLargeError
    ? jsonResponse({ error: error.message }, 413, corsHeaders)
    : null;
}



async function consumePostRateLimit(request, pathname, env) {
  const bindingName = EXPENSIVE_POST_PATHS.has(pathname)
    ? EXPENSIVE_RATE_LIMITER_BINDING
    : STANDARD_RATE_LIMITER_BINDING;
  const limiter = env?.[bindingName];
  if (!limiter || typeof limiter.limit !== 'function') {
    throw new Error(`${bindingName} binding is not configured`);
  }

  const client = quotaClientKey(request.headers.get('CF-Connecting-IP') || 'anonymous');
  const { success } = await limiter.limit({ key: client });
  return success ? null : RATE_LIMIT_RETRY_AFTER_SECONDS;
}

async function consumeDailyRateLimit(request, env, scope, limit) {
  if (!env?.DB || typeof env.DB.prepare !== 'function') throw new Error('D1 rate limiting is unavailable');
  const date = new Date().toISOString().slice(0, 10);
  const ip = quotaClientKey(request.headers.get('CF-Connecting-IP') || 'anonymous');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${date}:${ip}`));
  const hash = [...new Uint8Array(digest)].slice(0, 16).map(byte => byte.toString(16).padStart(2, '0')).join('');
  const now = new Date().toISOString();
  const expires = new Date(`${date}T00:00:00.000Z`);
  expires.setUTCDate(expires.getUTCDate() + 3);
  const row = await env.DB.prepare(`
    INSERT INTO reports (id, type, domain, report_json, created_at, expires_at)
    VALUES (?, 'rate_limit', NULL, '1', ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      report_json = CAST(CAST(report_json AS INTEGER) + 1 AS TEXT),
      expires_at = excluded.expires_at
    RETURNING CAST(report_json AS INTEGER) AS request_count
  `).bind(`rate:${scope}:${date}:${hash}`, now, expires.toISOString()).first();
  return (row?.request_count || 1) <= Math.max(1, Math.min(Number(limit) || 1, 5000));
}


function parseSpfRecord(value) {
  const record = String(value || '').trim().replace(/\s+/g, ' ');
  const tokens = record.split(' ').filter(Boolean);
  return {
    record,
    tokens,
    terms: tokens.slice(1),
    hasVersion: /^v=spf1$/i.test(tokens[0] || '')
  };
}

function findSpfRecord(records) {
  return (records || []).filter(record => /^\s*v=spf1(?:\s|$)/i.test(String(record || '')));
}

async function validateSpfRecord(domain, value, budget = null) {
  const parsed = parseSpfRecord(value);
  const { record, tokens } = parsed;
  const errors = [];
  const warnings = [];

  if (!parsed.hasVersion) errors.push('SPF record must begin with v=spf1 (case-insensitive).');
  if (tokens.filter(token => /^v=spf1$/i.test(token)).length !== 1) {
    errors.push('SPF record must contain exactly one v=spf1 version term.');
  }
  if (record.length > 4096) errors.push('SPF record is too large to publish safely.');
  else if (record.length > 450) warnings.push('Record is long and must be split into quoted TXT chunks by the DNS provider.');

  const terms = tokens.slice(1);
  let allIndex = -1;
  terms.forEach((token, index) => {
    const clean = stripSpfQualifier(token);
    if (clean === 'all') {
      if (allIndex !== -1) errors.push('SPF record contains more than one all mechanism.');
      allIndex = index;
      return;
    }
    if (clean.startsWith('ip4:')) {
      if (!isValidIpv4Cidr(clean.slice(4))) errors.push(`Invalid IPv4 mechanism: ${token}`);
      return;
    }
    if (clean.startsWith('ip6:')) {
      if (!isValidIpv6Cidr(clean.slice(4))) errors.push(`Invalid IPv6 mechanism: ${token}`);
      return;
    }
    if (clean.startsWith('include:')) {
      if (!isValidSpfDomainSpec(clean.slice(8))) errors.push(`Invalid include mechanism: ${token}`);
      return;
    }
    if (
      clean === 'a' || clean === 'mx' ||
      /^(?:a|mx)(?::[^/]+)?(?:\/\d{1,3})?(?:\/\/\d{1,3})?$/i.test(clean)
    ) {
      const cidrMatch = clean.match(/(?:^|[^/])\/(\d{1,3})(?:\/\/(\d{1,3}))?$/);
      const dualMatch = clean.match(/\/\/(\d{1,3})$/);
      const cidr4 = cidrMatch ? Number(cidrMatch[1]) : null;
      const cidr6 = dualMatch ? Number(dualMatch[1]) : null;
      if (cidr4 !== null && cidr4 > 32) errors.push(`IPv4 CIDR length exceeds 32: ${token}`);
      if (cidr6 !== null && cidr6 > 128) errors.push(`IPv6 CIDR length exceeds 128: ${token}`);
      return;
    }
    if (clean.startsWith('exists:')) {
      if (!isValidSpfDomainSpec(clean.slice(7))) errors.push(`Invalid exists mechanism: ${token}`);
      return;
    }
    if (clean === 'ptr' || clean.startsWith('ptr:')) {
      warnings.push('The ptr mechanism is valid but discouraged and should be replaced.');
      return;
    }
    if (clean.startsWith('redirect=') || clean.startsWith('exp=')) {
      if (!isValidSpfDomainSpec(clean.slice(clean.indexOf('=') + 1))) errors.push(`Invalid SPF modifier: ${token}`);
      return;
    }
    if (/^[a-z][a-z0-9_.-]*=[^\s]+$/i.test(clean)) {
      warnings.push(`Unknown SPF modifier retained: ${token}`);
      return;
    }
    errors.push(`Unsupported or malformed SPF term: ${token}`);
  });

  if (allIndex !== -1 && allIndex !== terms.length - 1) {
    warnings.push('Terms after all are unreachable during SPF evaluation and should be removed.');
  }
  if (allIndex === -1 && !terms.some(token => stripSpfQualifier(token).startsWith('redirect='))) {
    warnings.push('SPF record has no all mechanism or redirect modifier.');
  }

  const recursive = domain && parsed.hasVersion
    ? await countSpfDnsLookupsRecursive(domain, record, new Set(), 0, null, budget)
    : { count: countVisibleSpfLookups(terms), voidLookups: [], unknownLookups: [], macroLookups: [], truncated: false };
  if (recursive.count > 10) errors.push(`SPF evaluation requires ${recursive.count} DNS lookups; the maximum is 10.`);
  if (recursive.voidLookups?.length > 2) errors.push(`SPF evaluation produces ${recursive.voidLookups.length} void lookups; no more than 2 are allowed.`);
  else if (recursive.voidLookups?.length) warnings.push(`No SPF record was found for: ${recursive.voidLookups.join(', ')}`);
  if (recursive.truncated) errors.push('Recursive SPF validation could not complete within safety limits.');

  let evaluator = null;
  if (parsed.hasVersion) {
    try {
      evaluator = await evaluateSpf({
        ip: '192.0.2.1',
        sender: `postmaster@${domain || 'fixture.example'}`,
        helo: domain || 'fixture.example',
        mta: 'email-security-checker',
        resolver: makeSpfRecordResolver(domain || 'fixture.example', record, budget),
        maxResolveCount: 10,
        maxVoidCount: 2
      });
      if (evaluator.status?.result === 'permerror') {
        errors.push(`RFC 7208 evaluator: ${evaluator.status.comment || 'permanent policy error'}`);
      } else if (evaluator.status?.result === 'temperror') {
        warnings.push(`RFC 7208 evaluation was temporarily inconclusive: ${evaluator.status.comment || 'DNS error'}`);
      }
    } catch (err) {
      warnings.push(`RFC 7208 evaluator could not complete: ${err.message}`);
    }
  }

  return {
    valid: errors.length === 0,
    record,
    errors: [...new Set(errors)],
    warnings: [...new Set(warnings)],
    lookupCount: recursive.count,
    voidLookups: recursive.voidLookups || [],
    characterCount: record.length,
    evaluator: evaluator ? {
      result: evaluator.status?.result,
      lookups: evaluator.lookups
    } : null
  };
}

async function validateDmarcRecord(domain, value, budget = null) {
  const record = String(value || '').trim();
  const errors = [];
  const warnings = [];
  const parts = record.split(';').map(part => part.trim()).filter(Boolean);
  const pairs = [];
  const seen = new Set();

  parts.forEach(part => {
    const index = part.indexOf('=');
    if (index < 1) {
      errors.push(`Malformed DMARC term: ${part}`);
      return;
    }
    const key = part.slice(0, index).trim().toLowerCase();
    const val = part.slice(index + 1).trim();
    if (seen.has(key)) errors.push(`DMARC tag ${key}= appears more than once.`);
    seen.add(key);
    pairs.push([key, val]);
  });
  const tags = Object.fromEntries(pairs);

  if (pairs[0]?.[0] !== 'v' || pairs[0]?.[1] !== 'DMARC1') {
    errors.push('DMARC record must begin with v=DMARC1.');
  }
  if (!['none', 'quarantine', 'reject'].includes((tags.p || '').toLowerCase())) {
    errors.push('DMARC p= must be none, quarantine, or reject.');
  }
  if (tags.sp && !['none', 'quarantine', 'reject'].includes(tags.sp.toLowerCase())) {
    errors.push('DMARC sp= must be none, quarantine, or reject.');
  }
  if (tags.pct) warnings.push('pct= is a historic RFC 7489 tag and is ignored by RFC 9989 receivers; use t=y for testing.');
  if (tags.t && !['y', 'n'].includes(tags.t.toLowerCase())) errors.push('DMARC t= must be y or n.');
  if (tags.psd && !['y', 'n', 'u'].includes(tags.psd.toLowerCase())) errors.push('DMARC psd= must be y, n, or u.');
  ['np', 'sp'].forEach(key => {
    if (tags[key] && !['none', 'quarantine', 'reject'].includes(tags[key].toLowerCase())) {
      errors.push(`DMARC ${key}= must be none, quarantine, or reject.`);
    }
  });
  ['adkim', 'aspf'].forEach(key => {
    if (tags[key] && !['r', 's'].includes(tags[key].toLowerCase())) {
      errors.push(`DMARC ${key}= must be r or s.`);
    }
  });
  ['rua', 'ruf'].forEach(key => {
    if (!tags[key]) return;
    const destinations = tags[key].split(',').map(item => item.trim());
    if (!destinations.length || destinations.some(item => !isValidDmarcReportUri(item))) {
      errors.push(`DMARC ${key}= must contain valid mailto reporting addresses.`);
    }
  });
  if (tags.fo) {
    const options = tags.fo.toLowerCase().split(':');
    if (!options.length || options.some(option => !['0', '1', 'd', 's'].includes(option)) || new Set(options).size !== options.length) {
      errors.push('DMARC fo= must contain unique values from 0, 1, d, and s separated by colons.');
    }
  }
  if (!tags.rua) warnings.push('No aggregate reporting address is configured.');
  if (tags.p === 'none') warnings.push('DMARC is in monitoring mode and does not request enforcement.');
  if (record.length > 2048) errors.push('DMARC record is too large to publish safely.');
  if (domain && tags.rua && tags.rua.split(',').every(item => isValidDmarcReportUri(item.trim()))) {
    const external = parseMailtoList(tags.rua).filter(address => isExternalReportDestination(domain, address));
    for (const address of external) {
      const query = reportAuthorisationName(domain, address);
      const authRecords = await queryDNS(query, 'TXT', budget);
      const authorisation = assessReportAuthorisation(domain, address, authRecords);
      if (authorisation.status === 'unauthorised') warnings.push(`RFC 9990 authorisation was not found at ${authorisation.query}.`);
      if (authorisation.status === 'unknown') warnings.push(`RFC 9990 authorisation at ${authorisation.query} is inconclusive because DNS returned ${authorisation.dnsStatus}.`);
    }
  }

  return {
    valid: errors.length === 0,
    record,
    errors: [...new Set(errors)],
    warnings: [...new Set(warnings)],
    characterCount: record.length
  };
}

function isValidIpv4Cidr(value) {
  const parts = String(value).split('/');
  if (parts.length > 2) return false;
  const [ip, prefix] = parts;
  if (!isPublicOrReservedIpv4(ip)) return false;
  return prefix === undefined || (/^\d{1,2}$/.test(prefix) && Number(prefix) >= 0 && Number(prefix) <= 32);
}

function isPublicOrReservedIpv4(ip) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return false;
  return ip.split('.').every(part => Number(part) >= 0 && Number(part) <= 255);
}

function isValidIpv6Cidr(value) {
  const slash = String(value).lastIndexOf('/');
  const address = slash === -1 ? String(value) : String(value).slice(0, slash);
  const prefix = slash === -1 ? null : String(value).slice(slash + 1);
  if (prefix !== null && (!/^\d{1,3}$/.test(prefix) || Number(prefix) > 128)) return false;
  try {
    return ipaddr.parse(address).kind() === 'ipv6';
  } catch {
    return false;
  }
}

function isValidSpfDomainSpec(value) {
  if (!value || /\s/.test(value)) return false;
  if (value.includes('%')) return /^[a-z0-9_.%{}+/_=-]+$/i.test(value);
  return /^(?=.{1,253}\.?$)[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?\.?$/i.test(value);
}

function isValidDmarcReportUri(value) {
  return /^mailto:[^@\s,]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?:!\d+[kmgt]?)?$/i.test(value);
}


function reverseDnsName(ip) {
  const parsed = ipaddr.parse(ip);
  if (parsed.kind() === 'ipv4') return parsed.toString().split('.').reverse().join('.') + '.in-addr.arpa';
  return parsed.toNormalizedString().replace(/:/g, '').split('').reverse().join('.') + '.ip6.arpa';
}

async function enrichIp(ip, budget = null) {
  // Cache on the canonical address: 2001:DB8::1, 2001:db8::1, and
  // 2001:0db8:0::1 are one host and must share one PTR entry. Callers keep
  // their own spelling echoed back so hop matching by exact string still
  // works in the frontend.
  const cacheKey = new Request(`https://header-cache.internal/ip/${quotaClientKey(ip)}`);
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) {
    const cachedResult = await cached.json();
    return { ...cachedResult, ip };
  }

  const ptrName = reverseDnsName(ip);
  const ptrRecords = await queryDNS(ptrName, 'PTR', budget);
  const dns = dnsState(ptrRecords);
  // Only authoritative outcomes may be cached; a SERVFAIL or timeout must not
  // spend a day presenting "no PTR" for a host whose answer was never read.
  // The cached body omits the caller's own spelling of the address.
  const definitive = ['ok', 'nodata', 'nxdomain'].includes(dns.status);
  const result = {
    ptr: definitive ? (ptrRecords[0] ? ptrRecords[0].replace(/\.$/, '') : null) : null,
    checkedAt: new Date().toISOString()
  };
  if (!definitive) {
    result.dns = dns;
    return { ...result, ip };
  }

  await cache.put(cacheKey, new Response(JSON.stringify(result), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=86400, stale-while-revalidate=86400'
    }
  }));

  return { ...result, ip };
}

async function analyzeDomain(domain, budget = createRequestBudget(REQUEST_SUBREQUEST_LIMIT, Date.now() + ANALYSIS_WALL_MS)) {
  // Run all DNS queries in parallel
  const [
    spfRecords,
    dmarcDiscovery,
    mxRecords,
    caaRecords,
    mtaStsRecords,
    tlsRptRecords
  ] = await Promise.all([
    queryDNS(domain, 'TXT', budget),
    discoverDmarcPolicy(domain, budget),
    queryDNS(domain, 'MX', budget),
    queryDNS(domain, 'CAA', budget),
    queryDNS(`_mta-sts.${domain}`, 'TXT', budget),
    queryDNS(`_smtp._tls.${domain}`, 'TXT', budget)
  ]);

  // Scored controls claim the shared budget first: SPF recursion, then the
  // single MTA-STS policy fetch, then DKIM selector discovery. The policy
  // fetch runs before the wide selector fan-out because a one-request reserve
  // loses that race and transport evidence would read as inconclusive. DMARC
  // external-report authorisation and PTR are unscored supplementary
  // observations and run last on whatever remains; scheduling them first
  // starved DKIM discovery entirely on multi-MX domains.
  const spf = await analyzeSPF(domain, spfRecords, budget);
  const dmarc = analyzeDMARC(dmarcDiscovery.records, dmarcDiscovery);
  const mtaStsPolicy = mtaStsRecords.some(r => /^\s*v=STSv1(?:\s*;|\s*$)/i.test(r))
    ? await fetchMtaStsPolicy(domain, budget)
    : null;
  const dkimResults = await checkDKIMSelectors(domain, spf.providers, mxRecords, budget);
  await addDmarcReportAuthorisation(dmarc, budget);
  const ptrResult = await checkPTR(domain, mxRecords, budget);

  const dkim = analyzeDKIM(dkimResults);
  const mx = analyzeMX(mxRecords);
  const caa = analyzeCAA(caaRecords);
  const ptr = analyzePTR(ptrResult, mxRecords);
  const transport = analyzeTransportSecurity(mtaStsRecords, tlsRptRecords, mtaStsPolicy, mx.records || []);

  // Calculate score
  const { score, status, confidence, unknown } = calculateScore(spf, dkim, dmarc, mx, caa, transport, ptr);
  const timestamp = new Date().toISOString();

  return {
    domain,
    timestamp,
    source_revision: budget.sourceRevision || 'unknown',
    spf,
    dkim,
    dmarc,
    mx,
    caa,
    ptr,
    transport,
    dns: {
      spf: dnsState(spfRecords),
      dmarc: dmarcDiscovery.dns,
      mx: dnsState(mxRecords),
      caa: dnsState(caaRecords),
      mtaSts: dnsState(mtaStsRecords),
      tlsRpt: dnsState(tlsRptRecords)
    },
    provenance: {
      generatedAt: timestamp,
      sourceRevision: budget.sourceRevision || 'unknown',
      dnsProviders: DOH_PROVIDERS,
      observation: 'Public DNS and policy observations at lookup time. Unknown or provider-error states are not confirmed absence.'
    },
    score_confidence: confidence,
    unknown_controls: unknown,
    request_budget: budget.snapshot(),
    overall_score: score,
    overall_status: status
  };
}

async function addDmarcReportAuthorisation(dmarc, budget = null) {
  const policyDomain = dmarc.policyDomain;
  const external = policyDomain
    ? (dmarc.rua || []).filter(address => isExternalReportDestination(policyDomain, address))
    : [];
  const observations = [];
  for (const address of external) {
    const query = reportAuthorisationName(policyDomain, address);
    const records = await queryDNS(query, 'TXT', budget);
    observations.push(assessReportAuthorisation(policyDomain, address, records));
  }
  dmarc.reportingAuthorisation = observations;
  for (const observation of observations) {
    if (observation.status === 'authorised') {
      dmarc.checks.push({
        status: 'pass',
        title: 'External aggregate reporting authorised',
        detail: `${observation.destination} authorises reports requested by ${policyDomain}.`,
        recommendation: ''
      });
    } else if (observation.status === 'unauthorised') {
      dmarc.checks.push({
        status: 'warn',
        title: 'External aggregate reporting is not authorised',
        detail: `No RFC 9990 authorisation was found at ${observation.query}; receivers must ignore ${observation.address}.`,
        recommendation: `Ask ${observation.destination} to publish the authorisation record, or use a reporting address within the policy domain's organisation.`
      });
    } else {
      dmarc.checks.push({
        status: 'info',
        title: 'External aggregate reporting authorisation is inconclusive',
        detail: `DNS returned ${observation.dnsStatus} for ${observation.query}.`,
        recommendation: 'Retry before changing the DMARC reporting destination.'
      });
    }
  }
  return dmarc;
}

async function discoverDmarcPolicy(domain, budget = null) {
  const labels = domain.split('.');
  const queries = [];
  const offsets = labels.length > 8
    ? [0, ...Array.from({ length: 7 }, (_, index) => labels.length - 7 + index)]
    : Array.from({ length: labels.length - 1 }, (_, index) => index);
  const found = [];
  // RFC 9989 always checks the Author Domain. For names longer than eight
  // labels it then skips directly to the final seven tree-walk candidates.
  for (const offset of [...new Set(offsets)]) {
    const candidate = labels.slice(offset).join('.');
    const records = await queryDNS(`_dmarc.${candidate}`, 'TXT', budget);
    queries.push({ domain: candidate, dns: dnsState(records) });
    if (records.dnsStatus === 'servfail' || records.dnsStatus === 'timeout' || records.dnsStatus === 'error') {
      return { records, policyDomain: null, inherited: false, queries, dns: dnsState(records) };
    }
    const matching = records.filter(isDmarcVersionRecord);
    // Multiple matching records are discarded at this node by RFC 9989.
    if (matching.length === 1) {
      found.push({ domain: candidate, records, tags: parseTagRecord(matching[0]), dns: dnsState(records) });
      if (offset === 0) {
        return { records, policyDomain: candidate, inherited: false, queries, dns: dnsState(records) };
      }
      if (['y', 'n'].includes(found.at(-1).tags.psd)) break;
    }
  }
  if (found.length) {
    const highest = found.at(-1);
    let selected = highest;
    if (highest.tags.psd === 'y') {
      const psdOffset = labels.length - highest.domain.split('.').length;
      const organisationalDomain = labels.slice(Math.max(0, psdOffset - 1)).join('.');
      selected = found.find(item => item.domain === organisationalDomain) || highest;
    }
    return {
      records: selected.records,
      policyDomain: selected.domain,
      inherited: selected.domain !== domain,
      queries,
      dns: selected.dns
    };
  }
  const finalDns = queries.at(-1)?.dns || { status: 'nodata', rcode: 0, provider: null, error: null };
  return { records: [], policyDomain: null, inherited: false, queries, dns: finalDns };
}

async function queryDNS(name, type, budget = null) {
  const requestBudget = budget || createRequestBudget(REQUEST_SUBREQUEST_LIMIT, Date.now() + ANALYSIS_WALL_MS);
  let last = { status: 'error', rcode: null, provider: null, error: 'No DNS provider responded' };
  for (const provider of DOH_PROVIDERS) {
    if (requestBudget.outOfTime()) {
      last = {
        status: 'timeout',
        rcode: null,
        provider: null,
        error: `The analysis time budget was exceeded before ${name} ${type} could be resolved`
      };
      break;
    }
    if (!requestBudget.reserve('dns')) {
      last = { status: 'budget_exceeded', rcode: null, provider: null, error: `Request DNS subrequest budget of ${requestBudget.limit} was exhausted` };
      break;
    }
    const dohUrl = `${provider}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);
    try {
      const response = await fetch(dohUrl, {
        headers: { Accept: 'application/dns-json' },
        signal: controller.signal,
        cf: { cacheTtl: 3600, cacheEverything: true }
      });
      if (!response.ok) {
        last = { status: 'error', rcode: null, provider, error: `DNS-over-HTTPS HTTP ${response.status}` };
        continue;
      }
      const data = await response.json();
      const rcode = Number(data.Status);
      const status = rcode === 0
        ? ((data.Answer || []).length ? 'ok' : 'nodata')
        : rcode === 3 ? 'nxdomain'
        : rcode === 2 ? 'servfail'
        : 'error';
      const answers = (data.Answer || []).map(record => ({
        type: Number(record.type),
        ttl: Number(record.TTL || 0),
        data: String(record.data || '')
      }));
      const wantedType = { A: 1, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 }[type];
      const values = answers
        .filter(answer => answer.type === wantedType || (type === 'TXT' && answer.type === 5))
        .map(answer => answer.type === 16
          ? answer.data.replace(/^"|"$/g, '').replace(/"\s*"/g, '')
          : answer.data);
      Object.defineProperties(values, {
        dnsStatus: { value: status, enumerable: false },
        rcode: { value: rcode, enumerable: false },
        provider: { value: provider, enumerable: false },
        answers: { value: answers, enumerable: false }
      });
      // NXDOMAIN and NOERROR/NODATA are authoritative outcomes. Only retry
      // transient resolver failures such as SERVFAIL, timeout and HTTP errors.
      if (status !== 'servfail' && status !== 'error') return values;
      last = { status, rcode, provider, error: status === 'servfail' ? 'DNS server failure' : `DNS RCODE ${rcode}` };
    } catch (err) {
      last = {
        status: err?.name === 'AbortError' ? 'timeout' : 'error',
        rcode: null,
        provider,
        error: err?.name === 'AbortError' ? `DNS query timed out after ${DNS_TIMEOUT_MS}ms` : String(err?.message || err)
      };
    } finally {
      clearTimeout(timer);
    }
  }
  const values = [];
  Object.defineProperties(values, {
    dnsStatus: { value: last.status, enumerable: false },
    rcode: { value: last.rcode, enumerable: false },
    provider: { value: last.provider, enumerable: false },
    dnsError: { value: last.error, enumerable: false },
    answers: { value: [], enumerable: false }
  });
  return values;
}

function dnsState(records) {
  return {
    status: records?.dnsStatus || (records?.length ? 'ok' : 'nodata'),
    rcode: records?.rcode ?? null,
    provider: records?.provider || null,
    error: records?.dnsError || null
  };
}

async function spfDnsResolver(name, type, budget = null) {
  const records = await queryDNS(name, type, budget);
  const status = records.dnsStatus;
  if (status === 'nxdomain' || status === 'nodata') {
    // Coded DNS diagnostics are intentional evidence for callers evaluating
    // a policy; mark them exposed so the fault path never masks them.
    const err = exposedError(status === 'nxdomain' ? 'DNS name does not exist' : 'No records of requested type');
    err.code = status === 'nxdomain' ? 'ENOTFOUND' : 'ENODATA';
    throw err;
  }
  if (status === 'timeout' || status === 'servfail' || status === 'error' || status === 'budget_exceeded') {
    const err = exposedError(records.dnsError || `DNS ${status}`);
    err.code = status === 'timeout' ? 'ETIMEOUT' : status === 'servfail' ? 'ESERVFAIL' : status === 'budget_exceeded' ? 'EBUDGET' : 'EREFUSED';
    throw err;
  }
  if (type === 'TXT') return records.map(value => [value]);
  if (type === 'MX') return records.map(value => {
    const [priority, ...exchange] = value.trim().split(/\s+/);
    return { priority: Number(priority), exchange: exchange.join(' ').replace(/\.$/, '') };
  });
  return records.map(value => String(value).replace(/\.$/, ''));
}

async function checkDKIMSelectors(domain, providers = [], mxRecords = [], budget = null) {
  const inferred = new Set();
  providers.forEach(provider => (PROVIDER_DKIM_SELECTORS[provider] || []).forEach(selector => inferred.add(selector)));

  const mxText = mxRecords.join(' ').toLowerCase();
  if (mxText.includes('protection.outlook.com')) ['selector1', 'selector2'].forEach(selector => inferred.add(selector));
  if (mxText.includes('google.com') || mxText.includes('googlemail.com')) inferred.add('google');

  // Probe the whole bounded catalogue, inferred selectors first. Truncating
  // the scan below the catalogue size silently excluded its date-based
  // entries, which is exactly where Google publishes rotated selectors.
  const selectors = [...new Set([...inferred, ...DKIM_SELECTORS])];
  const lookupState = { transient: false, authoritative: false };
  const results = await Promise.all(
    selectors.map(async selector => {
      const resolved = await resolveDkimRecord(`${selector}._domainkey.${domain}`, 0, null, budget, lookupState);
      return resolved ? { selector, record: resolved.record, cname: resolved.cname } : null;
    })
  );
  const output = results.filter(Boolean);
  Object.defineProperties(output, {
    dnsStatus: { value: output.length ? (lookupState.transient ? 'partial' : 'ok') : lookupState.transient ? 'unknown' : 'nodata', enumerable: false, configurable: true },
    budget: { value: budget || null, enumerable: false }
  });
  if (budget?.exhausted) Object.defineProperty(output, 'dnsStatus', { value: 'budget_exceeded', enumerable: false });
  return output;
}

async function resolveDkimRecord(name, depth = 0, firstCname = null, budget = null, lookupState = null) {
  if (depth > 4) return null;

  const records = await queryDNS(name, 'TXT', budget);
  if (lookupState) {
    if (['ok', 'nodata', 'nxdomain'].includes(records.dnsStatus)) lookupState.authoritative = true;
    else lookupState.transient = true;
  }
  const record = records.find(value =>
    /(?:^|;)\s*v=DKIM1(?:;|$)/i.test(value) ||
    /(?:^|;)\s*(?:k|p)\s*=/i.test(value)
  );
  if (record) return { record, cname: firstCname };

  // Cloudflare DoH can return a CNAME target without chasing it for TXT data.
  const cname = records.find(value =>
    /^[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?\.?$/i.test(value) &&
    value.includes('.')
  );
  if (!cname) return null;

  const target = cname.replace(/\.$/, '');
  return resolveDkimRecord(target, depth + 1, firstCname || target, budget, lookupState);
}

async function checkPTR(domain, mxRecords = [], budget = null) {
  if (mxRecords?.dnsStatus && !['ok', 'nodata', 'nxdomain'].includes(mxRecords.dnsStatus)) {
    return { checked: false, unknown: true, dnsStatus: mxRecords.dnsStatus, reason: `MX lookup was ${mxRecords.dnsStatus}; inbound PTR evidence is inconclusive.` };
  }
  if (!mxRecords.length) return { checked: false, reason: 'No MX records. SMTP fallback may use A or AAAA records; no inbound MX host was available for PTR observation.' };
  if (mxRecords.some(value => /^0\s+\.$/i.test(value.trim()))) {
    return { checked: false, notApplicable: true, reason: 'Null MX explicitly declares that this domain does not accept email.' };
  }

  const observations = [];
  const hosts = [...new Set(mxRecords.map(value => String(value).trim().split(/\s+/).slice(1).join(' ').replace(/\.$/, '')).filter(Boolean))].slice(0, 8);
  for (const mxHost of hosts) {
    if (observations.length >= MAX_PTR_OBSERVATIONS) break;
    const [aRecords, aaaaRecords] = await Promise.all([
      queryDNS(mxHost, 'A', budget),
      queryDNS(mxHost, 'AAAA', budget)
    ]);
    const addresses = [...aRecords, ...aaaaRecords].filter(ip => ipaddr.isValid(ip)).slice(0, 8);
    // Forward confirmation compares addresses, not spellings: two lookups can
    // return equivalent IPv6 text in different canonical forms.
    const normalizedAddresses = new Map(addresses.map(ip => [ip, ipaddr.parse(ip).toString()]));
    for (const [ip, normalizedIp] of normalizedAddresses) {
      if (observations.length >= MAX_PTR_OBSERVATIONS) break;
      const ptrName = reverseDnsName(ip);
      const ptrRecords = await queryDNS(ptrName, 'PTR', budget);
      const ptrDns = dnsState(ptrRecords);
      // Only authoritative outcomes may claim "no PTR". A SERVFAIL or timeout
      // is not an observation about the host; carrying the state keeps the
      // report from presenting resolver trouble as reverse-DNS absence.
      const ptrDefinitive = ['ok', 'nodata', 'nxdomain'].includes(ptrDns.status);
      const ptr = ptrDefinitive ? (ptrRecords[0]?.replace(/\.$/, '') || null) : null;
      const forwardType = ipaddr.parse(ip).kind() === 'ipv6' ? 'AAAA' : 'A';
      let forwardRecords = [];
      let forwardUnknown = false;
      if (ptr) {
        const forward = await queryDNS(ptr, forwardType, budget);
        // A failed forward lookup is not evidence against the PTR; treat the
        // confirmation as unresolved instead of "not forward-confirmed".
        forwardUnknown = !['ok', 'nodata', 'nxdomain'].includes(dnsState(forward).status);
        forwardRecords = forward;
      }
      const matches = Boolean(
        ptr && !forwardUnknown && (forwardRecords.some(candidate =>
          candidate === ip ||
          (ipaddr.isValid(candidate) && ipaddr.parse(candidate).toString() === normalizedIp)
        ))
      );
      observations.push({
        mxHost, ip, ptr, matches,
        ptrUnknown: !ptrDefinitive,
        ...(ptrDefinitive ? {} : { dns: ptrDns }),
        forwardUnknown
      });
    }
  }
  const first = observations[0];
  return {
    checked: observations.length > 0,
    unknown: !observations.length && budget?.exhausted,
    observations,
    ...(first || {
      // The fallback must name the real cause: "no addresses" is an
      // observation about published MX hosts, while an exhausted budget means
      // they were never queried at all.
      reason: budget?.exhausted
        ? 'The request DNS budget ran out before any inbound MX host address could be observed.'
        : 'Published MX hosts had no A or AAAA addresses to inspect.'
    })
  };
}

async function analyzeSPF(domain, records, budget = null) {
  const dnsStatus = records?.dnsStatus || 'nodata';
  if (!['ok', 'nodata', 'nxdomain'].includes(dnsStatus)) {
    return {
      status: 'info', unknown: true, dnsStatus, record: null,
      checks: [{
        status: 'info', title: 'SPF lookup inconclusive',
        detail: `DNS returned ${dnsStatus}; absence of SPF cannot be concluded and no remediation is published.`,
        recommendation: 'Retry after the DNS provider or authoritative server recovers.'
      }], mechanisms: [], providers: [], lookupCount: 0
    };
  }
  const spfRecords = findSpfRecord(records);
  
  if (!spfRecords.length) {
    return {
      status: 'fail',
      record: null,
      checks: [{
        status: 'fail',
        title: 'No SPF record',
        detail: 'Domain has no SPF record. Anyone can spoof email.',
        recommendation: 'Create an SPF record to authorize sending servers.'
      }],
      mechanisms: [],
      providers: []
    };
  }

  if (spfRecords.length > 1) {
    return {
      status: 'fail',
      record: spfRecords[0],
      checks: [{
        status: 'fail',
        title: 'Multiple SPF records',
        detail: `Found ${spfRecords.length} records. Only one allowed.`,
        recommendation: 'Merge into a single SPF record.'
      }],
      mechanisms: [],
      providers: []
    };
  }

  const record = spfRecords[0];
  const checks = [];
  const mechanisms = [];
  const providers = new Set();

  // Parse mechanisms
  const parts = parseSpfRecord(record).tokens;
  for (const part of parts.slice(1)) {
    const clean = stripSpfQualifier(part);
    if (clean.startsWith('ip4:') || clean.startsWith('ip6:')) {
      mechanisms.push({ type: 'ip', value: clean });
    } else if (clean.startsWith('include:')) {
      mechanisms.push({ type: 'include', value: clean });
      // Detect provider
      for (const [key, name] of Object.entries(PROVIDERS)) {
        if (clean.includes(key) || part.includes(key)) providers.add(name);
      }
    } else if (clean.startsWith('a:') || clean === 'a' || clean.startsWith('a/')) {
      mechanisms.push({ type: 'a', value: clean });
    } else if (clean.startsWith('mx:') || clean === 'mx' || clean.startsWith('mx/')) {
      mechanisms.push({ type: 'mx', value: clean });
    } else if (clean.startsWith('exists:')) {
      mechanisms.push({ type: 'exists', value: clean });
    } else if (clean.startsWith('redirect=')) {
      mechanisms.push({ type: 'redirect', value: clean });
    } else if (clean === 'ptr' || clean.startsWith('ptr:')) {
      mechanisms.push({ type: 'ptr', value: clean });
    } else if (clean === 'all') {
      mechanisms.push({ type: 'all', value: part });
    }
  }

  // Check all mechanism
  const terminal = parts.map(spfTerminalTerm).find(Boolean);
  if (terminal === '-all') {
    checks.push({
      status: 'pass',
      title: 'Hard fail (-all)',
      detail: 'The domain asserts that unmatched clients are unauthorized; receiver handling remains local policy.',
      recommendation: ''
    });
  } else if (terminal === '~all') {
    checks.push({
      status: 'warn',
      title: 'Soft fail (~all)',
      detail: 'The domain makes a weak assertion that unmatched clients are probably unauthorized; receivers choose how to handle it.',
      recommendation: 'Consider -all for stricter enforcement.'
    });
  } else if (terminal === '?all' || terminal === '+all') {
    checks.push({
      status: 'fail',
      title: 'Permissive all mechanism',
      detail: `Using ${terminal} produces pass or neutral for unmatched clients and does not express a useful denial policy.`,
      recommendation: 'Change to -all or ~all.'
    });
  }

  const providerList = [...providers];
  if (providerList.length) {
    checks.push({
      status: 'info',
      title: 'Authorized providers',
      detail: `Found: ${providerList.join(', ')}`,
      recommendation: ''
    });
  }

  const duplicateIncludes = findDuplicateSpfIncludes(parts.slice(1));
  if (duplicateIncludes.length) {
    checks.push({
      status: 'warn',
      title: 'Duplicate SPF includes',
      detail: `Repeated include(s): ${duplicateIncludes.join(', ')}`,
      recommendation: 'Remove duplicate includes to keep the record readable and reduce maintenance risk.'
    });
  }

  if (mechanisms.some(m => m.type === 'ptr')) {
    checks.push({
      status: 'fail',
      title: 'SPF uses ptr mechanism',
      detail: 'The ptr mechanism is slow, fragile, and discouraged in SPF.',
      recommendation: 'Replace ptr with explicit include, a, mx, ip4, or ip6 mechanisms.'
    });
  }

  const recursive = await countSpfDnsLookupsRecursive(domain, record, new Set(), 0, null, budget);
  const lookupCount = recursive.count;
  if (recursive.truncated) {
    checks.push({
      status: 'warn',
      title: 'SPF recursion capped',
      detail: 'Nested SPF includes were capped during analysis to avoid excessive DNS lookups.',
      recommendation: 'Review complex SPF includes manually before relying on the exact count.'
    });
  }
  if (recursive.voidLookups.length) {
    checks.push({
      status: 'warn',
      title: 'SPF void lookups',
      detail: `No SPF record found for: ${recursive.voidLookups.slice(0, 4).join(', ')}`,
      recommendation: 'Remove stale includes or fix missing provider SPF records.'
    });
  }
  if (recursive.unknownLookups?.length) {
    checks.push({
      status: 'info',
      title: 'SPF nested lookup inconclusive',
      detail: `Could not confirm nested SPF state for: ${recursive.unknownLookups.slice(0, 4).join(', ')}`,
      recommendation: 'Retry before changing the published policy; a transient DNS failure is not a missing include.'
    });
  }
  if (recursive.macroLookups?.length) {
    checks.push({
      status: 'info',
      title: 'Sender macros in nested targets',
      detail: `${recursive.macroLookups.slice(0, 4).join(', ')} expand per message via sender macros, so their nested SPF state cannot be confirmed statically.`,
      recommendation: ''
    });
  }
  if (!terminal && mechanisms.some(m => m.type === 'redirect')) {
    // No local all-term: evaluation continues into the redirect target and
    // receivers apply that record's policy here (RFC 7208 §6.1). Judge
    // strength by the target chain's terminal instead of granting a pass.
    const redirectedTerminal = recursive.truncated ? null : recursive.finalAll;
    const voidedRedirect = mechanisms
      .map(m => m.value.slice('redirect='.length))
      .find(target => recursive.voidLookups.includes(target));
    if (redirectedTerminal === '-all') {
      checks.push({
        status: 'pass',
        title: 'Hard fail via redirect (-all)',
        detail: 'The redirect target asserts that unmatched clients are unauthorized; receiver handling remains local policy.',
        recommendation: ''
      });
    } else if (redirectedTerminal === '~all') {
      checks.push({
        status: 'warn',
        title: 'Soft fail via redirect (~all)',
        detail: 'The redirect target makes only a weak assertion about unmatched clients; receivers choose how to handle it.',
        recommendation: 'Consider a target with -all for stricter enforcement.'
      });
    } else if (redirectedTerminal === '?all' || redirectedTerminal === '+all') {
      checks.push({
        status: 'fail',
        title: 'Permissive policy behind redirect',
        detail: `The redirect target ends in ${redirectedTerminal}, producing pass or neutral for unmatched clients and expressing no useful denial policy.`,
        recommendation: 'Point the redirect at a record ending in -all or ~all.'
      });
    } else if (voidedRedirect) {
      // RFC 7208 §6.1: a redirect to a name without a usable SPF record is a
      // permanent error, not a pass.
      checks.push({
        status: 'fail',
        title: 'SPF redirect points nowhere',
        detail: `${voidedRedirect} publishes no SPF record, so evaluation ends in a permanent error rather than any denial policy.`,
        recommendation: 'Fix or remove the redirect modifier.'
      });
    } else {
      checks.push({
        status: 'warn',
        title: 'Redirected policy strength unconfirmed',
        detail: 'The record redirects to another domain and its terminal policy could not be confirmed during this analysis, so no enforcement claim can be made.',
        recommendation: 'Retry after DNS conditions improve, or inline the target policy.'
      });
    }
  }

  if (lookupCount > 10) {
    checks.push({
      status: 'fail',
      title: 'Too many DNS lookups',
      detail: `${lookupCount}/10 SPF DNS lookups are used after following nested includes.`,
      recommendation: 'Remove unused senders, flatten includes carefully, or split mail streams across subdomains.'
    });
  } else if (lookupCount >= 8) {
    checks.push({
      status: 'warn',
      title: 'SPF lookup budget nearly full',
      detail: `${lookupCount}/10 SPF DNS lookups are used after following nested includes.`,
      recommendation: 'Avoid adding more includes without flattening or removing unused senders.'
    });
  } else {
    checks.push({
      status: 'pass',
      title: 'SPF lookup budget healthy',
      detail: `${lookupCount}/10 SPF DNS lookups are used after following nested includes.`,
      recommendation: ''
    });
  }

  const status = recursive.unknownLookups?.length ? 'info' : checks.every(c => c.status === 'pass' || c.status === 'info') ? 'pass' :
                 checks.some(c => c.status === 'fail') ? 'fail' : 'warn';

  return { status, unknown: Boolean(recursive.unknownLookups?.length), record, checks, mechanisms, providers: providerList, lookupCount, recursiveLookups: recursive };
}

// SPF qualifier/terminal/lookup-count helpers and sender-macro detection
// live in policy-tags.js, shared with the unit suite.

function findDuplicateSpfIncludes(mechanisms) {
  const seen = new Set();
  const duplicates = new Set();
  mechanisms.forEach(part => {
    const clean = stripSpfQualifier(part);
    if (!clean.startsWith('include:')) return;
    const value = clean.slice(8);
    if (seen.has(value)) duplicates.add(value);
    seen.add(value);
  });
  return [...duplicates];
}

async function countSpfDnsLookupsRecursive(domain, record, seen = new Set(), depth = 0, state = null, budget = null) {
  state ||= { count: 0, voidLookups: [], unknownLookups: [], macroLookups: [], includes: [], truncated: false, queries: 0, finalAll: null };
  if (!record || depth > 8 || state.queries > 30) {
    state.truncated = true;
    return state;
  }

  const tokens = record.split(/\s+/).filter(Boolean).slice(1);
  state.count += countVisibleSpfLookups(tokens);

  // Track the terminal all-term of the redirect chain. Each call writes its
  // own all-term only when it does not successfully follow a redirect, so the
  // last write always belongs to the deepest followed target — the record
  // whose policy receivers actually apply (RFC 7208 §6.1).
  const ownAll = tokens.map(spfTerminalTerm).find(Boolean) || null;
  let followedRedirect = false;

  const includes = [];
  let redirect = null;
  tokens.forEach(token => {
    const clean = stripSpfQualifier(token);
    if (clean.startsWith('include:')) includes.push(clean.slice(8));
    if (clean.startsWith('redirect=')) redirect = clean.slice(9);
  });

  for (const includeDomain of includes) {
    if (seen.has(includeDomain)) continue;
    seen.add(includeDomain);
    state.includes.push(includeDomain);
    if (hasSpfMacro(includeDomain)) {
      state.macroLookups.push(includeDomain);
      continue;
    }
    state.queries++;
    const nestedRecords = await queryDNS(includeDomain, 'TXT', budget);
    const nestedSpf = findSpfRecord(nestedRecords)[0];
    if (!nestedSpf && !['ok', 'nodata', 'nxdomain'].includes(nestedRecords?.dnsStatus)) {
      state.unknownLookups.push(includeDomain);
      continue;
    }
    if (!nestedSpf) {
      state.voidLookups.push(includeDomain);
      continue;
    }
    await countSpfDnsLookupsRecursive(includeDomain, nestedSpf, seen, depth + 1, state, budget);
  }

  if (redirect && !seen.has(redirect)) {
    seen.add(redirect);
    state.includes.push(redirect);
    if (hasSpfMacro(redirect)) {
      state.macroLookups.push(redirect);
    } else {
      state.queries++;
      const redirectRecords = await queryDNS(redirect, 'TXT', budget);
      const redirectSpf = findSpfRecord(redirectRecords)[0];
      if (!redirectSpf && !['ok', 'nodata', 'nxdomain'].includes(redirectRecords?.dnsStatus)) state.unknownLookups.push(redirect);
      else if (!redirectSpf) state.voidLookups.push(redirect);
      else {
        followedRedirect = true;
        await countSpfDnsLookupsRecursive(redirect, redirectSpf, seen, depth + 1, state, budget);
      }
    }
  }

  if (!followedRedirect) state.finalAll = ownAll;

  return state;
}

async function buildSpfFlattenPreview(domain, record, budget = null) {
  if (!record) {
    return {
      available: false,
      safeToPublish: false,
      record: null,
      originalRecord: null,
      originalLookups: 0,
      flattenedLookups: 0,
      sources: [],
      warnings: ['No SPF record is available to flatten.'],
      generatedAt: new Date().toISOString()
    };
  }

  const context = {
    seen: new Set([domain]),
    queries: 0,
    maxQueries: 40,
    maxDepth: 10,
    sources: new Map(),
    warnings: [],
    incomplete: false,
    proof: true,
    proofReasons: [],
    budget
  };
  const parsed = parseSpfRecord(record);
  const rootTokens = parsed.terms;
  const rootTerminals = rootTokens.filter(token => stripSpfQualifier(token) === 'all');
  const finalAll = rootTerminals.at(-1) || '';
  if (!parsed.hasVersion) {
    context.proof = false;
    context.proofReasons.push('The source is not an SPF record.');
  }
  if (rootTerminals.length !== 1 || (finalAll && rootTokens.at(-1) !== finalAll)) {
    context.proof = false;
    context.proofReasons.push('The root policy does not have exactly one terminal all mechanism at the end.');
  }
  const expanded = await expandSpfForFlatten(domain, record, context, 0, true);
  const mechanisms = [];
  const seenMechanisms = new Set();

  expanded.forEach(item => {
    const clean = item.token.toLowerCase();
    if (stripSpfQualifier(clean) === 'all') return;
    if (seenMechanisms.has(clean)) return;
    seenMechanisms.add(clean);
    mechanisms.push(item.token);
    if (!context.sources.has(item.source)) context.sources.set(item.source, []);
    context.sources.get(item.source).push(item.token);
  });

  const flattenedRecord = ['v=spf1', ...mechanisms, finalAll].filter(Boolean).join(' ');
  const originalLookups = countVisibleSpfLookups(rootTokens);
  const flattenedLookups = countVisibleSpfLookups([...mechanisms, finalAll]);
  if (flattenedRecord.length > 450) {
    context.warnings.push(`Flattened record is ${flattenedRecord.length} characters and will require DNS TXT string chunking.`);
    context.incomplete = true;
  }
  if (flattenedLookups > 10) {
    context.warnings.push(`The preview still contains ${flattenedLookups} DNS lookups and does not solve the SPF limit.`);
    context.incomplete = true;
  }
  if (!context.warnings.length) {
    context.warnings.push('This is a point-in-time snapshot. Rebuild it whenever an email provider changes its sending ranges.');
  }
  const validation = await validateSpfRecord(domain, flattenedRecord, budget);
  context.warnings.push(...validation.warnings);
  context.warnings.push(...context.proofReasons);
  if (context.proofReasons.length) context.incomplete = true;

  return {
    available: true,
    safeToPublish: context.proof && !context.incomplete && validation.valid,
    record: flattenedRecord,
    originalRecord: record,
    originalLookups,
    flattenedLookups,
    characterCount: flattenedRecord.length,
    sources: [...context.sources.entries()].map(([source, tokens]) => ({ source, mechanisms: tokens })),
    warnings: [...new Set(context.warnings)],
    equivalence: {
      proven: context.proof && !context.incomplete && validation.valid,
      terminal: finalAll || null,
      method: 'positive ip4/ip6 mechanisms and includes ending in -all only; root terminal preserved',
      reasons: [...new Set(context.proofReasons)]
    },
    validation,
    generatedAt: new Date().toISOString()
  };
}

async function expandSpfForFlatten(domain, record, context, depth, isRoot = false) {
  if (depth > context.maxDepth || context.queries > context.maxQueries) {
    context.incomplete = true;
    context.warnings.push(`Expansion stopped at ${domain}: safety limit reached.`);
    return [];
  }

  const output = [];
  const tokens = String(record || '').split(/\s+/).filter(Boolean).slice(1);
  for (const token of tokens) {
    const clean = stripSpfQualifier(token);
    const qualifier = /^[+?~-]/.test(token) ? token[0] : '+';

    if (clean === 'all') {
      if (isRoot) output.push({ token, source: domain });
      continue;
    }
    if (clean.startsWith('ip4:') || clean.startsWith('ip6:')) {
      if (qualifier !== '+') {
        context.incomplete = true;
        context.proof = false;
        context.proofReasons.push(`${domain}: non-pass IP mechanism ${token} cannot be substituted safely.`);
        context.warnings.push(`Preserved ${token}: non-pass IP mechanisms cannot be substituted through include without changing SPF results.`);
      }
      output.push({ token, source: domain });
      continue;
    }
    if (clean.startsWith('redirect=')) {
      context.incomplete = true;
      context.proof = false;
      context.proofReasons.push(`${domain}: redirect modifier changes terminal evaluation.`);
      context.warnings.push(`Preserved ${token}: redirect changes the terminal result and is not flattened without a full equivalence proof.`);
      output.push({ token, source: domain });
      continue;
    }
    if (clean.startsWith('include:')) {
      const target = clean.slice(clean.indexOf(clean.startsWith('include:') ? ':' : '=') + 1);
      if (token.includes('%') || (clean.startsWith('include:') && qualifier !== '+')) {
        context.incomplete = true;
        context.proof = false;
        context.proofReasons.push(`${domain}: macros or qualified includes are not terminal-equivalent.`);
        context.warnings.push(`Preserved ${token}: macros and qualified includes cannot be safely flattened.`);
        output.push({ token, source: domain });
        continue;
      }
      if (context.seen.has(target)) {
        context.incomplete = true;
        context.proof = false;
        context.proofReasons.push(`${domain}: recursive SPF cycle detected at ${target}.`);
        context.warnings.push(`Preserved ${token}: recursive SPF cycle detected.`);
        output.push({ token, source: domain });
        continue;
      }
      context.seen.add(target);
      context.queries++;
      const records = await queryDNS(target, 'TXT', context.budget);
      const nested = findSpfRecord(records)[0];
      if (!nested) {
        context.incomplete = true;
        context.proof = false;
        context.proofReasons.push(`${target}: nested SPF record could not be confirmed.`);
        context.warnings.push(`Preserved ${token}: ${target} did not return an SPF record.`);
        output.push({ token, source: domain });
      } else {
        const nestedParsed = parseSpfRecord(nested);
        const nestedTerms = nestedParsed.terms;
        const nestedTerminal = nestedTerms.at(-1);
        if (stripSpfQualifier(nestedTerminal) !== 'all' || spfTerminalTerm(nestedTerminal) !== '-all') {
          context.incomplete = true;
          context.proof = false;
          context.proofReasons.push(`${target}: include terminal ${nestedTerminal || '(none)'} is not the proven -all subset.`);
          context.warnings.push(`Preserved ${token}: nested terminal behavior requires manual review.`);
          output.push({ token, source: domain });
        } else {
          output.push(...await expandSpfForFlatten(target, nested, context, depth + 1, false));
        }
      }
      context.seen.delete(target);
      continue;
    }

    // a, mx and exists are deliberately retained. Resolving them into a
    // snapshot could silently change semantics as hosts and macros change.
    if (
      clean === 'a' || clean.startsWith('a:') || clean.startsWith('a/') ||
      clean === 'mx' || clean.startsWith('mx:') || clean.startsWith('mx/') ||
      clean.startsWith('exists:')
    ) {
      context.incomplete = true;
      context.proof = false;
      context.proofReasons.push(`${domain}: dynamic ${clean.split(/[:/]/)[0]} mechanism is not frozen into a proof.`);
      context.warnings.push(`Preserved ${token}: dynamic ${clean.split(/[:/]/)[0]} mechanisms are not frozen into IP addresses.`);
      output.push({ token, source: domain });
      continue;
    }

    if (!clean.startsWith('exp=')) {
      context.incomplete = true;
      context.proof = false;
      context.proofReasons.push(`${domain}: unsupported SPF term ${token}.`);
      context.warnings.push(`Preserved unrecognised SPF term ${token}.`);
      output.push({ token, source: domain });
    } else {
      context.incomplete = true;
      context.proof = false;
      context.proofReasons.push(`${domain}: exp modifier is not preserved by flattening.`);
      output.push({ token, source: domain });
    }
  }
  return output;
}

function analyzeDMARC(records, discovery = {}) {
  const dmarcRecords = records.filter(isDmarcVersionRecord);
  
  if (!dmarcRecords.length) {
    const transient = discovery.dns?.status && !['ok', 'nodata', 'nxdomain'].includes(discovery.dns.status);
    return {
      status: transient ? 'info' : 'fail',
      unknown: Boolean(transient),
      record: null,
      checks: [{
        status: transient ? 'info' : 'fail',
        title: transient ? 'DMARC lookup inconclusive' : 'No DMARC policy discovered',
        detail: transient
          ? `DNS result: ${discovery.dns.status}. Absence cannot be concluded.`
          : 'RFC 9989 discovery found no policy on the domain or its parent policy domains.',
        recommendation: transient ? 'Retry after DNS recovers before creating or changing a policy.' : 'Create DMARC record to prevent spoofing.'
      }],
      policy: null,
      rua: null,
      ruf: null
    };
  }

  if (dmarcRecords.length > 1) {
    return {
      status: 'fail',
      record: dmarcRecords[0],
      checks: [{
        status: 'fail',
        title: 'Multiple DMARC records',
        detail: `Found ${dmarcRecords.length} DMARC records. Receivers expect exactly one.`,
        recommendation: 'Merge the policy into one _dmarc TXT record.'
      }],
      policy: null,
      rua: null,
      ruf: null
    };
  }

  const record = dmarcRecords[0];
  // The validator refuses duplicate tags, and receivers treat them as
  // malformed, but parseTagRecord silently keeps the last value — a record
  // like "p=none;p=reject" would be analyzed as whichever came last with no
  // diagnostic. Fail here exactly like validateDmarcRecord does.
  const seenTags = new Set();
  const duplicateTags = [];
  String(record).split(';').forEach(part => {
    const index = part.indexOf('=');
    if (index < 1) return;
    const key = part.slice(0, index).trim().toLowerCase();
    if (seenTags.has(key)) duplicateTags.push(key);
    seenTags.add(key);
  });
  if (duplicateTags.length) {
    return {
      status: 'fail',
      record,
      checks: [{
        status: 'fail',
        title: 'DMARC tag appears more than once',
        detail: `Tag${duplicateTags.length > 1 ? 's' : ''} ${duplicateTags.join(', ')} appear more than once. Receivers treat such records as invalid and may ignore the policy entirely.`,
        recommendation: 'Publish exactly one occurrence of each DMARC tag.'
      }],
      policy: null,
      rua: null,
      ruf: null
    };
  }
  const checks = [];
  const tags = parseTagRecord(record);
  if (discovery.inherited) {
    checks.push({
      status: 'info',
      title: 'Inherited DMARC policy',
      detail: `Policy discovered at _dmarc.${discovery.policyDomain}.`,
      recommendation: ''
    });
  }

  // Parse policy. For inherited records the value receivers apply to this
  // domain is sp= when present (RFC 7489 §6.6.3), not the parent's p=.
  const publishedPolicy = tags.p || null;
  const inheritedRecord = Boolean(discovery.inherited);
  const usingSp = inheritedRecord && DMARC_POLICY_VALUES.includes(tags.sp);
  const policy = effectiveDmarcPolicy(tags, inheritedRecord);

  if (policy === 'none') {
    checks.push({
      status: 'warn',
      title: `Monitoring mode (${usingSp ? 'sp' : 'p'}=none)`,
      detail: usingSp
        ? `Receivers apply sp=none from _dmarc.${discovery.policyDomain} to this subdomain: collecting data but not enforcing.`
        : 'Collecting data but not enforcing.',
      recommendation: `Move to ${usingSp ? 'sp' : 'p'}=quarantine or ${usingSp ? 'sp' : 'p'}=reject${usingSp ? `, or publish a DMARC record for this subdomain` : ''}.`
    });
  } else if (policy === 'quarantine') {
    checks.push({
      status: 'pass',
      title: 'Quarantine policy',
      detail: usingSp
        ? `Suspicious emails sent to spam; receivers apply sp=quarantine from _dmarc.${discovery.policyDomain} to this subdomain.`
        : 'Suspicious emails sent to spam.',
      recommendation: usingSp ? '' : 'Consider p=reject for maximum protection.'
    });
  } else if (policy === 'reject') {
    checks.push({
      status: 'pass',
      title: 'Reject policy',
      detail: usingSp
        ? `Spoofed emails rejected for this subdomain via sp=reject at _dmarc.${discovery.policyDomain}. Maximum protection.`
        : 'Spoofed emails rejected. Maximum protection.',
      recommendation: ''
    });
  } else {
    checks.push({
      status: 'fail',
      title: 'Invalid or missing DMARC policy',
      detail: publishedPolicy ? `Unknown p= value: ${publishedPolicy}` : 'No p= tag was found.',
      recommendation: 'Set p=none, p=quarantine, or p=reject.'
    });
  }

  // Parse reporting
  const rua = parseMailtoList(tags.rua);
  const ruf = parseMailtoList(tags.ruf);

  if (rua.length) {
    checks.push({
      status: 'pass',
      title: 'Aggregate reports configured',
      detail: `Reports to: ${rua.join(', ')}`,
      recommendation: ''
    });
  } else {
    checks.push({
      status: 'warn',
      title: 'No aggregate reporting',
      detail: 'No rua= tag. No DMARC reports.',
      recommendation: 'Add rua=mailto:dmarc@yourdomain.com'
    });
  }

  if (ruf.length) {
    checks.push({
      status: 'info',
      title: 'Forensic reports configured',
      detail: `Failure reports to: ${ruf.join(', ')}`,
      recommendation: 'Forensic reports can include sensitive message data; make sure this mailbox is controlled.'
    });
  }

  if (tags.pct) {
    checks.push({
      status: 'warn',
      title: 'Historic pct= tag is ignored',
      detail: 'RFC 9989 receivers ignore pct=. It no longer limits policy application.',
      recommendation: 'Remove pct=. Use t=y for a testing policy when required.'
    });
  }
  if (tags.t) checks.push({
    status: tags.t === 'y' ? 'warn' : tags.t === 'n' ? 'info' : 'fail',
    title: tags.t === 'y' ? 'Testing policy (t=y)' : tags.t === 'n' ? 'Production policy (t=n)' : 'Invalid t= tag',
    detail: tags.t === 'y' ? 'RFC 9989 testing mode is requested.' : `t=${tags.t}`,
    recommendation: tags.t === 'y' ? 'Move to t=n or omit t= after report review.' : ''
  });
  if (tags.np) checks.push({
    status: ['none', 'quarantine', 'reject'].includes(tags.np) ? 'info' : 'fail',
    title: `Non-existent subdomain policy: ${tags.np}`,
    detail: `RFC 9989 np=${tags.np} applies to non-existent subdomains.`,
    recommendation: ''
  });

  // Check subdomain policy. When sp= already governs this inherited record,
  // the effective-policy checks above describe it; repeating it here from the
  // parent-record perspective would read as if this domain were the parent.
  if (usingSp) {
    // covered by the effective-policy checks above
  } else if (tags.sp) {
    const weakerSubdomainPolicy = publishedPolicy !== 'none' && tags.sp === 'none';
    checks.push({
      status: ['none', 'quarantine', 'reject'].includes(tags.sp) ? (weakerSubdomainPolicy ? 'warn' : 'info') : 'fail',
      title: `Subdomain policy: ${tags.sp}`,
      detail: `Subdomains use: ${tags.sp}`,
      recommendation: weakerSubdomainPolicy ? 'Use sp=quarantine or sp=reject if subdomains should be protected too.' : ''
    });
  } else if (policy === 'reject' || policy === 'quarantine') {
    checks.push({
      status: 'info',
      title: 'Subdomains inherit DMARC policy',
      detail: `No sp= tag set, so subdomains inherit p=${policy}.`,
      recommendation: ''
    });
  }

  if (tags.adkim) {
    checks.push({
      status: ['r', 's'].includes(tags.adkim) ? 'info' : 'fail',
      title: `DKIM alignment: ${tags.adkim === 's' ? 'strict' : tags.adkim === 'r' ? 'relaxed' : 'invalid'}`,
      detail: tags.adkim === 's' ? 'DKIM signing domain must exactly match the From domain.' : tags.adkim === 'r' ? 'DKIM can align at the organisational domain.' : `Invalid adkim=${tags.adkim}.`,
      recommendation: ['r', 's'].includes(tags.adkim) ? '' : 'Use adkim=r or adkim=s.'
    });
  }
  if (tags.aspf) {
    checks.push({
      status: ['r', 's'].includes(tags.aspf) ? 'info' : 'fail',
      title: `SPF alignment: ${tags.aspf === 's' ? 'strict' : tags.aspf === 'r' ? 'relaxed' : 'invalid'}`,
      detail: tags.aspf === 's' ? 'Return-Path domain must exactly match the From domain.' : tags.aspf === 'r' ? 'SPF can align at the organisational domain.' : `Invalid aspf=${tags.aspf}.`,
      recommendation: ['r', 's'].includes(tags.aspf) ? '' : 'Use aspf=r or aspf=s.'
    });
  }

  const status = checks.some(c => c.status === 'fail') ? 'fail' :
                 policy === 'reject' || policy === 'quarantine' ? 'pass' :
                 policy === 'none' ? 'warn' : 'fail';

  return { status, record, checks, policy, rua, ruf, policyDomain: discovery.policyDomain || null, inherited: Boolean(discovery.inherited) };
}

// parseTagRecord lives in policy-tags.js, shared with the unit suites.

function parseMailtoList(value) {
  if (!value) return [];
  // URI schemes are case-insensitive (RFC 3986 §3.1); the validator accepts
  // MAILTO: so the authorisation loop must too, or uppercase spellings
  // silently skip external-destination verification.
  return value
    .split(',')
    .map(item => item.trim())
    .filter(item => /^mailto:/i.test(item))
    .map(item => item.slice(7).split('!')[0])
    .filter(Boolean);
}

function analyzeDKIM(results) {
  if (!results.length) {
    const unknown = ['timeout', 'servfail', 'error', 'budget_exceeded', 'unknown', 'partial'].includes(results.dnsStatus);
    return {
      status: unknown ? 'info' : 'warn',
      unknown,
      selectors: [],
      checks: [{
        status: unknown ? 'info' : 'warn',
        title: unknown ? 'DKIM selector lookup inconclusive' : 'No DKIM records found',
        detail: unknown ? `DNS returned ${results.dnsStatus}; common selectors cannot be concluded absent.` : 'Could not find DKIM keys for common selectors.',
        recommendation: unknown ? 'Retry before changing DKIM configuration.' : 'DKIM may use custom selectors or not be configured.'
      }]
    };
  }

  const checks = [{
    status: 'pass',
    title: `Found ${results.length} DKIM key(s)`,
    detail: `Selectors: ${results.map(r => r.selector).join(', ')}`,
    recommendation: ''
  }];
  // A scan that stopped early — through transient DNS trouble or because the
  // request's DNS budget ran out mid-scan — cannot conclude that the remaining
  // catalogue selectors are absent, even though the selectors it did reach may
  // be genuine findings.
  const partial = results.dnsStatus === 'partial' || results.dnsStatus === 'budget_exceeded';
  if (partial) {
    const budgetStopped = results.dnsStatus === 'budget_exceeded';
    checks.push({
      status: 'info',
      title: budgetStopped
        ? 'DKIM selector scan stopped at the DNS budget'
        : 'Some DKIM selector lookups were inconclusive',
      detail: budgetStopped
        ? 'At least one common selector was found before the request DNS budget ran out; the remaining selectors were never checked.'
        : 'At least one common selector was found, but other selector lookups did not complete authoritatively.',
      recommendation: 'Retry before concluding that additional selectors are absent.'
    });
  }

  let validKeys = 0;
  results.forEach(result => {
    const record = result.record || '';
    const tags = parseTagRecord(record);
    const hasPublicKey = Boolean(tags.p && tags.p.trim());
    if (hasPublicKey) validKeys++;
    if (/t=y/i.test(record)) {
      checks.push({
        status: 'warn',
        title: `Selector ${result.selector} is in test mode`,
        detail: 'DKIM record contains t=y.',
        recommendation: 'Remove t=y when DKIM signing is ready for production.'
      });
    }
    const keyType = tags.k || (record.includes('k=rsa') ? 'rsa' : 'rsa');
    if (keyType === 'rsa') {
      const keyBits = estimateDkimKeyBits(tags.p || '');
      checks.push({
        status: keyBits && keyBits < 2048 ? 'warn' : 'info',
        title: `Selector ${result.selector} uses RSA`,
        detail: keyBits ? `Public key length: ${keyBits} bits.` : 'RSA DKIM key found.',
        recommendation: keyBits && keyBits < 2048 ? 'Rotate to a 2048-bit DKIM key where supported.' : 'Use 2048-bit keys where supported.'
      });
    } else if (keyType === 'ed25519') {
      checks.push({
        status: 'info',
        title: `Selector ${result.selector} uses Ed25519`,
        detail: 'Modern DKIM key type found.',
        recommendation: 'Keep RSA selectors too if receivers in your market still require RSA DKIM.'
      });
    }
    if (!hasPublicKey) {
      checks.push({
        status: 'warn',
        title: `Selector ${result.selector} has an empty DKIM key`,
        detail: 'The DKIM public key p= value is empty, which usually means the selector is retired or revoked.',
        recommendation: 'Remove retired selectors if they are no longer used, or republish the key if this selector should still sign mail.'
      });
    }
  });

  if (!validKeys) {
    checks.push({
      status: 'fail',
      title: 'No usable DKIM public key found',
      detail: 'Selectors were discovered, but none contained a non-empty p= public key.',
      recommendation: 'Enable DKIM signing and publish at least one active selector.'
    });
  }

  const status = checks.some(c => c.status === 'fail') ? 'fail' :
                 checks.some(c => c.status === 'warn') ? 'warn' : 'pass';

  return {
    status,
    unknown: partial,
    selectors: results,
    checks
  };
}

// estimateDkimKeyBits and calculateScore live in scoring.js, shared with the
// unit suite; the estimator reads exact RSA modulus bits from the DER SPKI.

function analyzeMX(records) {
  if (!records.length) {
    const unknown = ['timeout', 'servfail', 'error', 'budget_exceeded'].includes(records?.dnsStatus);
    // Missing MX is informational either way: RFC 5321 A/AAAA fallback means
    // absence is not proof the domain cannot receive mail.
    return {
      status: 'info',
      unknown,
      records: [],
      checks: [{
        status: 'info',
        title: unknown ? 'MX lookup inconclusive' : 'No MX record published',
        detail: unknown
          ? `DNS returned ${records.dnsStatus}; absence of MX cannot be concluded.`
          : 'RFC 5321 permits SMTP fallback to the domain A or AAAA address records when no MX exists. This is not proof that the domain cannot receive mail.',
        recommendation: unknown ? 'Retry before changing mail routing.' : 'Publish MX records for explicit mail routing, or publish a Null MX record if the domain intentionally receives no mail.'
      }]
    };
  }

  const mx = records.map(r => {
    const [priority, ...hostParts] = String(r).trim().split(/\s+/);
    // DNS data is external input; an unparsable priority must not poison the
    // sort comparator with NaN and shuffle the whole table. Malformed rows
    // sort last so the rendered primary host stays the lowest real value.
    const parsed = Number.parseInt(priority, 10);
    return { priority: Number.isFinite(parsed) ? parsed : 65535, host: hostParts.join(' ').replace(/\.$/, '') };
  }).sort((a, b) => (Number.isFinite(a.priority) ? a.priority : 65535) - (Number.isFinite(b.priority) ? b.priority : 65535));
  const nullMx = mx.length === 1 && mx[0].priority === 0 && (mx[0].host === '' || mx[0].host === '.');
  const mixedNullMx = mx.some(item => item.priority === 0 && (item.host === '' || item.host === '.')) && !nullMx;
  if (mixedNullMx) {
    return {
      status: 'fail', records: mx, nullMx: false, mixedNullMx: true, providers: [],
      checks: [{ status: 'fail', title: 'Mixed Null MX and mail hosts', detail: 'A Null MX record must be the sole MX record. Mixing it with real mail hosts is malformed and ambiguous.', recommendation: 'Remove the Null MX record or publish it alone when the domain should reject inbound mail.' }]
    };
  }
  if (nullMx) {
    return {
      status: 'info',
      records: mx,
      nullMx: true,
      providers: [],
      checks: [{
        status: 'info',
        title: 'Null MX published',
        detail: 'RFC 7505 Null MX explicitly states that this domain does not accept inbound email.',
        recommendation: 'No inbound MX remediation is required unless the domain should receive mail.'
      }]
    };
  }

  const providers = [...new Set(mx.flatMap(record =>
    Object.entries(MX_PROVIDERS)
      .filter(([needle]) => record.host.toLowerCase().includes(needle))
      .map(([, provider]) => provider)
  ))];

  const checks = [{
    status: 'pass',
    title: `${mx.length} MX record(s)`,
    detail: `Primary: ${mx[0].host}`,
    recommendation: ''
  }];

  if (providers.length) {
    checks.push({
      status: 'info',
      title: 'Mail provider detected',
      detail: providers.join(', '),
      recommendation: ''
    });
  }

  return {
    status: 'pass',
    records: mx,
    providers,
    checks
  };
}

function analyzeCAA(records) {
  if (!records.length) {
    const unknown = ['timeout', 'servfail', 'error', 'budget_exceeded'].includes(records?.dnsStatus);
    return {
      status: unknown ? 'info' : 'warn',
      unknown,
      records: [],
      checks: [{
        status: unknown ? 'info' : 'warn',
        title: unknown ? 'CAA lookup inconclusive' : 'No CAA records',
        detail: unknown ? `DNS returned ${records.dnsStatus}; CAA absence cannot be concluded.` : 'Without CAA records, certificate issuance is not restricted by this domain.',
        recommendation: unknown ? 'Retry before changing certificate policy.' : 'Add CAA issue or issuewild records if issuance should be restricted.'
      }]
    };
  }

  const parsed = records.map(parseCaaRecord);
  const issuance = parsed.filter(item => item.tag === 'issue' || item.tag === 'issuewild');
  const reporting = parsed.filter(item => item.tag === 'iodef');
  const restricted = issuance.length > 0;
  return {
    status: restricted ? 'pass' : 'warn',
    records: parsed,
    issuers: issuance.map(item => item.value),
    reporting: reporting.map(item => item.value),
    checks: [{
      status: restricted ? 'pass' : 'warn',
      title: restricted ? 'CAA issuance policy configured' : 'CAA present without issuance restriction',
      detail: restricted ? `Issuance tags: ${issuance.map(item => `${item.tag}=${item.value || '(deny all)'}`).join(', ')}` : 'Only iodef or non-issuance CAA properties were found. They report incidents but do not restrict certificate issuance under RFC 8659.',
      recommendation: restricted ? '' : 'Add an issue or issuewild tag with the intended CA identifier, or document why unrestricted issuance is intentional.'
    }]
  };
}

function parseCaaRecord(value) {
  const raw = String(value || '').trim();
  const match = raw.match(/^([0-9]+)\s+([^\s]+)\s+(.*)$/);
  if (!match) return { raw, flags: null, tag: 'unknown', value: raw };
  const parsedValue = match[3].trim().replace(/^"|"$/g, '');
  return { raw, flags: Number(match[1]), tag: match[2].toLowerCase(), value: parsedValue };
}

function analyzePTR(result, mxRecords) {
  if (!result.checked) {
    const unknown = Boolean(result.unknown);
    return {
      status: unknown ? 'info' : 'warn',
      unknown,
      ...result,
      checks: [{
        status: unknown ? 'info' : result.notApplicable ? 'info' : 'warn',
        title: result.notApplicable ? 'Inbound reverse DNS not applicable' : unknown ? 'Inbound reverse DNS lookup inconclusive' : 'Inbound MX reverse DNS not checked',
        detail: result.reason,
        recommendation: unknown ? 'Retry after DNS recovers. PTR evidence is informational and does not prove outbound reputation.' : ''
      }]
    };
  }

  if (!result.ptr) {
    if (result.ptrUnknown) {
      return {
        status: 'info',
        unknown: true,
        ...result,
        checks: [{
          status: 'info',
          title: 'Inbound reverse DNS lookup inconclusive',
          detail: `The PTR query for ${result.ip} did not complete authoritatively (${result.dns?.status || 'DNS error'}), so no absence claim is made.`,
          recommendation: 'Retry after DNS recovers. PTR evidence is informational and does not prove outbound reputation.'
        }]
      };
    }
    return {
      status: 'warn',
      ...result,
      checks: [{
        status: 'warn',
        title: 'No PTR record',
        detail: `IP ${result.ip} has no reverse DNS.`,
        recommendation: 'Configure PTR record for better deliverability.'
      }]
    };
  }

  if (result.forwardUnknown) {
    return {
      status: 'info',
      unknown: true,
      ...result,
      checks: [{
        status: 'info',
        title: 'Forward confirmation inconclusive',
        detail: `${result.ip} -> ${result.ptr} was observed, but the forward lookup of ${result.ptr} could not be completed to confirm the pairing (MX host ${result.mxHost}).`,
        recommendation: 'Retry after DNS recovers before judging forward-confirmed reverse DNS for this MX IP.'
      }]
    };
  }

  return {
    status: result.matches ? 'pass' : 'warn',
    ...result,
    checks: [{
      status: result.matches ? 'pass' : 'warn',
      title: result.matches ? 'Inbound MX IP has forward-confirmed reverse DNS' : 'Inbound MX reverse DNS is not forward-confirmed',
      detail: `Observed ${result.ip} -> ${result.ptr}; MX host ${result.mxHost}. This is an inbound-host observation, not a sending-domain deliverability guarantee.`,
      recommendation: result.matches ? '' : 'Ask the mail-hosting provider to review forward-confirmed reverse DNS for this MX IP.'
    }]
  };
}

async function fetchMtaStsPolicy(domain, budget = null) {
  const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  const cacheKey = new Request(`https://policy-cache.internal/mta-sts/${domain}`);
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) return cached.json();

  const result = { fetched: false, url, finalUrl: null, status: null, redirected: false, policy: null, error: null };
  if (budget && !budget.reserve('mta-sts')) {
    result.error = `Request subrequest budget of ${budget.limit} was exhausted before MTA-STS policy fetch`;
    result.budgetExceeded = true;
    return result;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      // workerd does not implement the 'error' redirect mode; requesting it
      // makes every policy fetch throw before any request is sent. 'manual'
      // returns redirect responses unfollowed, which keeps the rule this
      // check exists for: the policy must be served from exactly the
      // expected origin.
      redirect: 'manual',
      cf: { cacheTtl: POLICY_CACHE_TTL, cacheEverything: true }
    });
    result.status = response.status;
    result.finalUrl = response.url || url;
    const wasRedirected = Boolean(response.redirected)
      || (response.status >= 300 && response.status < 400)
      || (Boolean(response.url) && response.url !== url);
    result.redirected = wasRedirected;
    if (wasRedirected) {
      result.error = 'MTA-STS policy fetch did not remain on the expected mta-sts origin.';
      return result;
    }
    result.contentType = response.headers.get('content-type');
    if (response.ok) {
      const policy = await readBodyBytes(response.body, MTA_STS_POLICY_MAX_BYTES, controller.signal, 'MTA-STS policy response body');
      result.fetched = true;
      result.policy = new TextDecoder().decode(policy).slice(0, 4000);
    }
  } catch (err) {
    result.error = err?.name === 'AbortError' ? `Policy fetch timed out after ${DNS_TIMEOUT_MS}ms` : err.message;
  } finally {
    clearTimeout(timer);
  }

  // A definitive observation (policy fetched, or an HTTP answer such as 404)
  // may be cached for a day. Transport-level failures — timeouts, aborted
  // bodies, network errors — are not observations; caching one would pin an
  // unreachable verdict into the edge cache for 24h, so they stay uncached
  // and retry on the next request.
  const durableObservation = result.fetched || (result.status !== null && !result.error);
  if (durableObservation) {
    await cache.put(cacheKey, new Response(JSON.stringify(result), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': `public, max-age=${POLICY_CACHE_TTL}, stale-while-revalidate=86400`
      }
    }));
  }

  return result;
}

function analyzeTransportSecurity(mtaStsRecords, tlsRptRecords, policyResult, mxRecords = []) {
  const checks = [];
  const transientMtaDns = !['ok', 'nodata', 'nxdomain'].includes(mtaStsRecords?.dnsStatus || 'nodata');
  const transientTlsDns = !['ok', 'nodata', 'nxdomain'].includes(tlsRptRecords?.dnsStatus || 'nodata');
  // Same shape rule as the discovery gate in analyzeDomain: accept a bare
  // version token so an incomplete record is analysed and reported as
  // "missing id=" instead of pretending no record exists.
  const mtaMatches = mtaStsRecords.filter(r => /^\s*v=STSv1(?:\s*;|\s*$)/i.test(r));
  const tlsMatches = tlsRptRecords.filter(r => /^\s*v=TLSRPTv1(?:\s*;|\s*$)/i.test(r));
  const mtaStsRecord = mtaMatches[0] || null;
  const tlsRptRecord = tlsMatches[0] || null;

  if (mtaMatches.length > 1) {
    checks.push({ status: 'fail', title: 'Multiple MTA-STS records', detail: `Found ${mtaMatches.length} STSv1 TXT records; exactly one is permitted.`, recommendation: 'Publish one _mta-sts TXT record.' });
  } else if (mtaStsRecord) {
    const dnsTags = parseTagRecord(mtaStsRecord);
    checks.push({
      status: dnsTags.id ? 'pass' : 'fail',
      title: dnsTags.id ? 'MTA-STS DNS record found' : 'MTA-STS id= is missing',
      detail: mtaStsRecord,
      recommendation: dnsTags.id ? '' : 'Publish v=STSv1; id=<policy-version>.'
    });
  } else {
    checks.push({
      status: 'info',
      title: transientMtaDns ? 'MTA-STS DNS lookup inconclusive' : 'No MTA-STS DNS record',
      detail: transientMtaDns ? `DNS returned ${mtaStsRecords.dnsStatus}; absence cannot be concluded.` : 'Inbound SMTP transport policy is not advertised.',
      recommendation: transientMtaDns ? 'Retry before changing transport policy.' : 'Add MTA-STS if the domain receives business email and you want downgrade protection.'
    });
  }

  if (policyResult?.fetched && policyResult.policy) {
    const policyTags = parsePolicyLines(policyResult.policy);
    const mode = policyTags.mode || 'missing';
    const mxPatterns = Array.isArray(policyTags.mx) ? policyTags.mx : policyTags.mx ? [policyTags.mx] : [];
    const maxAgeValid = /^\d+$/.test(String(policyTags.max_age || '')) && Number(policyTags.max_age) <= 31557600;
    const versionValid = policyTags.version === 'STSv1';
    const modeValid = ['enforce', 'testing', 'none'].includes(mode);
    const patternsValid = mxPatterns.every(isValidMtaStsMxPattern);
    const requiresMx = mode === 'enforce' || mode === 'testing';
    const currentMxCovered = mode === 'none' || mxRecords.every(mx => mxPatterns.some(pattern => mtaStsMxMatches(mx.host, pattern)));
    if (!versionValid || !modeValid || !maxAgeValid || !patternsValid || (requiresMx && !mxPatterns.length)) {
      checks.push({
        status: 'fail',
        title: 'Invalid MTA-STS policy syntax',
        detail: 'Policy requires version STSv1, a valid mode, max_age from 0 to 31557600, and valid mx lines in testing/enforce mode.',
        recommendation: 'Correct the HTTPS policy before relying on MTA-STS.'
      });
    }
    checks.push({
      status: mode === 'enforce' && currentMxCovered ? 'pass' : mode === 'testing' ? 'warn' : mode === 'none' ? 'info' : 'fail',
      title: `MTA-STS policy mode: ${mode}`,
      detail: mxPatterns.length ? `MX patterns: ${mxPatterns.join(', ')}${currentMxCovered ? '' : ' (do not cover every published MX host)'}` : 'No mx line was parsed.',
      recommendation: mode === 'enforce' && currentMxCovered ? '' : 'Move to mode=enforce after every inbound MX is covered.'
    });
    if (policyResult.contentType && !/^text\/plain(?:;|$)/i.test(policyResult.contentType)) {
      checks.push({
        status: 'warn',
        title: 'Unexpected MTA-STS media type',
        detail: `Policy was served as ${policyResult.contentType}.`,
        recommendation: 'Serve the policy as text/plain.'
      });
    }
  } else if (mtaStsRecord) {
    checks.push({
      status: policyResult?.budgetExceeded || policyResult?.error ? 'info' : 'warn',
      title: 'MTA-STS policy not reachable',
      detail: policyResult?.error || (policyResult?.status ? `HTTP status ${policyResult.status}` : 'Could not fetch the HTTPS policy file.'),
      recommendation: policyResult?.budgetExceeded ? 'The request budget was exhausted. Retry with a smaller batch.' : 'Publish https://mta-sts.domain/.well-known/mta-sts.txt with a valid certificate.'
    });
  }

  if (tlsMatches.length > 1) {
    checks.push({ status: 'fail', title: 'Multiple TLS-RPT records', detail: `Found ${tlsMatches.length} TLSRPTv1 records; the policy is invalid.`, recommendation: 'Merge reporting destinations into one record.' });
  } else if (tlsRptRecord) {
    const tlsTags = parseTagRecord(tlsRptRecord);
    const uris = String(tlsTags.rua || '').split(',').map(value => value.trim()).filter(Boolean);
    const validUris = uris.length && uris.every(isValidTlsRptUri);
    checks.push({
      status: validUris ? 'pass' : 'fail',
      title: validUris ? 'TLS-RPT configured' : 'Invalid TLS-RPT rua=',
      detail: tlsRptRecord,
      recommendation: validUris ? '' : 'Add at least one valid mailto: or https: reporting URI.'
    });
  } else {
    checks.push({
      status: transientTlsDns ? 'info' : mtaStsRecord ? 'warn' : 'info',
      title: transientTlsDns ? 'TLS-RPT lookup inconclusive' : 'No TLS-RPT record',
      detail: transientTlsDns ? `DNS returned ${tlsRptRecords.dnsStatus}; absence cannot be concluded.` : 'TLS delivery reports are not configured.',
      recommendation: transientTlsDns ? 'Retry before changing TLS reporting policy.' : 'Add _smtp._tls TXT with rua=mailto:tlsrpt@yourdomain.com to monitor TLS delivery issues.'
    });
  }

  const unknown = transientMtaDns || transientTlsDns || Boolean(policyResult?.error || policyResult?.budgetExceeded);
  const status = checks.some(c => c.status === 'fail') ? 'fail' :
                 checks.some(c => c.status === 'warn') ? 'warn' :
                 checks.some(c => c.status === 'pass') ? 'pass' : 'info';

  return {
    status,
    mtaStsRecord,
    tlsRptRecord,
    policy: policyResult,
    unknown,
    checks
  };
}

// MTA-STS policy parsing, mx-pattern validation, and wildcard matching live
// in mta-sts.js, shared with its behavioral unit suite. The matcher follows
// RFC 8461 §4.1: a wildcard expands to exactly one label.

function isValidTlsRptUri(value) {
  if (/^mailto:[^@\s,]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(value)) return true;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && Boolean(url.hostname);
  } catch {
    return false;
  }
}

// calculateScore lives in scoring.js; see the module for the evidence-in-hand
// scoring rules and the exact DKIM key-size reader.

