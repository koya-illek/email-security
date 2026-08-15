// Email Security Checker — Cloudflare Workers
// Optimized for 10ms CPU limit with parallel DoH lookups

const { spf: evaluateSpf } = require('mailauth/lib/spf');
const ipaddr = require('ipaddr.js');
const { analyzeEmailHeaders } = require('./header-analyzer');
const { redirectForRequest } = require('./redirects');
const { runScheduledCleanup } = require('./retention');
const { handleMcp } = require('./mcp');

const DOH_PROVIDERS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/resolve',
  'https://dns.quad9.net/dns-query'
];

const CACHE_TTL = 86400; // 24 hour edge cache
const POLICY_CACHE_TTL = 86400; // 24 hour cache for policy HTTP fetches
const CACHE_VERSION = 'v7-d1-reports';
const DNS_TIMEOUT_MS = 4500;
const NORMAL_JSON_BODY_MAX_BYTES = 16 * 1024;
const HEADER_JSON_BODY_MAX_BYTES = 256 * 1024;
const MTA_STS_POLICY_MAX_BYTES = 16 * 1024;
// Workers Free allows 50 external subrequests. Keep headroom for the
// request itself and make the limit explicit in every report instead of
// allowing a batch or recursive SPF walk to fail at the platform boundary.
const REQUEST_SUBREQUEST_LIMIT = 45;
const RATE_LIMIT_RETRY_AFTER_SECONDS = 60;
const DAILY_RATE_LIMIT_RETRY_AFTER_SECONDS = 86400;
const STANDARD_RATE_LIMITER_BINDING = 'STANDARD_RATE_LIMITER';
const EXPENSIVE_RATE_LIMITER_BINDING = 'EXPENSIVE_RATE_LIMITER';
const REPORT_RETENTION_DAYS = 14;
const REPORT_ID_RE = /^[A-Za-z0-9_-]{16}$/;
const BATCH_MAX_DOMAINS = 25;
const BATCH_CONCURRENCY = 5;
const EXPENSIVE_POST_PATHS = new Set([
  '/api/check',
  '/api/v2/domain-check',
  '/api/batch',
  '/api/header/enrich',
  '/api/spf/inspect',
  '/api/spf/evaluate',
  '/mcp',
  '/mcp/v2'
]);
const MCP_PATHS = new Set(['/mcp', '/mcp/v2']);

const API_SECURITY_HEADERS = {
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Robots-Tag': 'noindex, nofollow'
};

// Cloudflare Rate Limiting bindings share counters across Worker isolates within
// each serving location; these are not strict global quotas.

// Common DKIM selectors to check
// Generate a 16-character unguessable report ID using crypto.randomUUID
function generateReportId() {
  const raw = crypto.randomUUID().replace(/-/g, '');
  return raw.slice(0, 16);
}

function reportExpiry() {
  const d = new Date();
  d.setDate(d.getDate() + REPORT_RETENTION_DAYS);
  return d.toISOString();
}

async function storeReport(env, report) {
  if (!env.DB) return null;
  const id = generateReportId();
  const now = new Date().toISOString();
  const expires = reportExpiry();
  const storedReport = {
    ...report,
    id,
    share: reportShareMetadata(id, expires, true)
  };
  try {
    await env.DB.prepare(
      'INSERT INTO reports (id, type, domain, report_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(
      id,
      report._reportType || 'domain',
      report.domain || null,
      JSON.stringify(storedReport),
      now,
      expires
    ).run();
    return id;
  } catch {
    return null;
  }
}

async function loadReport(env, id) {
  if (!env.DB || !REPORT_ID_RE.test(id)) return null;
  try {
    const row = await env.DB.prepare(
      'SELECT report_json FROM reports WHERE id = ? AND expires_at > ?'
    ).bind(id, new Date().toISOString()).first();
    if (!row) return null;
    const report = JSON.parse(row.report_json);
    if (!report.id) report.id = id;
    return report;
  } catch {
    return null;
  }
}

function createRequestBudget(limit = REQUEST_SUBREQUEST_LIMIT) {
  return {
    limit,
    used: 0,
    exhausted: false,
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

function reportShareMetadata(id, expiresAt = null, available = Boolean(id)) {
  return {
    available,
    id: id || null,
    retentionDays: REPORT_RETENTION_DAYS,
    expiresAt,
    bearer: true,
    cacheControl: 'private, no-store'
  };
}

async function createDomainReport(domain, env, budget = createRequestBudget()) {
  const cacheKey = new Request(`https://cache.internal/${CACHE_VERSION}/${domain}`);
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) {
    const report = await cached.json();
    report.request_budget = budget.snapshot();
    return report;
  }

  const report = await analyzeDomain(domain, budget);
  report._reportType = 'domain';
  const reportId = await storeReport(env, report);
  if (reportId) report.id = reportId;
  report.share = reportShareMetadata(reportId, reportId ? reportExpiry() : null, Boolean(reportId));
  report.request_budget = budget.snapshot();

  if (report.overall_score > 0) {
    await cache.put(cacheKey, new Response(JSON.stringify(report), {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': `public, max-age=${CACHE_TTL}, stale-while-revalidate=86400`
      }
    }));
  }
  return report;
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

async function createBatchReport(domains, env, budget = createRequestBudget()) {
  const validation = validateBatchDomains(domains);
  const uniqueDomains = validation.accepted;
  if (!uniqueDomains.length) throw new InvalidRequestError('At least one valid public domain is required');
  const results = [];
  for (let index = 0; index < uniqueDomains.length; index += BATCH_CONCURRENCY) {
    const chunk = uniqueDomains.slice(index, index + BATCH_CONCURRENCY);
    const chunkResults = await Promise.all(chunk.map(async domain => {
      try {
        const report = await analyzeDomain(domain, budget);
        return {
          domain, overall_score: report.overall_score, overall_status: report.overall_status,
          spf: { status: report.spf.status, record: report.spf.record || null },
          dkim: { status: report.dkim.status, selectors: (report.dkim.selectors || []).map(selector => selector.selector) },
          dmarc: { status: report.dmarc.status, policy: report.dmarc.policy || null },
          mx: { status: report.mx.status, records: (report.mx.records || []).map(record => record.host) },
          transport: { status: report.transport?.status || 'info' },
        };
      } catch (error) {
        return {
          domain, overall_score: 0, overall_status: 'error', error: error.message,
          spf: { status: 'fail' }, dkim: { status: 'warn' }, dmarc: { status: 'fail' },
          mx: { status: 'fail' }, transport: { status: 'info' },
        };
      }
    }));
    results.push(...chunkResults);
  }
  const report = {
    _reportType: 'batch', domains: uniqueDomains, results, created_at: new Date().toISOString(),
    source_revision: budget.sourceRevision || 'unknown',
    validation, request_budget: budget.snapshot()
  };
  const reportId = await storeReport(env, report);
  if (reportId) report.id = reportId;
  report.share = reportShareMetadata(reportId, reportId ? reportExpiry() : null, Boolean(reportId));
  return report;
}

async function buildEmailRecord(input, budget = null) {
  const type = String(input.type || '').toLowerCase();
  const domain = normalizeDomain(input.domain);
  if (!domain || !isValidDomain(domain)) throw new Error('A valid domain is required');
  if (type === 'spf') {
    const mechanisms = Array.isArray(input.mechanisms) ? input.mechanisms.map(value => String(value).trim()).filter(Boolean) : [];
    const policy = ['~all', '-all', '?all', '+all', ''].includes(input.policy) ? input.policy : '~all';
    const record = ['v=spf1', ...mechanisms, policy].filter(Boolean).join(' ');
    const validation = await validateSpfRecord(domain, record, budget);
    const safetyWarnings = [];
    if (policy === '-all' && input.rolloutStage !== 'confirmed') safetyWarnings.push('Use ~all until every legitimate sender is confirmed.');
    if (!mechanisms.length && policy === '-all' && input.confirmsNoSenders !== true) safetyWarnings.push('An empty -all record rejects every sender and requires explicit confirmation that the domain sends no mail.');
    return { type, host: domain, record, validation, safetyWarnings, publishReady: validation.valid && !safetyWarnings.length };
  }
  if (type === 'dmarc') {
    const policy = ['none', 'quarantine', 'reject'].includes(input.policy) ? input.policy : 'none';
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
  throw new Error('type must be spf or dmarc');
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
  const requestBudget = createRequestBudget();
  requestBudget.sourceRevision = env?.SOURCE_REVISION || 'unknown';
  const securityHeaders = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://cloudflareinsights.com; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };

  const redirect = redirectForRequest(request);
  if (redirect) return redirect;
  
  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept, Authorization, MCP-Protocol-Version, MCP-Session-Id',
    'Access-Control-Expose-Headers': 'MCP-Protocol-Version, X-Report-Retention-Days'
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: { ...securityHeaders, ...corsHeaders, 'Access-Control-Max-Age': '600' } });
  }

  if (url.pathname === '/api/health' && request.method === 'GET') {
    return jsonResponse({ ok: true, service: 'email-security-checker', version: '2.0.0', source_revision: env.SOURCE_REVISION || 'unknown', liveness: true }, 200, securityHeaders);
  }

  if ((url.pathname === '/api' || url.pathname === '/api/' || url.pathname === '/api/v2') && request.method === 'GET') {
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

  if (request.method === 'POST' && ((url.pathname.startsWith('/api/') && url.pathname !== '/api/health') || MCP_PATHS.has(url.pathname))) {
    let retryAfter;
    try {
      const dailySuccess = await consumeDailyRateLimit(request, env, 'post', Number(env.DAILY_POST_LIMIT) || 500);
      if (!dailySuccess) return jsonResponse({ error: 'Daily API request limit reached.' }, 429, { ...corsHeaders, 'Retry-After': String(DAILY_RATE_LIMIT_RETRY_AFTER_SECONDS) });
      retryAfter = await consumePostRateLimit(request, url.pathname, env);
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
  }

  if (MCP_PATHS.has(url.pathname)) {
    return handleMcp(request, async (tool, args) => {
      if (tool === 'analyze_email_headers') {
        if (typeof args.headers !== 'string') throw new Error('headers must be a string');
        if (new TextEncoder().encode(args.headers).byteLength > HEADER_JSON_BODY_MAX_BYTES) throw new Error('headers exceeds the 256 KiB limit');
        return analyzeEmailHeaders(args.headers);
      }
      if (tool === 'analyze_email_domains_batch') {
        if (!Array.isArray(args.domains)) throw new Error('domains must be an array');
        return createBatchReport(args.domains, env, requestBudget);
      }
      if (tool === 'inspect_spf') {
        const domain = normalizeDomain(args.domain);
        if (!domain || !isValidDomain(domain)) throw new Error('A valid public domain is required');
        const txtRecords = await queryDNS(domain, 'TXT', requestBudget);
        const spf = await analyzeSPF(domain, txtRecords, requestBudget);
        return { domain, spf, flatten: await buildSpfFlattenPreview(domain, spf.record, requestBudget), request_budget: requestBudget.snapshot() };
      }
      if (tool === 'evaluate_spf') {
        const domain = normalizeDomain(args.domain || String(args.sender || '').split('@').pop());
        if (!domain || !isValidDomain(domain) || typeof args.ip !== 'string') throw new Error('A valid domain (or sender) and client IP are required');
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
        throw new Error('type must be spf or dmarc');
      }
      if (tool === 'build_email_record') return { ...(await buildEmailRecord(args, requestBudget)), request_budget: requestBudget.snapshot() };
      if (tool === 'enrich_email_hops') {
        if (!Array.isArray(args.ips)) throw new Error('ips must be an array');
        const ips = [...new Set(args.ips)].filter(isPublicIpAddress).slice(0, 10);
        return { enriched: await Promise.all(ips.map(ip => enrichIp(ip, requestBudget))), limit: 10, request_budget: requestBudget.snapshot() };
      }
      if (tool === 'get_email_security_report') {
        const reportId = String(args.reportId || '');
        if (!REPORT_ID_RE.test(reportId)) throw new Error('A valid 16-character report ID is required');
        const report = await loadReport(env, reportId);
        if (!report) throw new Error('Report not found or expired');
        return report;
      }
      const cleanDomain = normalizeDomain(args.domain);
      if (!cleanDomain || !isValidDomain(cleanDomain)) throw new Error('A valid public domain is required');
      return createDomainReport(cleanDomain, env, requestBudget);
    });
  }

  // API endpoint
  if ((url.pathname === '/api/check' || url.pathname === '/api/v2/domain-check') && request.method === 'POST') {
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

  if ((url.pathname === '/api/header/analyze' || url.pathname === '/api/v2/header-analysis') && request.method === 'POST') {
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

  if (url.pathname === '/api/header/enrich' && request.method === 'POST') {
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

  if (url.pathname === '/api/spf/inspect' && request.method === 'POST') {
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
      return requestErrorResponse(err, corsHeaders, 503);
    }
  }

  if (url.pathname === '/api/spf/evaluate' && request.method === 'POST') {
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

  if (url.pathname === '/api/records/validate' && request.method === 'POST') {
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

  if (url.pathname === '/api/v2/record-build' && request.method === 'POST') {
    try {
      return jsonResponse({ ...(await buildEmailRecord(await readJsonBody(request, NORMAL_JSON_BODY_MAX_BYTES), requestBudget)), request_budget: requestBudget.snapshot() }, 200, corsHeaders);
    } catch (err) {
      const limited = bodyLimitResponse(err, corsHeaders);
      if (limited) return limited;
      return requestErrorResponse(err, corsHeaders, 400);
    }
  }

  if (request.method === 'GET' && url.pathname.startsWith('/api/reports/')) {
    try {
      const success = await consumeDailyRateLimit(request, env, 'report', Number(env.REPORT_DAILY_LIMIT) || 120);
      if (!success) return jsonResponse({ error: 'Daily report retrieval limit reached.' }, 429, { ...corsHeaders, 'Retry-After': String(DAILY_RATE_LIMIT_RETRY_AFTER_SECONDS) });
    } catch {
      return jsonResponse({ error: 'Rate limiting is unavailable.' }, 503, corsHeaders);
    }
  }

  // GET /api/reports/:id — load a stored report
  const reportMatch = url.pathname.match(/^\/api\/reports\/([A-Za-z0-9_-]+)(\/export)?$/);
  if (reportMatch && request.method === 'GET') {
    const reportId = reportMatch[1];
    if (!REPORT_ID_RE.test(reportId)) {
      return jsonResponse({ error: 'Report not found' }, 404, corsHeaders);
    }
    const stored = await loadReport(env, reportId);
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
  if (url.pathname === '/api/batch' && request.method === 'POST') {
    try {
      const { domains } = await readJsonBody(request, NORMAL_JSON_BODY_MAX_BYTES);
      const batchReport = await createBatchReport(domains, env, requestBudget);
      return jsonResponse(batchReport, 200, corsHeaders);
    } catch (err) {
      return requestErrorResponse(err, corsHeaders, 503);
    }
  }

  // Serve static assets (index.html, styles.css, app.js, robots.txt, sitemap.xml, etc.)
  if (request.method === 'GET' && !url.pathname.startsWith('/api/')) {
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

function requestErrorResponse(error, corsHeaders, fallbackStatus = 500) {
  const limited = bodyLimitResponse(error, corsHeaders);
  if (limited) return limited;
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

  const client = request.headers.get('CF-Connecting-IP')?.trim() || 'anonymous';
  const { success } = await limiter.limit({ key: client });
  return success ? null : RATE_LIMIT_RETRY_AFTER_SECONDS;
}

async function consumeDailyRateLimit(request, env, scope, limit) {
  if (!env?.DB || typeof env.DB.prepare !== 'function') throw new Error('D1 rate limiting is unavailable');
  const date = new Date().toISOString().slice(0, 10);
  const ip = request.headers.get('CF-Connecting-IP')?.trim() || 'anonymous';
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

function isValidDomain(domain) {
  const value = String(domain || '');
  if (!value || value.length > 253 || value.includes('..') || ipaddr.isValid(value)) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  return labels.every((label, index) =>
    label.length >= 1 && label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label) &&
    (index !== labels.length - 1 || /^[a-z0-9-]{2,63}$/i.test(label))
  );
}

function normalizeDomain(value) {
  if (typeof value !== 'string') return '';
  let input = value.trim();
  if (!input || /[\s@?#]/.test(input)) return '';
  if (/^https?:\/\//i.test(input)) {
    try {
      const parsed = new URL(input);
      if (parsed.username || parsed.password || parsed.port || parsed.pathname !== '/' || parsed.search || parsed.hash) return '';
      input = parsed.hostname;
    } catch {
      return '';
    }
  }
  if (input.includes('/') || input.includes(':')) return '';
  input = input.toLowerCase().replace(/\.$/, '');
  return isValidDomain(input) ? input : '';
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

function spfTerminalTerm(term) {
  const clean = stripSpfQualifier(term);
  return clean === 'all' ? String(term || '').toLowerCase() : null;
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
    : { count: countVisibleSpfLookups(terms), voidLookups: [], truncated: false };
  if (recursive.count > 10) errors.push(`SPF evaluation requires ${recursive.count} DNS lookups; the maximum is 10.`);
  if (recursive.voidLookups?.length > 2) errors.push(`SPF evaluation produces ${recursive.voidLookups.length} void lookups; no more than 2 are allowed.`);
  else if (recursive.voidLookups?.length) warnings.push(`No SPF record was found for: ${recursive.voidLookups.join(', ')}`);
  if (recursive.truncated) errors.push('Recursive SPF validation could not complete within safety limits.');

  let evaluator = null;
  if (parsed.hasVersion && (domain || isValidDomain('fixture.example'))) {
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

  if (pairs[0]?.[0] !== 'v' || pairs[0]?.[1].toUpperCase() !== 'DMARC1') {
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
  if (tags.psd && !['y', 'n'].includes(tags.psd.toLowerCase())) errors.push('DMARC psd= must be y or n.');
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
    const external = parseMailtoList(tags.rua).filter(address => !address.toLowerCase().endsWith(`@${domain}`));
    for (const address of external) {
      const destination = address.split('@').pop().toLowerCase();
      const authName = `${domain}._report._dmarc.${destination}`;
      const authRecords = await queryDNS(authName, 'TXT', budget);
      const authorised = authRecords.some(item => /^\s*v=DMARC1\s*;/i.test(item));
      if (!authorised) warnings.push(`RFC 9990 authorisation was not found at ${authName}.`);
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

function isPublicIpAddress(ip) {
  try {
    return ipaddr.parse(String(ip)).range() === 'unicast';
  } catch {
    return false;
  }
}

function reverseDnsName(ip) {
  const parsed = ipaddr.parse(ip);
  if (parsed.kind() === 'ipv4') return parsed.toString().split('.').reverse().join('.') + '.in-addr.arpa';
  return parsed.toNormalizedString().replace(/:/g, '').split('').reverse().join('.') + '.ip6.arpa';
}

async function enrichIp(ip, budget = null) {
  const cacheKey = new Request(`https://header-cache.internal/ip/${ip}`);
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) return cached.json();

  const ptrName = reverseDnsName(ip);
  const ptrRecords = await queryDNS(ptrName, 'PTR', budget);
  const result = {
    ip,
    ptr: ptrRecords[0] ? ptrRecords[0].replace(/\.$/, '') : null,
    checkedAt: new Date().toISOString()
  };

  await cache.put(cacheKey, new Response(JSON.stringify(result), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=86400, stale-while-revalidate=86400'
    }
  }));

  return result;
}

async function analyzeDomain(domain, budget = createRequestBudget()) {
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

  const ptrResult = await checkPTR(domain, mxRecords, budget);
  const mtaStsPolicy = mtaStsRecords.some(r => /^\s*v=STSv1(?:\s*;|\s*$)/i.test(r))
    ? await fetchMtaStsPolicy(domain, budget)
    : null;

  // Analyze results
  const spf = await analyzeSPF(domain, spfRecords, budget);
  const dmarc = analyzeDMARC(dmarcDiscovery.records, dmarcDiscovery);
  const dkimResults = await checkDKIMSelectors(domain, spf.providers, mxRecords, budget);
  const dkim = analyzeDKIM(dkimResults);
  const mx = analyzeMX(mxRecords);
  const caa = analyzeCAA(caaRecords);
  const ptr = analyzePTR(ptrResult, mxRecords);
  const transport = analyzeTransportSecurity(mtaStsRecords, tlsRptRecords, mtaStsPolicy, mx.records || []);

  // Calculate score
  const { score, status, confidence, unknown } = calculateScore(spf, dkim, dmarc, mx, caa, transport);
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
    const matching = records.filter(record => /^\s*v=DMARC1(?:\s*;|$)/i.test(record));
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
  const requestBudget = budget || createRequestBudget();
  let last = { status: 'error', rcode: null, provider: null, error: 'No DNS provider responded' };
  for (const provider of DOH_PROVIDERS) {
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
    const err = new Error(status === 'nxdomain' ? 'DNS name does not exist' : 'No records of requested type');
    err.code = status === 'nxdomain' ? 'ENOTFOUND' : 'ENODATA';
    throw err;
  }
  if (status === 'timeout' || status === 'servfail' || status === 'error' || status === 'budget_exceeded') {
    const err = new Error(records.dnsError || `DNS ${status}`);
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

  // Check a slightly wider selector set, prioritising selectors inferred from SPF/MX.
  const selectors = [...new Set([...inferred, ...DKIM_SELECTORS])].slice(0, 14);
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
    const [aRecords, aaaaRecords] = await Promise.all([
      queryDNS(mxHost, 'A', budget),
      queryDNS(mxHost, 'AAAA', budget)
    ]);
    const addresses = [...aRecords, ...aaaaRecords].filter(ip => ipaddr.isValid(ip)).slice(0, 8);
    for (const ip of addresses) {
      const ptrName = reverseDnsName(ip);
      const ptrRecords = await queryDNS(ptrName, 'PTR', budget);
      const ptr = ptrRecords[0]?.replace(/\.$/, '') || null;
      const forwardType = ipaddr.parse(ip).kind() === 'ipv6' ? 'AAAA' : 'A';
      const forward = ptr ? await queryDNS(ptr, forwardType, budget) : [];
      observations.push({ mxHost, ip, ptr, matches: Boolean(ptr && forward.includes(ip)) });
    }
  }
  const first = observations[0];
  return {
    checked: observations.length > 0,
    unknown: !observations.length && budget?.exhausted,
    observations,
    ...(first || { reason: 'Published MX hosts had no A or AAAA addresses to inspect.' })
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

function stripSpfQualifier(part) {
  return String(part || '').replace(/^[+?~-]/, '').toLowerCase();
}

function countVisibleSpfLookups(mechanisms) {
  return mechanisms.reduce((count, part) => {
    const clean = stripSpfQualifier(part);
    if (
      clean === 'a' ||
      clean.startsWith('a:') ||
      clean.startsWith('a/') ||
      clean === 'mx' ||
      clean.startsWith('mx:') ||
      clean.startsWith('mx/') ||
      clean === 'ptr' ||
      clean.startsWith('ptr:') ||
      clean.startsWith('include:') ||
      clean.startsWith('exists:') ||
      clean.startsWith('redirect=')
    ) {
      return count + 1;
    }
    return count;
  }, 0);
}

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
  state ||= { count: 0, voidLookups: [], unknownLookups: [], includes: [], truncated: false, queries: 0 };
  if (!record || depth > 8 || state.queries > 30) {
    state.truncated = true;
    return state;
  }

  const tokens = record.split(/\s+/).filter(Boolean).slice(1);
  state.count += countVisibleSpfLookups(tokens);

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
    state.queries++;
    const redirectRecords = await queryDNS(redirect, 'TXT', budget);
    const redirectSpf = findSpfRecord(redirectRecords)[0];
    if (!redirectSpf && !['ok', 'nodata', 'nxdomain'].includes(redirectRecords?.dnsStatus)) state.unknownLookups.push(redirect);
    else if (!redirectSpf) state.voidLookups.push(redirect);
    else await countSpfDnsLookupsRecursive(redirect, redirectSpf, seen, depth + 1, state, budget);
  }

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
  const dmarcRecords = records.filter(r => /^\s*v=DMARC1(?:\s*;|$)/i.test(r));
  
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

  // Parse policy
  const policy = tags.p || null;

  if (policy === 'none') {
    checks.push({
      status: 'warn',
      title: 'Monitoring mode (p=none)',
      detail: 'Collecting data but not enforcing.',
      recommendation: 'Move to p=quarantine or p=reject.'
    });
  } else if (policy === 'quarantine') {
    checks.push({
      status: 'pass',
      title: 'Quarantine policy',
      detail: 'Suspicious emails sent to spam.',
      recommendation: 'Consider p=reject for maximum protection.'
    });
  } else if (policy === 'reject') {
    checks.push({
      status: 'pass',
      title: 'Reject policy',
      detail: 'Spoofed emails rejected. Maximum protection.',
      recommendation: ''
    });
  } else {
    checks.push({
      status: 'fail',
      title: 'Invalid or missing DMARC policy',
      detail: policy ? `Unknown p= value: ${policy}` : 'No p= tag was found.',
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

  // Check subdomain policy
  if (tags.sp) {
    const weakerSubdomainPolicy = policy !== 'none' && tags.sp === 'none';
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

function parseTagRecord(record) {
  return Object.fromEntries(
    String(record || '')
      .split(';')
      .map(part => part.trim())
      .filter(Boolean)
      .map(part => {
        const idx = part.indexOf('=');
        return idx > 0 ? [part.slice(0, idx).toLowerCase(), part.slice(idx + 1).trim().toLowerCase()] : [part.toLowerCase(), ''];
      })
  );
}

function parseMailtoList(value) {
  if (!value) return [];
  return value
    .split(',')
    .map(item => item.trim())
    .filter(item => item.startsWith('mailto:'))
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
  const partial = results.dnsStatus === 'partial';
  if (partial) {
    checks.push({
      status: 'info',
      title: 'Some DKIM selector lookups were inconclusive',
      detail: 'At least one common selector was found, but other selector lookups did not complete authoritatively.',
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
        detail: keyBits ? `Estimated public key length: ${keyBits} bits.` : 'RSA DKIM key found.',
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

function estimateDkimKeyBits(publicKey) {
  const clean = String(publicKey || '').replace(/[^a-z0-9+/=]/gi, '');
  if (!clean) return null;
  // DKIM p= contains a DER SubjectPublicKeyInfo wrapper as well as the RSA
  // modulus, so raw base64 bit length overstates the actual key strength.
  const length = clean.replace(/=+$/, '').length;
  if (length < 300) return 1024;
  if (length < 550) return 2048;
  if (length < 950) return 4096;
  return Math.round((length * 6) / 1024) * 1024;
}

function analyzeMX(records) {
  if (!records.length) {
    const unknown = ['timeout', 'servfail', 'error', 'budget_exceeded'].includes(records?.dnsStatus);
    return {
      status: unknown ? 'info' : 'info',
      unknown,
      records: [],
      checks: [{
        status: unknown ? 'info' : 'info',
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
    return { priority: Number.parseInt(priority, 10), host: hostParts.join(' ').replace(/\.$/, '') };
  }).sort((a, b) => a.priority - b.priority);
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
      redirect: 'error',
      cf: { cacheTtl: POLICY_CACHE_TTL, cacheEverything: true }
    });
    result.status = response.status;
    result.finalUrl = response.url || url;
    result.redirected = Boolean(response.redirected);
    if (result.finalUrl !== url || result.redirected) {
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

  await cache.put(cacheKey, new Response(JSON.stringify(result), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${POLICY_CACHE_TTL}, stale-while-revalidate=86400`
    }
  }));

  return result;
}

function analyzeTransportSecurity(mtaStsRecords, tlsRptRecords, policyResult, mxRecords = []) {
  const checks = [];
  const transientMtaDns = !['ok', 'nodata', 'nxdomain'].includes(mtaStsRecords?.dnsStatus || 'nodata');
  const transientTlsDns = !['ok', 'nodata', 'nxdomain'].includes(tlsRptRecords?.dnsStatus || 'nodata');
  const mtaMatches = mtaStsRecords.filter(r => /^\s*v=STSv1\s*;/i.test(r));
  const tlsMatches = tlsRptRecords.filter(r => /^\s*v=TLSRPTv1\s*;/i.test(r));
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
      status: transientMtaDns ? 'info' : 'info',
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

function isValidMtaStsMxPattern(value) {
  return /^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(String(value || '')) && !String(value).includes('..');
}

function mtaStsMxMatches(host, pattern) {
  const cleanHost = String(host || '').toLowerCase().replace(/\.$/, '');
  const cleanPattern = String(pattern || '').toLowerCase().replace(/\.$/, '');
  return cleanPattern.startsWith('*.')
    ? cleanHost.endsWith(cleanPattern.slice(1)) && cleanHost !== cleanPattern.slice(2)
    : cleanHost === cleanPattern;
}

function isValidTlsRptUri(value) {
  if (/^mailto:[^@\s,]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(value)) return true;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && Boolean(url.hostname);
  } catch {
    return false;
  }
}

function parsePolicyLines(policy) {
  const tags = {};
  String(policy || '').split(/\r?\n/).forEach(line => {
    const clean = line.trim();
    if (!clean || clean.startsWith('#')) return;
    const idx = clean.indexOf(':') > -1 && clean.indexOf('=') === -1 ? clean.indexOf(':') : clean.indexOf('=');
    if (idx < 1) return;
    const key = clean.slice(0, idx).trim().toLowerCase().replace('-', '_');
    const value = clean.slice(idx + 1).trim();
    if (tags[key]) tags[key] = Array.isArray(tags[key]) ? [...tags[key], value] : [tags[key], value];
    else tags[key] = value;
  });
  return tags;
}

function calculateScore(spf, dkim, dmarc, mx, caa, transport) {
  let score = 0;
  const unknown = [];
  if (spf.unknown || spf.status === 'info') unknown.push('spf');
  if (dkim.unknown || dkim.status === 'info') unknown.push('dkim');
  if (dmarc.unknown || dmarc.status === 'info') unknown.push('dmarc');
  if (mx.unknown || mx.status === 'info' && mx.records?.length === 0 && mx.checks?.some(check => /inconclusive/i.test(check.title))) unknown.push('mx');
  if (caa.unknown) unknown.push('caa');
  if (transport?.unknown) unknown.push('transport');

  // SPF: 0-25. A conventional ~all policy is a modest deduction, not a
  // category-level failure; structural errors remain heavily penalised.
  if (spf.status === 'pass' && !spf.unknown) {
    score += 25;
  } else if (spf.status === 'warn' && !spf.unknown) {
    const softFailOnly = spf.checks?.some(c => c.title === 'Soft fail (~all)') &&
      !spf.checks.some(c => c.status === 'fail');
    score += softFailOnly ? 21 : 18;
  }

  // DKIM: 0-25. Selector discovery is best-effort, so an undiscovered selector
  // is unknown rather than proof that DKIM is disabled. One active key earns
  // most points even when another selector is weak, testing, or retired.
  const usableDkimKeys = (dkim.selectors || []).filter(result => {
    const tags = parseTagRecord(result.record || '');
    return Boolean(tags.p && tags.p.trim());
  }).length;
  if (usableDkimKeys && !dkim.unknown) {
    const hasWeakKey = dkim.checks?.some(c =>
      c.status === 'warn' &&
      (c.title.includes('uses RSA') || c.title.includes('test mode'))
    );
    score += hasWeakKey ? 20 : 25;
  } else if (dkim.status === 'warn' && !dkim.unknown) {
    score += 10;
  }

  // DMARC: 0-35
  if (dmarc.status === 'pass' && !dmarc.unknown) {
    score += dmarc.policy === 'reject' ? 35 : 30;
  } else if (dmarc.status === 'warn' && !dmarc.unknown) score += 15;

  // MX: 0-8
  if (mx.status === 'pass' && !mx.unknown) score += 8;

  // CAA: 0-2. Useful certificate protection, but not email authentication.
  if (caa.status === 'pass' && !caa.unknown) score += 2;

  // MTA-STS/TLS-RPT: 0-5
  if (transport?.status === 'pass' && !transport.unknown) score += 5;
  else if (transport?.status === 'warn' && !transport.unknown) score += 2;

  let status;
  if (score >= 85) status = 'excellent';
  else if (score >= 70) status = 'good';
  else if (score >= 50) status = 'fair';
  else status = 'poor';

  const confidence = unknown.length === 0 ? 'high' : unknown.length <= 2 ? 'medium' : 'low';
  return { score, status, confidence, unknown: [...new Set(unknown)] };
}
