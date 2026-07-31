// Email Security Checker — Cloudflare Workers
// Optimized for 10ms CPU limit with parallel DoH lookups

const { spf: evaluateSpf } = require('mailauth/lib/spf');
const ipaddr = require('ipaddr.js');
const { analyzeEmailHeaders } = require('./header-analyzer');

const DOH_PROVIDERS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/resolve',
  'https://dns.quad9.net/dns-query'
];

const CACHE_TTL = 86400; // 24 hour edge cache
const POLICY_CACHE_TTL = 86400; // 24 hour cache for policy HTTP fetches
const CACHE_VERSION = 'v5-rfc9989';
const DNS_TIMEOUT_MS = 4500;

// Common DKIM selectors to check
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
  fetch(request) {
    return handleRequest(request);
  }
};

async function handleRequest(request) {
  const url = new URL(request.url);
  const securityHeaders = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://cloudflareinsights.com; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };

  if (url.hostname === 'checker.illek.ie') {
    url.hostname = 'email.illek.ie';
    return Response.redirect(url.toString(), 308);
  }
  
  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  if (url.pathname === '/api/health' && request.method === 'GET') {
    return jsonResponse({ ok: true, service: 'email-security-checker', version: '1.0.0' }, 200, securityHeaders);
  }

  if (url.pathname === '/robots.txt' && request.method === 'GET') {
    return new Response('User-agent: *\nAllow: /\nSitemap: https://email.illek.ie/sitemap.xml\n', {
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=86400', ...securityHeaders }
    });
  }

  if (url.pathname === '/sitemap.xml' && request.method === 'GET') {
    return new Response('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://email.illek.ie/</loc><changefreq>monthly</changefreq><priority>1.0</priority></url></urlset>', {
      headers: { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': 'public, max-age=86400', ...securityHeaders }
    });
  }

  // API endpoint
  if (url.pathname === '/api/check' && request.method === 'POST') {
    try {
      const { domain } = await request.json();
      if (!domain) {
        return jsonResponse({ error: 'Domain required' }, 400, corsHeaders);
      }
      
      const cleanDomain = domain.toLowerCase().trim()
        .replace(/^https?:\/\//, '')
        .split('/')[0];
      
      if (!isValidDomain(cleanDomain)) {
        return jsonResponse({ error: 'Invalid domain' }, 400, corsHeaders);
      }

      // Check cache first
      const cacheKey = new Request(`https://cache.internal/${CACHE_VERSION}/${cleanDomain}`);
      const cache = caches.default;
      const cached = await cache.match(cacheKey);
      
      if (cached) {
        return new Response(cached.body, {
          headers: { ...corsHeaders, 'Content-Type': 'application/json', 'X-Cache': 'HIT' }
        });
      }

      const report = await analyzeDomain(cleanDomain);
      const response = jsonResponse(report, 200, corsHeaders);
      
      // Cache successful results for 1 hour
      if (report.overall_score > 0) {
        const cacheResponse = new Response(JSON.stringify(report), {
          headers: { 
            'Content-Type': 'application/json', 
            'Cache-Control': `public, max-age=${CACHE_TTL}, stale-while-revalidate=86400` 
          }
        });
        await cache.put(cacheKey, cacheResponse);
      }
      
      return response;
    } catch (err) {
      return jsonResponse({ error: err.message }, 500, corsHeaders);
    }
  }

  if (url.pathname === '/api/header/analyze' && request.method === 'POST') {
    try {
      const contentLength = Number(request.headers.get('content-length') || 0);
      if (contentLength > 300 * 1024) {
        return jsonResponse({ error: 'Header analysis requests are limited to 256 KB of header content.' }, 413, corsHeaders);
      }
      const { headers = '' } = await request.json();
      return jsonResponse(analyzeEmailHeaders(headers), 200, corsHeaders);
    } catch (err) {
      return jsonResponse({ error: err.message }, 400, corsHeaders);
    }
  }

  if (url.pathname === '/api/header/enrich' && request.method === 'POST') {
    try {
      const { ips = [] } = await request.json();
      const cleanIps = [...new Set(ips)]
        .filter(isPublicIpAddress)
        .slice(0, 10);

      const enriched = await Promise.all(cleanIps.map(enrichIp));
      return jsonResponse({ enriched, limit: 10 }, 200, corsHeaders);
    } catch (err) {
      return jsonResponse({ error: err.message }, 500, corsHeaders);
    }
  }

  if (url.pathname === '/api/spf/inspect' && request.method === 'POST') {
    try {
      const { domain } = await request.json();
      const cleanDomain = normalizeDomain(domain);
      if (!cleanDomain || !isValidDomain(cleanDomain)) {
        return jsonResponse({ error: 'Valid domain required' }, 400, corsHeaders);
      }

      const txtRecords = await queryDNS(cleanDomain, 'TXT');
      const spf = await analyzeSPF(cleanDomain, txtRecords);
      const flatten = await buildSpfFlattenPreview(cleanDomain, spf.record);
      return jsonResponse({ domain: cleanDomain, spf, flatten }, 200, corsHeaders);
    } catch (err) {
      return jsonResponse({ error: err.message }, 500, corsHeaders);
    }
  }

  if (url.pathname === '/api/spf/evaluate' && request.method === 'POST') {
    try {
      const { ip, sender, helo, domain, record } = await request.json();
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
        resolver: record ? makeSpfRecordResolver(cleanDomain, record) : spfDnsResolver,
        maxResolveCount: 10,
        maxVoidCount: 2
      });
      return jsonResponse(result, 200, corsHeaders);
    } catch (err) {
      return jsonResponse({ error: err.message }, 400, corsHeaders);
    }
  }

  if (url.pathname === '/api/records/validate' && request.method === 'POST') {
    try {
      const { type, domain, record } = await request.json();
      const cleanDomain = normalizeDomain(domain);
      if (cleanDomain && !isValidDomain(cleanDomain)) {
        return jsonResponse({ valid: false, errors: ['Enter a valid domain name.'], warnings: [] }, 200, corsHeaders);
      }
      if (type === 'spf') {
        return jsonResponse(await validateSpfRecord(cleanDomain, record), 200, corsHeaders);
      }
      if (type === 'dmarc') {
        return jsonResponse(await validateDmarcRecord(cleanDomain, record), 200, corsHeaders);
      }
      return jsonResponse({ error: 'Record type must be spf or dmarc' }, 400, corsHeaders);
    } catch (err) {
      return jsonResponse({ error: err.message }, 500, corsHeaders);
    }
  }

  if (url.pathname === '/' && request.method === 'GET') {
    return new Response(HTML, {
      headers: { 'Content-Type': 'text/html; charset=utf-8', ...securityHeaders }
    });
  }

  return new Response('Not found', { status: 404, headers: securityHeaders });
}

function makeSpfRecordResolver(domain, record) {
  const normalized = normalizeDomain(domain);
  return async (name, type) => {
    if (type === 'TXT' && normalizeDomain(name) === normalized) return [[String(record)]];
    return spfDnsResolver(name, type);
  };
}

function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers }
  });
}

function isValidDomain(domain) {
  return /^[a-z0-9][a-z0-9-_.]*\.[a-z]{2,}$/.test(domain);
}

function normalizeDomain(value) {
  return String(value || '').toLowerCase().trim()
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .replace(/\.$/, '');
}

async function validateSpfRecord(domain, value) {
  const record = String(value || '').trim().replace(/\s+/g, ' ');
  const errors = [];
  const warnings = [];
  const tokens = record.split(' ').filter(Boolean);

  if (tokens[0] !== 'v=spf1') errors.push('SPF record must begin with v=spf1.');
  if (tokens.filter(token => token.toLowerCase() === 'v=spf1').length !== 1) {
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

  const recursive = domain && tokens[0] === 'v=spf1'
    ? await countSpfDnsLookupsRecursive(domain, record)
    : { count: countVisibleSpfLookups(terms), voidLookups: [], truncated: false };
  if (recursive.count > 10) errors.push(`SPF evaluation requires ${recursive.count} DNS lookups; the maximum is 10.`);
  if (recursive.voidLookups?.length > 2) errors.push(`SPF evaluation produces ${recursive.voidLookups.length} void lookups; no more than 2 are allowed.`);
  else if (recursive.voidLookups?.length) warnings.push(`No SPF record was found for: ${recursive.voidLookups.join(', ')}`);
  if (recursive.truncated) errors.push('Recursive SPF validation could not complete within safety limits.');

  let evaluator = null;
  if (tokens[0] === 'v=spf1' && (domain || isValidDomain('fixture.example'))) {
    try {
      evaluator = await evaluateSpf({
        ip: '192.0.2.1',
        sender: `postmaster@${domain || 'fixture.example'}`,
        helo: domain || 'fixture.example',
        mta: 'email-security-checker',
        resolver: makeSpfRecordResolver(domain || 'fixture.example', record),
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

async function validateDmarcRecord(domain, value) {
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
      const authRecords = await queryDNS(authName, 'TXT');
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

async function enrichIp(ip) {
  const cacheKey = new Request(`https://header-cache.internal/ip/${ip}`);
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) return cached.json();

  const ptrName = reverseDnsName(ip);
  const ptrRecords = await queryDNS(ptrName, 'PTR');
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

async function analyzeDomain(domain) {
  // Run all DNS queries in parallel
  const [
    spfRecords,
    dmarcDiscovery,
    mxRecords,
    caaRecords,
    ptrResult,
    mtaStsRecords,
    tlsRptRecords
  ] = await Promise.all([
    queryDNS(domain, 'TXT'),
    discoverDmarcPolicy(domain),
    queryDNS(domain, 'MX'),
    queryDNS(domain, 'CAA'),
    checkPTR(domain),
    queryDNS(`_mta-sts.${domain}`, 'TXT'),
    queryDNS(`_smtp._tls.${domain}`, 'TXT')
  ]);

  const mtaStsPolicy = mtaStsRecords.some(r => r.startsWith('v=STSv1'))
    ? await fetchMtaStsPolicy(domain)
    : null;

  // Analyze results
  const spf = await analyzeSPF(domain, spfRecords);
  const dmarc = analyzeDMARC(dmarcDiscovery.records, dmarcDiscovery);
  const dkimResults = await checkDKIMSelectors(domain, spf.providers, mxRecords);
  const dkim = analyzeDKIM(dkimResults);
  const mx = analyzeMX(mxRecords);
  const caa = analyzeCAA(caaRecords);
  const ptr = analyzePTR(ptrResult, mxRecords);
  const transport = analyzeTransportSecurity(mtaStsRecords, tlsRptRecords, mtaStsPolicy, mx.records || []);

  // Calculate score
  const { score, status } = calculateScore(spf, dkim, dmarc, mx, caa, transport);

  return {
    domain,
    timestamp: new Date().toISOString(),
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
    overall_score: score,
    overall_status: status
  };
}

async function discoverDmarcPolicy(domain) {
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
    const records = await queryDNS(`_dmarc.${candidate}`, 'TXT');
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

async function queryDNS(name, type) {
  let last = { status: 'error', rcode: null, provider: null, error: 'No DNS provider responded' };
  for (const provider of DOH_PROVIDERS) {
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

async function spfDnsResolver(name, type) {
  const records = await queryDNS(name, type);
  const status = records.dnsStatus;
  if (status === 'nxdomain' || status === 'nodata') {
    const err = new Error(status === 'nxdomain' ? 'DNS name does not exist' : 'No records of requested type');
    err.code = status === 'nxdomain' ? 'ENOTFOUND' : 'ENODATA';
    throw err;
  }
  if (status === 'timeout' || status === 'servfail' || status === 'error') {
    const err = new Error(records.dnsError || `DNS ${status}`);
    err.code = status === 'timeout' ? 'ETIMEOUT' : status === 'servfail' ? 'ESERVFAIL' : 'EREFUSED';
    throw err;
  }
  if (type === 'TXT') return records.map(value => [value]);
  if (type === 'MX') return records.map(value => {
    const [priority, ...exchange] = value.trim().split(/\s+/);
    return { priority: Number(priority), exchange: exchange.join(' ').replace(/\.$/, '') };
  });
  return records.map(value => String(value).replace(/\.$/, ''));
}

async function checkDKIMSelectors(domain, providers = [], mxRecords = []) {
  const inferred = new Set();
  providers.forEach(provider => (PROVIDER_DKIM_SELECTORS[provider] || []).forEach(selector => inferred.add(selector)));

  const mxText = mxRecords.join(' ').toLowerCase();
  if (mxText.includes('protection.outlook.com')) ['selector1', 'selector2'].forEach(selector => inferred.add(selector));
  if (mxText.includes('google.com') || mxText.includes('googlemail.com')) inferred.add('google');

  // Check a slightly wider selector set, prioritising selectors inferred from SPF/MX.
  const selectors = [...new Set([...inferred, ...DKIM_SELECTORS])].slice(0, 14);
  const results = await Promise.all(
    selectors.map(async selector => {
      const resolved = await resolveDkimRecord(`${selector}._domainkey.${domain}`);
      return resolved ? { selector, record: resolved.record, cname: resolved.cname } : null;
    })
  );
  return results.filter(Boolean);
}

async function resolveDkimRecord(name, depth = 0, firstCname = null) {
  if (depth > 4) return null;

  const records = await queryDNS(name, 'TXT');
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
  return resolveDkimRecord(target, depth + 1, firstCname || target);
}

async function checkPTR(domain) {
  // Get MX IPs first, then check PTR
  const mxRecords = await queryDNS(domain, 'MX');
  if (!mxRecords.length) return { checked: false, reason: 'No MX records' };
  if (mxRecords.some(value => /^0\s+\.$/.test(value.trim()))) {
    return { checked: false, notApplicable: true, reason: 'Null MX explicitly declares that this domain does not accept email.' };
  }
  
  const mxHost = mxRecords[0].split(' ').pop().replace(/\.$/, '');
  const aRecords = await queryDNS(mxHost, 'A');
  
  if (!aRecords.length) return { checked: false, reason: 'No A record for MX' };
  
  const ip = aRecords[0];
  const ptrName = ip.split('.').reverse().join('.') + '.in-addr.arpa';
  const ptrRecords = await queryDNS(ptrName, 'PTR');
  const ptr = ptrRecords[0]?.replace(/\.$/, '') || null;
  const forward = ptr ? await queryDNS(ptr, 'A') : [];
  
  return {
    checked: true,
    ip,
    ptr,
    matches: Boolean(ptr && forward.includes(ip)),
    mxHost
  };
}

async function analyzeSPF(domain, records) {
  const spfRecords = records.filter(r => r.startsWith('v=spf1'));
  
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
  const parts = record.split(/\s+/).filter(Boolean);
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
    } else if (['~all', '-all', '?all', '+all'].includes(part) || clean === 'all') {
      mechanisms.push({ type: 'all', value: part });
    }
  }

  // Check all mechanism
  if (record.includes(' -all')) {
    checks.push({
      status: 'pass',
      title: 'Hard fail (-all)',
      detail: 'The domain asserts that unmatched clients are unauthorized; receiver handling remains local policy.',
      recommendation: ''
    });
  } else if (record.includes(' ~all')) {
    checks.push({
      status: 'warn',
      title: 'Soft fail (~all)',
      detail: 'The domain makes a weak assertion that unmatched clients are probably unauthorized; receivers choose how to handle it.',
      recommendation: 'Consider -all for stricter enforcement.'
    });
  } else if (record.includes(' ?all') || record.includes(' +all')) {
    checks.push({
      status: 'fail',
      title: 'Permissive all mechanism',
      detail: `Using ${parts[parts.length-1]} produces pass or neutral for unmatched clients and does not express a useful denial policy.`,
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

  const recursive = await countSpfDnsLookupsRecursive(domain, record);
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

  const status = checks.every(c => c.status === 'pass' || c.status === 'info') ? 'pass' :
                 checks.some(c => c.status === 'fail') ? 'fail' : 'warn';

  return { status, record, checks, mechanisms, providers: providerList, lookupCount, recursiveLookups: recursive };
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

async function countSpfDnsLookupsRecursive(domain, record, seen = new Set(), depth = 0, state = null) {
  state ||= { count: 0, voidLookups: [], includes: [], truncated: false, queries: 0 };
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
    const nestedRecords = await queryDNS(includeDomain, 'TXT');
    const nestedSpf = nestedRecords.find(r => r.startsWith('v=spf1'));
    if (!nestedSpf) {
      state.voidLookups.push(includeDomain);
      continue;
    }
    await countSpfDnsLookupsRecursive(includeDomain, nestedSpf, seen, depth + 1, state);
  }

  if (redirect && !seen.has(redirect)) {
    seen.add(redirect);
    state.includes.push(redirect);
    state.queries++;
    const redirectRecords = await queryDNS(redirect, 'TXT');
    const redirectSpf = redirectRecords.find(r => r.startsWith('v=spf1'));
    if (!redirectSpf) state.voidLookups.push(redirect);
    else await countSpfDnsLookupsRecursive(redirect, redirectSpf, seen, depth + 1, state);
  }

  return state;
}

async function buildSpfFlattenPreview(domain, record) {
  if (!record) {
    return {
      available: false,
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
    incomplete: false
  };
  const rootTokens = record.split(/\s+/).filter(Boolean).slice(1);
  const finalAll = [...rootTokens].reverse().find(token => stripSpfQualifier(token) === 'all') || '~all';
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

  const flattenedRecord = ['v=spf1', ...mechanisms, finalAll].join(' ');
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
  const validation = await validateSpfRecord(domain, flattenedRecord);
  context.warnings.push(...validation.warnings);

  return {
    available: true,
    safeToPublish: !context.incomplete && validation.valid,
    record: flattenedRecord,
    originalRecord: record,
    originalLookups,
    flattenedLookups,
    characterCount: flattenedRecord.length,
    sources: [...context.sources.entries()].map(([source, tokens]) => ({ source, mechanisms: tokens })),
    warnings: [...new Set(context.warnings)],
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
        context.warnings.push(`Preserved ${token}: non-pass IP mechanisms cannot be substituted through include without changing SPF results.`);
      }
      output.push({ token, source: domain });
      continue;
    }
    if (clean.startsWith('redirect=')) {
      context.incomplete = true;
      context.warnings.push(`Preserved ${token}: redirect changes the terminal result and is not flattened without a full equivalence proof.`);
      output.push({ token, source: domain });
      continue;
    }
    if (clean.startsWith('include:')) {
      const target = clean.slice(clean.indexOf(clean.startsWith('include:') ? ':' : '=') + 1);
      if (token.includes('%') || (clean.startsWith('include:') && qualifier !== '+')) {
        context.incomplete = true;
        context.warnings.push(`Preserved ${token}: macros and qualified includes cannot be safely flattened.`);
        output.push({ token, source: domain });
        continue;
      }
      if (context.seen.has(target)) {
        context.incomplete = true;
        context.warnings.push(`Preserved ${token}: recursive SPF cycle detected.`);
        output.push({ token, source: domain });
        continue;
      }
      context.seen.add(target);
      context.queries++;
      const records = await queryDNS(target, 'TXT');
      const nested = records.find(value => value.startsWith('v=spf1'));
      if (!nested) {
        context.incomplete = true;
        context.warnings.push(`Preserved ${token}: ${target} did not return an SPF record.`);
        output.push({ token, source: domain });
      } else {
        output.push(...await expandSpfForFlatten(target, nested, context, depth + 1, false));
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
      context.warnings.push(`Preserved ${token}: dynamic ${clean.split(/[:/]/)[0]} mechanisms are not frozen into IP addresses.`);
      output.push({ token, source: domain });
      continue;
    }

    if (!clean.startsWith('exp=')) {
      context.incomplete = true;
      context.warnings.push(`Preserved unrecognised SPF term ${token}.`);
      output.push({ token, source: domain });
    }
  }
  return output;
}

function analyzeDMARC(records, discovery = {}) {
  const dmarcRecords = records.filter(r => /^\s*v=DMARC1(?:\s*;|$)/i.test(r));
  
  if (!dmarcRecords.length) {
    return {
      status: 'fail',
      record: null,
      checks: [{
        status: 'fail',
        title: discovery.dns?.status && !['ok', 'nodata', 'nxdomain'].includes(discovery.dns.status)
          ? 'DMARC lookup inconclusive'
          : 'No DMARC policy discovered',
        detail: discovery.dns?.status && !['ok', 'nodata', 'nxdomain'].includes(discovery.dns.status)
          ? `DNS result: ${discovery.dns.status}. Absence cannot be concluded.`
          : 'RFC 9989 discovery found no policy on the domain or its parent policy domains.',
        recommendation: 'Create DMARC record to prevent spoofing.'
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
    return {
      status: 'warn',
      selectors: [],
      checks: [{
        status: 'warn',
        title: 'No DKIM records found',
        detail: 'Could not find DKIM keys for common selectors.',
        recommendation: 'DKIM may use custom selectors or not be configured.'
      }]
    };
  }

  const checks = [{
    status: 'pass',
    title: `Found ${results.length} DKIM key(s)`,
    detail: `Selectors: ${results.map(r => r.selector).join(', ')}`,
    recommendation: ''
  }];

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
    return {
      status: 'fail',
      records: [],
      checks: [{
        status: 'fail',
        title: 'No MX records',
        detail: 'Domain cannot receive email.',
        recommendation: 'Configure MX records for email delivery.'
      }]
    };
  }

  const mx = records.map(r => {
    const [priority, host] = r.split(' ');
    return { priority: parseInt(priority), host: host.replace(/\.$/, '') };
  }).sort((a, b) => a.priority - b.priority);
  const nullMx = mx.length === 1 && mx[0].priority === 0 && (mx[0].host === '' || mx[0].host === '.');
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
    return {
      status: 'warn',
      records: [],
      checks: [{
        status: 'warn',
        title: 'No CAA records',
        detail: 'Any CA can issue certificates for this domain.',
        recommendation: 'Add CAA records to restrict certificate issuance.'
      }]
    };
  }

  const issuers = records.map(r => r.split(' ').pop().replace(/"/g, ''));
  
  return {
    status: 'pass',
    records: issuers,
    checks: [{
      status: 'pass',
      title: 'CAA configured',
      detail: `Allowed: ${issuers.join(', ')}`,
      recommendation: ''
    }]
  };
}

function analyzePTR(result, mxRecords) {
  if (!result.checked) {
    return {
      status: 'warn',
      ...result,
      checks: [{
        status: 'warn',
        title: result.notApplicable ? 'Inbound reverse DNS not applicable' : 'Inbound MX reverse DNS not checked',
        detail: result.reason,
        recommendation: ''
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
      detail: `Observed ${result.ip} → ${result.ptr}; MX host ${result.mxHost}. This is an inbound-host observation, not a sending-domain deliverability guarantee.`,
      recommendation: result.matches ? '' : 'Ask the mail-hosting provider to review forward-confirmed reverse DNS for this MX IP.'
    }]
  };
}

async function fetchMtaStsPolicy(domain) {
  const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  const cacheKey = new Request(`https://policy-cache.internal/mta-sts/${domain}`);
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) return cached.json();

  const result = { fetched: false, url, status: null, policy: null, error: null };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DNS_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      cf: { cacheTtl: POLICY_CACHE_TTL, cacheEverything: true }
    });
    result.status = response.status;
    result.contentType = response.headers.get('content-type');
    if (response.ok) {
      result.fetched = true;
      result.policy = (await response.text()).slice(0, 4000);
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
      status: 'info',
      title: 'No MTA-STS DNS record',
      detail: 'Inbound SMTP transport policy is not advertised.',
      recommendation: 'Add MTA-STS if the domain receives business email and you want downgrade protection.'
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
      recommendation: mode === 'enforce' && currentMxCovered ? '' : 'Ensure every inbound MX is covered, then move to mode=enforce.'
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
      status: 'warn',
      title: 'MTA-STS policy not reachable',
      detail: policyResult?.status ? `HTTP status ${policyResult.status}` : 'Could not fetch the HTTPS policy file.',
      recommendation: 'Publish https://mta-sts.domain/.well-known/mta-sts.txt with a valid certificate.'
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
      status: mtaStsRecord ? 'warn' : 'info',
      title: 'No TLS-RPT record',
      detail: 'TLS delivery reports are not configured.',
      recommendation: 'Add _smtp._tls TXT with rua=mailto:tlsrpt@yourdomain.com to monitor TLS delivery issues.'
    });
  }

  const status = checks.some(c => c.status === 'fail') ? 'fail' :
                 checks.some(c => c.status === 'warn') ? 'warn' :
                 checks.some(c => c.status === 'pass') ? 'pass' : 'info';

  return {
    status,
    mtaStsRecord,
    tlsRptRecord,
    policy: policyResult,
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

  // SPF: 0-25. A conventional ~all policy is a modest deduction, not a
  // category-level failure; structural errors remain heavily penalised.
  if (spf.status === 'pass') {
    score += 25;
  } else if (spf.status === 'warn') {
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
  if (usableDkimKeys) {
    const hasWeakKey = dkim.checks?.some(c =>
      c.status === 'warn' &&
      (c.title.includes('uses RSA') || c.title.includes('test mode'))
    );
    score += hasWeakKey ? 20 : 25;
  } else if (dkim.status === 'warn') {
    score += 10;
  }

  // DMARC: 0-35
  if (dmarc.status === 'pass') {
    score += dmarc.policy === 'reject' ? 35 : 30;
  } else if (dmarc.status === 'warn') score += 15;

  // MX: 0-8
  if (mx.status === 'pass') score += 8;

  // CAA: 0-2. Useful certificate protection, but not email authentication.
  if (caa.status === 'pass') score += 2;

  // MTA-STS/TLS-RPT: 0-5
  if (transport?.status === 'pass') score += 5;
  else if (transport?.status === 'warn') score += 2;

  let status;
  if (score >= 85) status = 'excellent';
  else if (score >= 70) status = 'good';
  else if (score >= 50) status = 'fair';
  else status = 'poor';

  return { score, status };
}

// Inline HTML UI
const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="theme-color" content="#0a0a0f">
  <meta name="description" content="Check SPF, DKIM, DMARC, mail routing and transport security, inspect SPF lookup paths, build safer DNS records, and interpret email headers.">
  <meta property="og:title" content="Email Security Analyzer">
  <meta property="og:description" content="Evidence-led email authentication checks, SPF tools, DNS record guidance, and message header analysis.">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://email.illek.ie/">
  <meta name="twitter:card" content="summary">
  <link rel="canonical" href="https://email.illek.ie/">
  <title>Email Security Analyzer — SPF, DKIM, DMARC & Header Review</title>
  <style>
    :root{--bg:#0a0a0f;--bg-card:#12121a;--bg-elevated:#1a1a25;--border:#2a2a3a;--text:#e8e8f0;--text-muted:#8888a0;--accent:#6366f1;--accent-hover:#818cf8;--success:#22c55e;--warning:#eab308;--error:#ef4444;--info:#3b82f6}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}
    .container{max-width:960px;margin:0 auto;padding:40px 20px}
    .skip-link{position:fixed;left:16px;top:12px;z-index:1000;transform:translateY(-150%);padding:10px 14px;border-radius:8px;background:#fff;color:#111;font-weight:700;text-decoration:none}
    .skip-link:focus{transform:none}
    .sr-only{position:absolute!important;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
    .header{text-align:center;margin-bottom:48px}
    .logo{width:64px;height:64px;background:linear-gradient(135deg,var(--accent),#8b5cf6);border:1px solid rgba(255,255,255,.15);border-radius:18px;display:inline-flex;align-items:center;justify-content:center;margin-bottom:16px;box-shadow:0 14px 40px rgba(99,102,241,.24)}
    .logo svg{width:34px;height:34px;fill:none;stroke:#fff;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
    .header h1{font-size:32px;font-weight:700;letter-spacing:-0.02em;margin-bottom:8px}
    .header p{color:var(--text-muted);font-size:16px}
    .capability-strip{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;margin:0 0 32px;border:1px solid var(--border);border-radius:14px;overflow:hidden;background:var(--border)}
    .capability{padding:14px 16px;background:var(--bg-card)}
    .capability strong{display:block;font-size:13px;margin-bottom:2px}
    .capability span{display:block;color:var(--text-muted);font-size:12px}
    .search-form{display:flex;gap:12px;margin-bottom:48px}
    .search-input{flex:1;padding:16px 20px;font-size:16px;background:var(--bg-card);border:2px solid var(--border);border-radius:12px;color:var(--text);outline:none;transition:border-color .2s,box-shadow .2s}
    .search-input:focus{border-color:var(--accent);box-shadow:0 0 0 4px rgba(99,102,241,.15)}
    .search-input::placeholder{color:var(--text-muted)}
    .btn{padding:16px 32px;font-size:16px;font-weight:600;background:var(--accent);color:#fff;border:none;border-radius:12px;cursor:pointer;transition:background .2s,transform .1s}
    .btn:hover{background:var(--accent-hover);transform:translateY(-1px)}
    .btn:active{transform:translateY(0)}
    .btn:disabled{opacity:.6;cursor:not-allowed}
    .loading{display:none;text-align:center;padding:60px}
    .loading.active{display:block}
    .spinner{width:48px;height:48px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 16px}
    @keyframes spin{to{transform:rotate(360deg)}}
    .results{display:none}
    .results.active{display:block}
    .score-card{background:var(--bg-card);border:1px solid var(--border);border-radius:20px;padding:32px;text-align:center;margin-bottom:24px}
    .score-value{font-size:72px;font-weight:800;line-height:1;margin-bottom:8px}
    .score-value.excellent,.score-value.good{color:var(--success)}
    .score-value.fair{color:var(--warning)}
    .score-value.poor{color:var(--error)}
    .score-label{font-size:18px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.1em}
    .score-domain{font-size:14px;color:var(--text-muted);margin-top:16px;font-family:monospace}
    .section{background:var(--bg-card);border:1px solid var(--border);border-radius:16px;margin-bottom:16px;overflow:hidden}
    .section-header{display:flex;align-items:center;gap:12px;padding:20px 24px;cursor:pointer;user-select:none;transition:background .2s}
    .section-header:hover{background:var(--bg-elevated)}
    .section-icon{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px}
    .section-icon.spf{background:rgba(34,197,94,.15)}
    .section-icon.dkim{background:rgba(99,102,241,.15)}
    .section-icon.dmarc{background:rgba(234,179,8,.15)}
    .section-icon.mx{background:rgba(59,130,246,.15)}
    .section-icon.caa{background:rgba(168,85,247,.15)}
    .section-icon.ptr{background:rgba(236,72,153,.15)}
    .section-icon.transport{background:rgba(14,165,233,.15)}
    .section-title{flex:1;font-size:18px;font-weight:600}
    .section-status{padding:6px 12px;border-radius:20px;font-size:13px;font-weight:600;text-transform:uppercase}
    .section-status.pass{background:rgba(34,197,94,.2);color:var(--success)}
    .section-status.warn{background:rgba(234,179,8,.2);color:var(--warning)}
    .section-status.fail{background:rgba(239,68,68,.2);color:var(--error)}
    .section-status.info{background:rgba(59,130,246,.2);color:var(--info)}
    .section-chevron{color:var(--text-muted);transition:transform .2s}
    .section.expanded .section-chevron{transform:rotate(180deg)}
    .section-content{display:none;padding:0 24px 24px;border-top:1px solid var(--border)}
    .section.expanded .section-content{display:block}
    .record-box{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:16px;margin:16px 0;font-family:'JetBrains Mono',monospace;font-size:13px;word-break:break-all;color:var(--text-muted)}
    .record-box strong{color:var(--text);display:block;margin-bottom:8px;font-family:inherit}
    .check-item{display:flex;gap:12px;padding:16px 0;border-bottom:1px solid var(--border)}
    .check-item:last-child{border-bottom:none}
    .check-icon{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0;margin-top:2px}
    .check-icon.pass{background:rgba(34,197,94,.2);color:var(--success)}
    .check-icon.warn{background:rgba(234,179,8,.2);color:var(--warning)}
    .check-icon.fail{background:rgba(239,68,68,.2);color:var(--error)}
    .check-icon.info{background:rgba(59,130,246,.2);color:var(--info)}
    .check-content{flex:1}
    .check-title{font-weight:600;margin-bottom:4px}
    .check-detail{color:var(--text-muted);font-size:14px;margin-bottom:8px}
    .check-recommendation{background:var(--bg-elevated);border-left:3px solid var(--accent);padding:12px 16px;border-radius:0 8px 8px 0;font-size:14px;color:var(--text-muted)}
    .check-recommendation strong{color:var(--accent);display:block;margin-bottom:4px;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
    .mx-table{width:100%;border-collapse:collapse;margin-top:16px}
    .mx-table th,.mx-table td{padding:12px 16px;text-align:left;border-bottom:1px solid var(--border)}
    .mx-table th{color:var(--text-muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em;font-weight:600}
    .mx-table tr:last-child td{border-bottom:none}
    .error-card{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:16px;padding:32px;text-align:center}
    .error-card h2{color:var(--error);margin-bottom:8px}
    .tool-card{background:var(--bg-card);border:1px solid var(--border);border-radius:20px;padding:24px;margin-bottom:32px}
    .tool-card h2{font-size:20px;margin-bottom:6px}
    .tool-card p{color:var(--text-muted);font-size:14px;margin-bottom:16px}
    .header-input{width:100%;min-height:220px;resize:vertical;padding:16px 20px;font-size:14px;line-height:1.5;background:var(--bg);border:2px solid var(--border);border-radius:12px;color:var(--text);outline:none;font-family:'JetBrains Mono','SFMono-Regular',Consolas,monospace}
    .header-input:focus{border-color:var(--accent);box-shadow:0 0 0 4px rgba(99,102,241,.15)}
    .header-input-label{display:block;font-size:14px;font-weight:600;margin-bottom:8px}
    .privacy-note{display:flex;gap:9px;align-items:flex-start;color:var(--text-muted);font-size:13px;margin:10px 0 0}
    .privacy-note strong{color:var(--text)}
    .header-actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:14px}
    .btn.secondary{background:var(--bg-elevated);border:1px solid var(--border)}
    .btn.secondary:hover{background:#232333}
    .header-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:20px 0}
    .summary-tile{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px}
    .summary-tile span{display:block;color:var(--text-muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px}
    .summary-tile strong{font-size:18px}
    .hop-list{display:grid;gap:10px;margin-top:12px}
    .hop-item{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:14px}
    .hop-item code{color:var(--text);word-break:break-word}
    .hop-route{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:7px 0}
    .hop-meta{display:flex;gap:8px;flex-wrap:wrap;color:var(--text-muted);font-size:12px}
    .trust-banner{padding:15px 17px;border-radius:12px;margin:18px 0;border:1px solid var(--border);background:var(--bg)}
    .trust-banner.pass{border-color:rgba(34,197,94,.35)}.trust-banner.warn{border-color:rgba(234,179,8,.35)}.trust-banner.fail{border-color:rgba(239,68,68,.4)}
    .trust-banner strong{display:block;margin-bottom:3px}.trust-banner span{color:var(--text-muted);font-size:13px}
    .muted{color:var(--text-muted)}
    .tool-nav{display:flex;gap:8px;padding:6px;background:var(--bg-card);border:1px solid var(--border);border-radius:14px;margin:-20px 0 32px;overflow-x:auto}
    .tool-tab{flex:1;min-width:max-content;padding:11px 14px;border:0;border-radius:9px;background:transparent;color:var(--text-muted);font-weight:600;cursor:pointer}
    .tool-tab:hover{color:var(--text);background:var(--bg-elevated)}
    .tool-tab.active{background:var(--accent);color:#fff}
    .tool-panel{display:none}
    .tool-panel.active{display:block}
    .panel-heading{margin-bottom:22px}
    .panel-heading h2{font-size:24px;margin-bottom:4px}
    .panel-heading p,.field-help{color:var(--text-muted);font-size:14px}
    .form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
    .field{display:grid;gap:7px}
    .field.full{grid-column:1/-1}
    .field label{font-size:13px;font-weight:600;color:var(--text-muted)}
    .field input,.field select{width:100%;padding:12px 14px;background:var(--bg);border:1px solid var(--border);border-radius:9px;color:var(--text);font-size:14px}
    .provider-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}
    .provider-option{display:flex;align-items:center;gap:9px;padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:9px;font-size:14px}
    .provider-option input{width:auto}
    .output-card{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px;margin-top:16px}
    .output-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}
    .output-head strong{font-size:14px}
    .copy-btn{padding:7px 11px;border:1px solid var(--border);border-radius:7px;background:var(--bg-elevated);color:var(--text);cursor:pointer}
    .dns-value{font:13px 'JetBrains Mono',monospace;color:var(--text);word-break:break-all;white-space:pre-wrap}
    .notice{padding:13px 15px;border:1px solid rgba(234,179,8,.35);background:rgba(234,179,8,.08);border-radius:10px;color:#d7ca91;font-size:13px;margin:14px 0}
    .notice.good{border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.08);color:#a7d9b8}
    .inspector-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px}
    .source-group{padding:12px 0;border-bottom:1px solid var(--border)}
    .source-group:last-child{border-bottom:0}
    .source-group code{display:block;color:var(--accent-hover);margin-bottom:5px}
    .source-group span{font:12px 'JetBrains Mono',monospace;color:var(--text-muted);word-break:break-all}
    .builder-tabs{display:flex;gap:8px;margin-bottom:18px}
    .builder-tab{padding:9px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text-muted);cursor:pointer}
    .builder-tab.active{color:#fff;border-color:var(--accent);background:rgba(99,102,241,.18)}
    .builder-pane{display:none}.builder-pane.active{display:block}
    .footer{text-align:center;margin-top:48px;padding-top:24px;border-top:1px solid var(--border);color:var(--text-muted);font-size:14px}
    .section-header:is(button){width:100%;border:0;color:inherit;font:inherit;text-align:left;background:transparent}
    @media(max-width:640px){.search-form{flex-direction:column}.score-value{font-size:56px}.section-header{padding:16px}.header-summary,.inspector-summary,.form-grid,.provider-grid,.capability-strip{grid-template-columns:1fr}.tool-nav{display:grid;grid-template-columns:1fr 1fr;overflow:visible}.tool-tab{font-size:13px;min-width:0}.header-actions .btn{flex:1;padding:14px 12px}.tool-card{padding:16px}.container{padding:28px 20px}.header{margin-bottom:30px}.capability-strip{gap:1px}}
    @media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
  </style>
</head>
<body>
  <a class="skip-link" href="#main-content">Skip to email tools</a>
  <div class="container">
    <header class="header">
      <div class="logo" aria-hidden="true"><svg viewBox="0 0 40 40"><path d="M20 4 33 9v10c0 8.3-5.2 14.2-13 17-7.8-2.8-13-8.7-13-17V9l13-5Z"/><path d="m13.5 20 4.2 4.2L27 14.8"/></svg></div>
      <h1>Email Security Analyzer</h1>
      <p>Understand what your domain publishes, what a receiver reported, and what to fix next.</p>
    </header>
    <main id="main-content">
    <div class="capability-strip" aria-label="Available analysis">
      <div class="capability"><strong>Domain posture</strong><span>SPF, DKIM, DMARC, MX and transport</span></div>
      <div class="capability"><strong>SPF engineering</strong><span>Lookup paths, validation and guarded guidance</span></div>
      <div class="capability"><strong>Message evidence</strong><span>Authentication results and delivery hops</span></div>
    </div>
    <nav class="tool-nav" aria-label="Email security tools" role="tablist">
      <button class="tool-tab active" id="tab-domain" data-tool="domain" role="tab" aria-controls="panel-domain" aria-selected="true">Check Domain</button>
      <button class="tool-tab" id="tab-spf" data-tool="spf" role="tab" aria-controls="panel-spf" aria-selected="false" tabindex="-1">SPF Inspector</button>
      <button class="tool-tab" id="tab-builder" data-tool="builder" role="tab" aria-controls="panel-builder" aria-selected="false" tabindex="-1">Record Builder</button>
      <button class="tool-tab" id="tab-headers" data-tool="headers" role="tab" aria-controls="panel-headers" aria-selected="false" tabindex="-1">Header Analyzer</button>
    </nav>

    <section class="tool-panel active" id="panel-domain" role="tabpanel" aria-labelledby="tab-domain">
      <div class="panel-heading"><h2>Check Domain</h2><p>Audit SPF, DKIM, DMARC, mail routing and transport security.</p></div>
      <form class="search-form" id="checkForm">
        <label class="sr-only" for="domainInput">Domain to check</label>
        <input type="text" class="search-input" id="domainInput" placeholder="Enter domain (e.g., example.com)" inputmode="url" autocomplete="off" spellcheck="false" required>
        <button type="submit" class="btn" id="checkBtn">Check Security</button>
      </form>
      <div class="loading" id="loading"><div class="spinner"></div><p>Analyzing DNS records...</p></div>
      <div class="results" id="results"></div>
    </section>

    <section class="tool-panel" id="panel-spf" role="tabpanel" aria-labelledby="tab-spf">
      <div class="panel-heading"><h2>SPF Inspector</h2><p>Trace nested includes, identify lookup pressure, and generate a guarded flattening preview.</p></div>
      <form class="search-form" id="spfForm">
        <label class="sr-only" for="spfDomainInput">Domain whose SPF record should be inspected</label>
        <input type="text" class="search-input" id="spfDomainInput" placeholder="Enter domain to inspect" inputmode="url" autocomplete="off" spellcheck="false" required>
        <button type="submit" class="btn" id="spfBtn">Inspect SPF</button>
      </form>
      <div class="loading" id="spfLoading"><div class="spinner"></div><p>Resolving the SPF include tree...</p></div>
      <div class="results" id="spfResults"></div>
    </section>

    <section class="tool-panel" id="panel-builder" role="tabpanel" aria-labelledby="tab-builder">
      <div class="panel-heading"><h2>Record Builder</h2><p>Create review-ready SPF records and plan a staged DMARC rollout.</p></div>
      <section class="tool-card">
        <div class="builder-tabs">
          <button class="builder-tab active" data-builder="spf">SPF Builder</button>
          <button class="builder-tab" data-builder="dmarc">DMARC Planner</button>
        </div>
        <div class="builder-pane active" id="builder-spf">
          <div class="form-grid">
            <div class="field full"><label>Domain</label><input id="builderDomain" placeholder="example.com"></div>
            <div class="field full"><label>Authorised email services</label><div class="provider-grid" id="providerOptions">
              <label class="provider-option"><input type="checkbox" value="include:spf.protection.outlook.com"> Microsoft 365</label>
              <label class="provider-option"><input type="checkbox" value="include:_spf.google.com"> Google Workspace</label>
              <label class="provider-option"><input type="checkbox" value="include:sendgrid.net"> SendGrid</label>
              <label class="provider-option"><input type="checkbox" value="include:mailgun.org"> Mailgun</label>
              <label class="provider-option"><input type="checkbox" value="include:amazonses.com"> Amazon SES</label>
              <label class="provider-option"><input type="checkbox" value="include:servers.mcsv.net"> Mailchimp</label>
            </div></div>
            <div class="field full"><label>Additional mechanisms</label><input id="spfCustom" placeholder="ip4:203.0.113.10 include:other-provider.example"><span class="field-help">Space-separated ip4, ip6, include, a or mx mechanisms.</span></div>
            <div class="field"><label>Policy</label><select id="spfPolicy"><option value="~all">Soft fail (~all) — migration</option><option value="-all">Hard fail (-all) — enforced</option></select></div>
            <div class="field"><label>Current rollout stage</label><select id="spfStage"><option value="testing">Testing senders</option><option value="confirmed">All senders confirmed</option></select></div>
          </div>
          <div class="notice">Confirm every legitimate sending service before publishing. An omitted sender may fail SPF.</div>
          <div id="spfBuilderOutput"></div>
        </div>
        <div class="builder-pane" id="builder-dmarc">
          <div class="form-grid">
            <div class="field full"><label>Domain</label><input id="dmarcDomain" placeholder="example.com"></div>
            <div class="field"><label>Rollout stage</label><select id="dmarcStage"><option value="none">1 — Monitor</option><option value="quarantine">2 — Quarantine</option><option value="reject">3 — Reject</option></select></div>
            <div class="field"><label>Policy state (RFC 9989)</label><select id="dmarcTesting"><option value="n">Production (t=n)</option><option value="y">Testing (t=y)</option></select></div>
            <div class="field full"><label>Aggregate report mailbox</label><input id="dmarcRua" placeholder="dmarc@example.com"></div>
            <div class="field"><label>Subdomain policy</label><select id="dmarcSubdomain"><option value="">Inherit main policy</option><option value="none">Monitor</option><option value="quarantine">Quarantine</option><option value="reject">Reject</option></select></div>
            <div class="field"><label>Alignment</label><select id="dmarcAlignment"><option value="relaxed">Relaxed — recommended initially</option><option value="strict">Strict</option></select></div>
          </div>
          <div class="notice">Start with monitoring, review aggregate reports, then increase enforcement after legitimate senders align.</div>
          <div id="dmarcBuilderOutput"></div>
        </div>
      </section>
    </section>

    <section class="tool-panel" id="panel-headers" role="tabpanel" aria-labelledby="tab-headers">
      <div class="panel-heading"><h2>Header Analyzer</h2><p>Interpret receiver-reported authentication, sender alignment, and the delivery chain without overstating certainty.</p></div>
      <section class="tool-card">
        <label class="header-input-label" for="headerInput">Complete message headers</label>
        <textarea class="header-input" id="headerInput" placeholder="Paste the original headers from your mailbox provider…" spellcheck="false" aria-describedby="headerPrivacy"></textarea>
        <div class="privacy-note" id="headerPrivacy"><span>🔒</span><span><strong>Stateless analysis.</strong> Headers are sent to this Cloudflare Worker for this request only; this application does not store them. Hop enrichment separately submits up to 10 public IP addresses for PTR lookup.</span></div>
        <div class="header-actions">
          <button type="button" class="btn" id="analyzeHeadersBtn">Analyze Headers</button>
          <button type="button" class="btn secondary" id="enrichHeadersBtn" disabled>Enrich Hops</button>
          <button type="button" class="btn secondary" id="clearHeadersBtn">Clear</button>
        </div>
        <div id="headerResults" aria-live="polite"></div>
      </section>
    </section>
    </main>
    <footer class="footer">
      <p>Independent email security diagnostics. Results are guidance, not proof of deliverability.</p>
      <p>© 2026 Illek. All rights reserved. <a href="https://tools.illek.ie/privacy" style="color:var(--accent-hover)">Privacy</a></p>
    </footer>
  </div>
  <script>
    const form=document.getElementById('checkForm'),input=document.getElementById('domainInput'),btn=document.getElementById('checkBtn'),loading=document.getElementById('loading'),results=document.getElementById('results');
    const headerInput=document.getElementById('headerInput'),headerResults=document.getElementById('headerResults'),analyzeHeadersBtn=document.getElementById('analyzeHeadersBtn'),enrichHeadersBtn=document.getElementById('enrichHeadersBtn'),clearHeadersBtn=document.getElementById('clearHeadersBtn');
    const spfForm=document.getElementById('spfForm'),spfInput=document.getElementById('spfDomainInput'),spfBtn=document.getElementById('spfBtn'),spfLoading=document.getElementById('spfLoading'),spfResults=document.getElementById('spfResults');
    let lastHeaderAnalysis=null,lastDomainReport=null;
    function selectTool(name,pushHash=true){document.querySelectorAll('.tool-tab').forEach(x=>{const active=x.dataset.tool===name;x.classList.toggle('active',active);x.setAttribute('aria-selected',String(active));x.tabIndex=active?0:-1});document.querySelectorAll('.tool-panel').forEach(x=>{const active=x.id==='panel-'+name;x.classList.toggle('active',active);x.hidden=!active});if(pushHash)history.replaceState(null,'','#'+name);if(name==='domain')input.focus();if(name==='spf')spfInput.focus();if(name==='headers')headerInput.focus()}
    document.querySelectorAll('.tool-tab').forEach(x=>x.addEventListener('click',()=>selectTool(x.dataset.tool)));
    document.querySelector('.tool-nav').addEventListener('keydown',event=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;const tabs=[...document.querySelectorAll('.tool-tab')];const current=tabs.indexOf(document.activeElement);let next=event.key==='Home'?0:event.key==='End'?tabs.length-1:event.key==='ArrowRight'?(current+1)%tabs.length:(current-1+tabs.length)%tabs.length;event.preventDefault();selectTool(tabs[next].dataset.tool);tabs[next].focus()});
    selectTool(['domain','spf','builder','headers'].includes(location.hash.slice(1))?location.hash.slice(1):'domain',false);
    document.querySelectorAll('.builder-tab').forEach(x=>x.addEventListener('click',()=>{document.querySelectorAll('.builder-tab').forEach(y=>y.classList.toggle('active',y===x));document.querySelectorAll('.builder-pane').forEach(y=>y.classList.toggle('active',y.id==='builder-'+x.dataset.builder))}));
    form.addEventListener('submit',async e=>{e.preventDefault();const domain=input.value.trim();if(!domain)return;loading.classList.add('active');results.classList.remove('active');btn.disabled=true;try{const r=await fetch('/api/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain})});const d=await r.json();d.error?showError(d.error):showResults(d)}catch{showError('Failed to analyze domain')}finally{loading.classList.remove('active');btn.disabled=false}});
    spfForm.addEventListener('submit',async e=>{e.preventDefault();const domain=spfInput.value.trim();if(!domain)return;spfLoading.classList.add('active');spfResults.classList.remove('active');spfBtn.disabled=true;try{const r=await fetch('/api/spf/inspect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain})});const d=await r.json();d.error?showSpfError(d.error):showSpfInspector(d)}catch{showSpfError('Failed to inspect SPF')}finally{spfLoading.classList.remove('active');spfBtn.disabled=false}});
    headerInput.addEventListener('input',()=>{headerResults.innerHTML='';lastHeaderAnalysis=null;enrichHeadersBtn.disabled=true});
    analyzeHeadersBtn.addEventListener('click',runHeaderAnalysis);
    async function runHeaderAnalysis(){const raw=headerInput.value.trim();if(!raw){showHeaderError('Paste the complete message headers first.');return}analyzeHeadersBtn.disabled=true;analyzeHeadersBtn.textContent='Analyzing…';headerResults.innerHTML='<div class="loading active" style="padding:32px"><div class="spinner"></div><p>Interpreting receiver results and delivery hops…</p></div>';try{const r=await fetch('/api/header/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({headers:raw})});const d=await r.json();if(!r.ok||d.error)throw new Error(d.error||'Header analysis failed');lastHeaderAnalysis=d;showHeaderAnalysis(d);enrichHeadersBtn.disabled=!d.ips.length}catch(err){showHeaderError(err.message||'Header analysis failed')}finally{analyzeHeadersBtn.disabled=false;analyzeHeadersBtn.textContent='Analyze Headers'}}
    clearHeadersBtn.addEventListener('click',()=>{headerInput.value='';headerResults.innerHTML='';lastHeaderAnalysis=null;enrichHeadersBtn.disabled=true});
    enrichHeadersBtn.addEventListener('click',async()=>{if(!lastHeaderAnalysis||!lastHeaderAnalysis.ips.length)return;enrichHeadersBtn.disabled=true;enrichHeadersBtn.textContent='Enriching…';try{const r=await fetch('/api/header/enrich',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ips:lastHeaderAnalysis.ips})});const d=await r.json();if(!r.ok||d.error)throw new Error(d.error||'PTR lookup failed');lastHeaderAnalysis.enrichment=d.enriched||[];showHeaderAnalysis(lastHeaderAnalysis)}catch(err){showHeaderError(err.message||'Hop enrichment failed')}finally{enrichHeadersBtn.textContent='Enrich Hops';enrichHeadersBtn.disabled=false}});
    function esc(v){return String(v??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))}
    function showError(m){results.innerHTML='<div class="error-card"><h2>Analysis Failed</h2><p>'+esc(m)+'</p></div>';results.classList.add('active')}
    function showResults(d){lastDomainReport=d;const icons={pass:'✓',warn:'⚠',fail:'✗',info:'ℹ'},colors={excellent:'excellent',good:'good',fair:'fair',poor:'poor'};let h='<div class="score-card"><div class="score-value '+colors[d.overall_status]+'">'+d.overall_score+'</div><div class="score-label">'+esc(d.overall_status)+'</div><div class="score-domain">'+esc(d.domain)+'</div><div class="header-actions" style="justify-content:center"><button class="btn secondary" data-action="inspect-spf">Inspect SPF</button><button class="btn secondary" data-action="build-records">Build records</button></div></div>';h+=createSection('spf','SPF Record',d.spf,icons);h+=createSection('dkim','DKIM Configuration',d.dkim,icons);h+=createSection('dmarc','DMARC Policy',d.dmarc,icons);h+=createMXSection(d.mx);h+=createSection('transport','Transport Security',d.transport,icons);h+=createSection('caa','CAA Records',d.caa,icons);h+=createPTRSection(d.ptr);results.innerHTML=h;results.classList.add('active');bindSections(results);results.querySelector('.section')?.classList.add('expanded');results.querySelector('[data-action="inspect-spf"]').onclick=()=>{spfInput.value=d.domain;selectTool('spf');spfForm.requestSubmit()};results.querySelector('[data-action="build-records"]').onclick=()=>{prefillBuilders(d);selectTool('builder')}}
    function createSection(id,t,d,icons){const c=d.checks.map(x=>'<div class="check-item"><div class="check-icon '+x.status+'">'+icons[x.status]+'</div><div class="check-content"><div class="check-title">'+esc(x.title)+'</div><div class="check-detail">'+esc(x.detail)+'</div>'+(x.recommendation?'<div class="check-recommendation"><strong>Recommendation</strong>'+esc(x.recommendation)+'</div>':'')+'</div></div>').join('');const r=d.record?'<div class="record-box"><strong>DNS Record</strong>'+esc(d.record)+'</div>':'';const s=d.selectors&&d.selectors.length?'<div class="record-box"><strong>Found DKIM Selectors</strong>'+d.selectors.map(x=>'<div style="margin-bottom:8px"><code>'+esc(x.selector)+'</code></div>').join('')+'</div>':'';const icon=id==='spf'?'📧':id==='dkim'?'🔐':id==='dmarc'?'🛡️':id==='caa'?'🔒':id==='transport'?'🔁':'📬';return'<div class="section" id="'+id+'"><div class="section-header"><div class="section-icon '+id+'">'+icon+'</div><div class="section-title">'+t+'</div><div class="section-status '+d.status+'">'+d.status+'</div><div class="section-chevron">▼</div></div><div class="section-content">'+r+s+c+'</div></div>'}
    function createMXSection(d){if(!d.records||!d.records.length)return'<div class="section"><div class="section-header"><div class="section-icon mx">📬</div><div class="section-title">MX Records</div><div class="section-status warn">none</div><div class="section-chevron">▼</div></div><div class="section-content"><p style="color:var(--text-muted);padding:16px 0">No MX records found.</p></div></div>';const r=d.records.map(x=>'<tr><td>'+x.priority+'</td><td><code>'+esc(x.host)+'</code></td></tr>').join('');return'<div class="section"><div class="section-header"><div class="section-icon mx">📬</div><div class="section-title">MX Records</div><div class="section-status pass">'+d.records.length+' found</div><div class="section-chevron">▼</div></div><div class="section-content"><table class="mx-table"><thead><tr><th>Priority</th><th>Mail Server</th></tr></thead><tbody>'+r+'</tbody></table></div></div>'}
    function createPTRSection(d){const icons={pass:'✓',warn:'⚠',fail:'✗',info:'ℹ'};return'<div class="section"><div class="section-header"><div class="section-icon ptr">🔄</div><div class="section-title">Reverse DNS (PTR)</div><div class="section-status '+d.status+'">'+d.status+'</div><div class="section-chevron">▼</div></div><div class="section-content">'+d.checks.map(x=>'<div class="check-item"><div class="check-icon '+x.status+'">'+icons[x.status]+'</div><div class="check-content"><div class="check-title">'+esc(x.title)+'</div><div class="check-detail">'+esc(x.detail)+'</div>'+(x.recommendation?'<div class="check-recommendation"><strong>Recommendation</strong>'+esc(x.recommendation)+'</div>':'')+'</div></div>').join('')+'</div></div>'}
    function showSpfError(m){spfResults.innerHTML='<div class="error-card"><h2>SPF Inspection Failed</h2><p>'+esc(m)+'</p></div>';spfResults.classList.add('active')}
    function showSpfInspector(d){const f=d.flatten;if(!f.available){showSpfError('No SPF record was found for '+d.domain);return}const recursive=d.spf.lookupCount??f.originalLookups;let h='<div class="inspector-summary"><div class="summary-tile"><span>Recursive lookups</span><strong>'+recursive+'/10</strong></div><div class="summary-tile"><span>After preview</span><strong>'+f.flattenedLookups+'/10</strong></div><div class="summary-tile"><span>Record length</span><strong>'+f.characterCount+'</strong></div></div>';h+='<div class="output-card"><div class="output-head"><strong>Current SPF record</strong><button class="copy-btn" data-copy="original">Copy</button></div><div class="dns-value">'+esc(f.originalRecord)+'</div></div>';h+='<div class="output-card"><div class="output-head"><strong>Flattened preview</strong><button class="copy-btn" data-copy="flattened" '+(f.safeToPublish?'':'disabled')+'>'+(f.safeToPublish?'Copy validated preview':'Review required')+'</button></div><div class="dns-value">'+esc(f.record)+'</div></div>';h+='<div class="notice '+(f.safeToPublish?'good':'')+'"><strong>'+(f.safeToPublish?'Validated point-in-time preview':'Copy blocked — manual review required')+'</strong><br>'+[...(f.validation?.errors||[]),...f.warnings].map(esc).join('<br>')+'</div>';h+='<div class="section expanded"><div class="section-header"><div class="section-icon spf">🌳</div><div class="section-title">Expanded sources</div><div class="section-status info">'+f.sources.length+' records</div><div class="section-chevron">▼</div></div><div class="section-content">'+f.sources.map(x=>'<div class="source-group"><code>'+esc(x.source)+'</code><span>'+esc(x.mechanisms.join(' '))+'</span></div>').join('')+'</div></div>';h+='<div class="header-actions"><button class="btn secondary" data-action="use-spf">Use in Record Builder</button></div>';spfResults.innerHTML=h;spfResults.classList.add('active');bindSections(spfResults);spfResults.querySelector('[data-copy="original"]').onclick=()=>copyText(f.originalRecord);if(f.safeToPublish)spfResults.querySelector('[data-copy="flattened"]').onclick=()=>copyText(f.record);spfResults.querySelector('[data-action="use-spf"]').onclick=()=>{document.getElementById('builderDomain').value=d.domain;document.getElementById('spfCustom').value=f.record.replace(/^v=spf1\\s+/,'').replace(/\\s+[?~+-]all\\s*$/,'');document.getElementById('spfPolicy').value=(f.record.match(/([?~+-]all)\\s*$/)||[])[1]||'~all';renderSpfBuilder();selectTool('builder')}}
    function copyText(value){navigator.clipboard.writeText(value).then(()=>{}).catch(()=>{const t=document.createElement('textarea');t.value=value;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()})}
    function outputCard(title,host,value,warning){return'<div class="output-card"><div class="output-head"><strong>'+esc(title)+'</strong><button class="copy-btn" disabled>Validating...</button></div><div class="field-help" style="margin-bottom:6px">Host: '+esc(host)+'</div><div class="dns-value">'+esc(value)+'</div>'+(warning?'<div class="notice">'+esc(warning)+'</div>':'')+'<div class="validation-result"></div></div>'}
    function validSpfMechanism(value){return /^(?:ip4:[0-9./]+|ip6:[0-9a-f:/]+|include:[a-z0-9_.-]+|a(?::[a-z0-9_.-]+)?(?:\\/\\d+)?|mx(?::[a-z0-9_.-]+)?(?:\\/\\d+)?)$/i.test(value)}
    let spfValidationSequence=0,dmarcValidationSequence=0;
    function validBuilderDomain(value){return /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\\.[a-z]{2,}$/i.test(value)}
    function showValidation(root,validation,extraErrors,record,type){const errors=[...(extraErrors||[]),...(validation.errors||[])],warnings=validation.warnings||[];const box=root.querySelector('.validation-result'),button=root.querySelector('.copy-btn');if(errors.length){box.innerHTML='<div class="notice"><strong>Cannot copy this record</strong><br>'+errors.map(esc).join('<br>')+'</div>';button.textContent='Invalid record';button.disabled=true;return}const metrics=type==='spf'?' · '+validation.lookupCount+' SPF DNS lookups · '+validation.characterCount+' characters':' · '+validation.characterCount+' characters';box.innerHTML='<div class="notice good"><strong>Valid record</strong>'+metrics+(warnings.length?'<br>'+warnings.map(esc).join('<br>'):'')+'</div>';button.textContent='Copy value';button.disabled=false;button.onclick=()=>copyText(record)}
    async function renderSpfBuilder(){const sequence=++spfValidationSequence;const selected=[...document.querySelectorAll('#providerOptions input:checked')].map(x=>x.value);const raw=document.getElementById('spfCustom').value.trim().split(/\\s+/).filter(Boolean);const valid=raw.filter(validSpfMechanism),invalid=raw.filter(x=>!validSpfMechanism(x));const policy=document.getElementById('spfPolicy').value;const stage=document.getElementById('spfStage').value;const domain=document.getElementById('builderDomain').value.trim();const record=['v=spf1',...new Set([...selected,...valid]),policy].join(' ');const warning=stage!=='confirmed'&&policy==='-all'?'Use ~all until every legitimate sender is confirmed.':!selected.length&&!valid.length?'No sending service is authorised by this record.':'';const root=document.getElementById('spfBuilderOutput');root.innerHTML=outputCard('Proposed SPF TXT record',domain||'your domain',record,warning);const extra=[];if(!validBuilderDomain(domain))extra.push('Enter a valid domain before copying.');if(invalid.length)extra.push('Correct unsupported terms: '+invalid.join(', '));try{const r=await fetch('/api/records/validate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:'spf',domain,record})});const validation=await r.json();if(sequence!==spfValidationSequence)return;showValidation(root,validation,extra,record,'spf')}catch{if(sequence===spfValidationSequence)showValidation(root,{errors:['Validation service could not confirm this record.'],warnings:[]},extra,record,'spf')}}
    async function renderDmarcBuilder(){const sequence=++dmarcValidationSequence;const domain=document.getElementById('dmarcDomain').value.trim();const policy=document.getElementById('dmarcStage').value;const testing=document.getElementById('dmarcTesting').value;const rua=document.getElementById('dmarcRua').value.trim();const sub=document.getElementById('dmarcSubdomain').value;const strict=document.getElementById('dmarcAlignment').value==='strict';const parts=['v=DMARC1','p='+policy,'t='+testing];if(rua)parts.push('rua=mailto:'+rua.replace(/^mailto:/i,''));if(sub)parts.push('sp='+sub);parts.push('adkim='+(strict?'s':'r'),'aspf='+(strict?'s':'r'));const record=parts.join('; ')+';';let warning='';if(!rua)warning='Add a controlled aggregate-report mailbox before publishing.';else if(testing==='y')warning='Testing mode is temporary; review reports before changing to t=n.';else if(policy!=='none'&&!lastDomainReport)warning='Review DMARC reports before enforcing quarantine or rejection.';const root=document.getElementById('dmarcBuilderOutput');root.innerHTML=outputCard('Proposed DMARC TXT record','_dmarc.'+(domain||'your-domain'),record,warning);const extra=[];if(!validBuilderDomain(domain))extra.push('Enter a valid domain before copying.');try{const r=await fetch('/api/records/validate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:'dmarc',domain,record})});const validation=await r.json();if(sequence!==dmarcValidationSequence)return;showValidation(root,validation,extra,record,'dmarc')}catch{if(sequence===dmarcValidationSequence)showValidation(root,{errors:['Validation service could not confirm this record.'],warnings:[]},extra,record,'dmarc')}}
    function prefillBuilders(d){document.getElementById('builderDomain').value=d.domain;document.getElementById('dmarcDomain').value=d.domain;document.getElementById('dmarcRua').value=(d.dmarc.rua&&d.dmarc.rua[0])||('dmarc@'+d.domain);document.getElementById('dmarcStage').value=d.dmarc.policy||'none';document.getElementById('spfPolicy').value=d.spf.record&&/-all(?:\\s|$)/.test(d.spf.record)?'-all':'~all';renderSpfBuilder();renderDmarcBuilder()}
    document.querySelectorAll('#builder-spf input,#builder-spf select').forEach(x=>x.addEventListener('input',renderSpfBuilder));
    document.querySelectorAll('#builder-dmarc input,#builder-dmarc select').forEach(x=>x.addEventListener('input',renderDmarcBuilder));
    renderSpfBuilder();renderDmarcBuilder();
    function showHeaderError(m){headerResults.innerHTML='<div class="error-card" style="margin-top:16px"><h2>Header Analysis Failed</h2><p>'+esc(m)+'</p></div>'}
    function showHeaderAnalysis(d){if(d.error){showHeaderError(d.error);return}const icons={pass:'✓',warn:'⚠',fail:'✗',info:'i'};const summary=d.summary;let html='<div class="trust-banner '+esc(summary.status)+'"><strong>'+esc(summary.verdict)+'</strong><span>'+esc(summary.confidence)+(summary.authservId?' · Receiver ID: '+esc(summary.authservId):'')+'. Authentication outcomes are reported by the pasted headers, not independently re-run.</span></div>';html+='<div class="header-summary"><div class="summary-tile"><span>Reported authentication</span><strong>'+summary.passCount+'/3 pass</strong></div><div class="summary-tile"><span>Delivery chain</span><strong>'+d.hops.length+' hops</strong></div><div class="summary-tile"><span>Enrichable addresses</span><strong>'+d.ips.length+'</strong></div></div>';html+='<div class="section expanded"><button type="button" class="section-header" aria-expanded="true"><div class="section-icon dmarc">🧾</div><div class="section-title">Header Findings</div><div class="section-status '+esc(summary.status)+'">'+esc(summary.status)+'</div><div class="section-chevron">▼</div></button><div class="section-content">'+d.checks.map(x=>'<div class="check-item"><div class="check-icon '+esc(x.status)+'">'+icons[x.status]+'</div><div class="check-content"><div class="check-title">'+esc(x.title)+'</div><div class="check-detail">'+esc(x.detail)+'</div>'+(x.recommendation?'<div class="check-recommendation"><strong>Recommended next step</strong>'+esc(x.recommendation)+'</div>':'')+'</div></div>').join('')+'</div></div>';html+='<div class="section"><button type="button" class="section-header" aria-expanded="false"><div class="section-icon mx">📬</div><div class="section-title">Message Details</div><div class="section-status info">parsed</div><div class="section-chevron">▼</div></button><div class="section-content"><div class="record-box"><strong>From</strong>'+esc(summary.from||'Not found')+'</div><div class="record-box"><strong>Return-Path</strong>'+esc(summary.returnPath||'Not found')+'</div><div class="record-box"><strong>Reply-To</strong>'+esc(summary.replyTo||'Not found')+'</div><div class="record-box"><strong>Subject</strong>'+esc(summary.subject||'Not found')+'</div><div class="record-box"><strong>Date</strong>'+esc(summary.date||'Not found')+'</div><div class="record-box"><strong>Message-ID</strong>'+esc(summary.messageId||'Not found')+'</div></div></div>';html+='<div class="section"><button type="button" class="section-header" aria-expanded="false"><div class="section-icon ptr">🔄</div><div class="section-title">Received Chain</div><div class="section-status info">'+d.hops.length+' hops</div><div class="section-chevron">▼</div></button><div class="section-content"><p class="muted" style="padding-top:16px">Hop 1 is the newest, topmost Received header. Later numbers move toward the earliest recorded sender-side hop.</p><div class="hop-list">'+(d.hops.length?d.hops.map(h=>renderHop(h,d.enrichment)).join(''):'<p class="muted">No Received headers found. Use the complete post-delivery message source.</p>')+'</div></div></div>';headerResults.innerHTML=html;bindSections(headerResults)}
    function renderHop(h,enrichment){const addresses=(h.ips||[]).map(ip=>{const e=(enrichment||[]).find(x=>x.ip===ip);return '<div><code>'+esc(ip)+'</code>'+(e?'<span class="muted"> · PTR: '+esc(e.ptr||'none found')+'</span>':'')+'</div>'}).join('');const route='<div class="hop-route"><code>'+esc(h.from||'unknown source')+'</code><span class="muted">→</span><code>'+esc(h.by||'unknown receiver')+'</code></div>';const meta=[h.protocol&&'Protocol: '+h.protocol,h.id&&'ID: '+h.id,h.date&&'Time: '+h.date].filter(Boolean).map(x=>'<span>'+esc(x)+'</span>').join('');return '<div class="hop-item"><strong>Hop '+h.index+' · '+esc(h.position)+'</strong>'+route+'<div class="hop-meta">'+meta+'</div>'+(addresses?'<div style="margin-top:9px">'+addresses+'</div>':'')+'<details style="margin-top:9px"><summary class="muted">Raw Received header</summary><div class="muted" style="margin-top:6px;word-break:break-word">'+esc(h.value)+'</div></details></div>'}
    function bindSections(root){root.querySelectorAll('.section-header').forEach(x=>x.addEventListener('click',()=>{const expanded=x.parentElement.classList.toggle('expanded');x.setAttribute('aria-expanded',String(expanded))}))}
    input.focus();
  </script>
</body>
</html>`;
