'use strict';

const { getDomain } = require('tldts');
const ipaddr = require('ipaddr.js');

const MAX_HEADER_BYTES = 256 * 1024;
const AUTH_RESULTS = new Set(['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror', 'policy', 'bestguesspass']);

function normalizeDomain(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '')
    .replace(/[>"'),;]+$/g, '');
}

// RFC 5322 §3.2.3 comments and quoted strings hide address-like text from
// every downstream extraction. "Alice (bob@example.net) <alice@example.com>"
// must resolve to example.com everywhere — Author Domains, the visible From
// domain, and Received keyword parsing alike.
function visibleHeaderText(text) {
  let commentDepth = 0;
  let quoted = false;
  let escaped = false;
  let visible = '';

  for (const character of String(text || '')) {
    if (escaped) {
      escaped = false;
      if (!commentDepth) visible += character;
      continue;
    }
    if (character === '\\') {
      escaped = true;
      if (!commentDepth) visible += character;
      continue;
    }
    if (!commentDepth && character === '"') quoted = !quoted;
    if (!quoted && character === '(') {
      commentDepth += 1;
      continue;
    }
    if (!quoted && commentDepth && character === ')') {
      commentDepth -= 1;
      continue;
    }
    if (!commentDepth) visible += character;
  }
  return visible.replace(/"(?:\\.|[^"\\])*"/g, '');
}

function domainFromAddress(value) {
  // Comment text is removed before matching, so the last @-sign belongs to
  // the real mailbox instead of a display-name aside.
  const text = visibleHeaderText(value);
  const bracketed = [...text.matchAll(/<[^<>]*@([^<>\s]+)>/g)].at(-1);
  const bare = [...text.matchAll(/@([^\s<>,;\]]+)/g)].at(-1);
  return normalizeDomain((bracketed || bare || [])[1]);
}

function authorDomainsFromField(value) {
  const withoutDisplayNames = visibleHeaderText(value);
  return [...new Set(
    [...withoutDisplayNames.matchAll(/@([^\s<>,;\]]+)/g)]
      .map(match => normalizeDomain(match[1]))
      .filter(Boolean)
  )];
}

function organisationalDomain(domain) {
  const clean = normalizeDomain(domain);
  return getDomain(clean, { allowPrivateDomains: true }) || clean;
}

function alignment(fromDomain, candidateDomain) {
  const from = normalizeDomain(fromDomain);
  const candidate = normalizeDomain(candidateDomain);
  if (!from || !candidate) return { aligned: false, mode: 'unknown' };
  if (from === candidate) return { aligned: true, mode: 'strict' };
  const fromOrg = organisationalDomain(from);
  const candidateOrg = organisationalDomain(candidate);
  return {
    aligned: Boolean(fromOrg && candidateOrg && fromOrg === candidateOrg),
    mode: fromOrg && candidateOrg && fromOrg === candidateOrg ? 'relaxed' : 'none'
  };
}

function parseHeaders(raw) {
  const source = String(raw || '');
  if (!source.trim()) throw new Error('Paste the complete message headers first.');
  if (Buffer.byteLength(source, 'utf8') > MAX_HEADER_BYTES) {
    throw new Error('Headers exceed the 256 KB analysis limit.');
  }

  const headerBlock = source.replace(/\r\n?/g, '\n').split(/\n\n/, 1)[0];
  const headers = {};
  const ordered = [];
  let current = null;

  for (const line of headerBlock.split('\n')) {
    if (/^[ \t]/.test(line) && current) {
      current.value += ` ${line.trim()}`;
      headers[current.name][headers[current.name].length - 1] = current.value;
      continue;
    }
    const separator = line.indexOf(':');
    if (separator < 1) {
      current = null;
      continue;
    }
    const name = line.slice(0, separator).trim().toLowerCase();
    if (!/^[!-9;-~]+$/.test(name)) {
      current = null;
      continue;
    }
    current = { name, value: line.slice(separator + 1).trim() };
    (headers[name] ||= []).push(current.value);
    ordered.push(current);
  }

  return { headers, ordered };
}

// Removes any run of comment groups opening the value but leaves the rest
// untouched, so a quoted-string authserv-id survives intact.
function stripLeadingComments(text) {
  const source = String(text || '');
  let index = 0;
  while (index < source.length) {
    const character = source[index];
    if (character === ' ' || character === '\t') {
      index += 1;
      continue;
    }
    if (character !== '(') break;
    let depth = 1;
    index += 1;
    while (index < source.length && depth > 0) {
      if (source[index] === '(') depth += 1;
      else if (source[index] === ')') depth -= 1;
      index += 1;
    }
  }
  return source.slice(index);
}

function parseAuthResults(value) {
  // Real-world headers open with a CFWS comment ("(mx1.example server)
  // mx1.example; ...") even though RFC 8601 puts no comment before the
  // authserv-id; strip leading comments so the identity is the first token.
  const parts = String(value || '').split(';');
  const authservId = stripLeadingComments(parts.shift()).trim().split(/\s+/)[0] || 'unknown';
  const methods = [];
  for (const clause of parts) {
    const match = clause.match(/\b(spf|dkim|dmarc)\s*=\s*([a-z]+)/i);
    if (!match) continue;
    const method = match[1].toLowerCase();
    const rawResult = match[2].toLowerCase();
    const result = AUTH_RESULTS.has(rawResult) ? rawResult : 'unknown';
    methods.push({
      method,
      result,
      smtpMailfrom: normalizeDomain((clause.match(/\bsmtp\.mailfrom\s*=\s*([^\s;]+)/i) || [])[1]),
      headerFrom: normalizeDomain((clause.match(/\bheader\.from\s*=\s*([^\s;]+)/i) || [])[1]),
      headerD: normalizeDomain((clause.match(/\bheader\.d\s*=\s*([^\s;]+)/i) || [])[1]),
      reason: (clause.match(/\breason\s*=\s*"([^"]+)"/i) || [])[1] || ''
    });
  }
  return { authservId, methods };
}

function parseReceivedSpf(value) {
  const text = String(value || '').trim();
  const result = (text.match(/^(pass|fail|softfail|neutral|none|temperror|permerror|policy|bestguesspass)\b/i) || [])[1]?.toLowerCase() || 'unknown';
  const fields = Object.fromEntries([...text.matchAll(/(?:^|\s)([a-z][a-z0-9_-]*)=([^\s;]+)/gi)].map(match => [match[1].toLowerCase(), match[2]]));
  return { raw: text, result, fields, validSyntax: result !== 'unknown' };
}

function parseDkimSignature(value) {
  const raw = String(value || '').trim();
  const tags = Object.fromEntries(raw.split(';').map(part => {
    const index = part.indexOf('=');
    return index > 0 ? [part.slice(0, index).trim().toLowerCase(), part.slice(index + 1).trim()] : null;
  }).filter(Boolean));
  const required = ['v', 'a', 'd', 's', 'bh', 'b'];
  const validSyntax = required.every(key => Boolean(tags[key])) && /^1$/.test(tags.v);
  return { raw, tags, validSyntax };
}

function authResultCheck(method, result) {
  const label = method.toUpperCase();
  if (!result) {
    return {
      status: 'info',
      title: `${label} result not found`,
      detail: `The selected Authentication-Results header does not report ${label}.`,
      recommendation: 'Use the full original headers from the final receiving mailbox. Missing evidence is not a pass or a failure.'
    };
  }
  if (result.result === 'pass') {
    return {
      status: 'pass',
      title: `${label} reported pass`,
      detail: `${label}=pass was reported by ${result.authservId}.`,
      recommendation: ''
    };
  }
  if (result.result === 'fail' || result.result === 'softfail' || result.result === 'policy') {
    return {
      status: 'fail',
      title: `${label} reported ${result.result}`,
      detail: `${label}=${result.result} was reported by ${result.authservId}${result.reason ? `: ${result.reason}` : '.'}`,
      recommendation: method === 'spf'
        ? 'Check the envelope sender, forwarding path, and whether the sending IP is authorised by its SPF policy.'
        : method === 'dkim'
          ? 'Check the signing domain, selector, and whether the message changed after signing.'
          : 'Check whether SPF or DKIM passed with alignment to the visible From domain.'
    };
  }
  if (result.result === 'temperror') {
    return {
      status: 'warn',
      title: `${label} was temporarily inconclusive`,
      detail: `${result.authservId} reported a temporary authentication error.`,
      recommendation: 'Retry or inspect a later delivery. Temporary DNS or receiver errors should not be treated as a permanent failure.'
    };
  }
  if (result.result === 'permerror') {
    return {
      status: 'fail',
      title: `${label} configuration error`,
      detail: `${result.authservId} reported a permanent authentication error.`,
      recommendation: 'Review the published authentication record for invalid syntax, duplicate records, or evaluation-limit failures.'
    };
  }
  return {
    status: 'info',
    title: `${label} reported ${result.result}`,
    detail: `${result.authservId} did not report a definitive pass or fail.`,
    recommendation: 'Treat this result as indeterminate and inspect the receiver details before taking action.'
  };
}

// Address shapes are extracted most-specific-first, blanking each consumed
// span before the next pattern runs. A single combined alternation let a
// generic hexadecimal pattern eat part of an IPv4 tail ("::ffff:198" out of
// "::ffff:198.51.100.9") or the "IPv6:" label inside an address literal
// ("6:2001:db8::1"), producing plausible-looking but wrong addresses.
const IP_PATTERNS = [
  // RFC 4291 §2.2 form 3: hexadecimal prefix with embedded IPv4 tail.
  /(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){1,6}(?:\d{1,3}\.){3}\d{1,3}/gi,
  // Plain dotted-quad IPv4 (not the embedded tail of the form above).
  /(?<![0-9a-f.:])(?:\d{1,3}\.){3}\d{1,3}(?![0-9a-f])/g,
  // General compressed hexadecimal IPv6.
  /(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])/gi
];

function extractIpCandidates(value) {
  // RFC 5321 §4.1.3 wraps IPv6 in "[IPv6:...]"; unwrap the label first so it
  // cannot glue onto the address text.
  let working = String(value || '').replace(/\[\s*ipv6\s*:/gi, '[');
  const found = [];
  for (const pattern of IP_PATTERNS) {
    working = working.replace(pattern, match => {
      found.push(match);
      return ' '.repeat(match.length);
    });
  }
  return [...new Set(found.map(candidate => candidate.replace(/^[[(]|[\])];,]$/g, '')))]
    .filter(candidate => {
      try {
        return ipaddr.parse(candidate).range() === 'unicast';
      } catch {
        return false;
      }
    });
}

function parseReceived(value, index, total) {
  const text = String(value || '');
  // Keyword extraction must ignore RFC 5322 comments — "(note by
  // fake.example here)" must not become the by-host — while IP candidates
  // still come from the full raw value, where the real connection data sits.
  const visible = visibleHeaderText(text);
  const from = (visible.match(/\bfrom\s+([^\s(;]+)/i) || [])[1] || '';
  const by = (visible.match(/\bby\s+([^\s(;]+)/i) || [])[1] || '';
  const protocol = (visible.match(/\bwith\s+([^\s;]+)/i) || [])[1] || '';
  const id = (visible.match(/\bid\s+([^\s;]+)/i) || [])[1] || '';
  // The date clause follows the last top-level semicolon; a semicolon inside
  // a comment no longer derails the split.
  const dateText = visible.includes(';') ? visible.slice(visible.lastIndexOf(';') + 1).trim() : '';
  const parsedDate = dateText && !Number.isNaN(Date.parse(dateText)) ? new Date(dateText).toISOString() : null;
  return {
    index: index + 1,
    position: index === 0 ? 'Final receiving hop' : index === total - 1 ? 'Earliest recorded hop' : 'Intermediate hop',
    from,
    by,
    protocol,
    id,
    date: dateText,
    parsedDate,
    value: text,
    ips: extractIpCandidates(text)
  };
}

function analyzeEmailHeaders(raw) {
  const { headers } = parseHeaders(raw);
  const first = name => headers[name]?.[0] || '';
  const from = first('from');
  const returnPath = first('return-path');
  const replyTo = first('reply-to');
  const fromDomain = domainFromAddress(from);
  const returnDomain = domainFromAddress(returnPath);
  const replyDomain = domainFromAddress(replyTo);

  const authHeaders = headers['authentication-results'] || [];
  const receivedSpfHeaders = headers['received-spf'] || [];
  const dkimSignatureHeaders = headers['dkim-signature'] || [];
  const parsedAuthHeaders = authHeaders.map(parseAuthResults);
  const selectedAuth = parsedAuthHeaders[0] || { authservId: '', methods: [] };
  const selected = method => {
    const candidates = selectedAuth.methods.filter(item => item.method === method);
    if (method === 'dkim' && fromDomain) {
      return candidates.find(item => item.result === 'pass' && alignment(fromDomain, item.headerD).aligned) || candidates[0];
    }
    if (method === 'spf') {
      // RFC 8601 lets one header carry both an smtp.helo and an
      // smtp.mailfrom SPF result; whichever appeared first is not the rule.
      // The envelope-from clause is the message-level verdict, so it wins,
      // with an aligned pass preferred among envelope clauses like DKIM's
      // aligned-signature preference.
      const envelopeClauses = candidates.filter(item => item.smtpMailfrom);
      return envelopeClauses.find(item => item.result === 'pass' && fromDomain && alignment(fromDomain, item.smtpMailfrom).aligned)
        || envelopeClauses[0]
        || candidates[0];
    }
    return candidates[0];
  };
  const withServer = item => item ? { ...item, authservId: selectedAuth.authservId } : null;
  const spf = withServer(selected('spf'));
  const dkim = withServer(selected('dkim'));
  const dmarc = withServer(selected('dmarc'));

  const checks = [
    {
      status: authHeaders.length ? 'info' : 'warn',
      title: authHeaders.length ? `Receiver report: ${selectedAuth.authservId}` : 'No receiver authentication report',
      detail: authHeaders.length
        ? 'These are claims in the topmost Authentication-Results header; this tool does not cryptographically re-run authentication.'
        : 'No Authentication-Results header was found, so SPF, DKIM, and DMARC cannot be assessed from this paste.',
      recommendation: authHeaders.length
        ? 'Confirm this authserv-id belongs to the mailbox provider that received the message. Pasted headers can be forged or incomplete.'
        : 'Open the message source in the final receiving mailbox and paste all headers.'
    },
    authResultCheck('spf', spf),
    authResultCheck('dkim', dkim),
    authResultCheck('dmarc', dmarc)
  ];

  if (receivedSpfHeaders.length) {
    const parsedReceivedSpf = receivedSpfHeaders.map(parseReceivedSpf);
    const malformed = parsedReceivedSpf.filter(item => !item.validSyntax);
    checks.push({
      status: malformed.length ? 'warn' : 'info',
      title: malformed.length ? 'Received-SPF syntax needs review' : 'Received-SPF evidence found',
      detail: malformed.length
        ? `${malformed.length} Received-SPF field(s) do not begin with a recognized result.`
        : `The receiving server supplied ${parsedReceivedSpf.length} Received-SPF result(s): ${parsedReceivedSpf.map(item => item.result).join(', ')}.`,
      recommendation: 'Received-SPF is receiver-provided evidence. It is not independently re-run by this tool.'
    });
  }

  if (dkimSignatureHeaders.length) {
    const parsedSignatures = dkimSignatureHeaders.map(parseDkimSignature);
    const malformed = parsedSignatures.filter(item => !item.validSyntax);
    checks.push({
      status: malformed.length ? 'warn' : 'info',
      title: malformed.length ? 'DKIM-Signature syntax needs review' : 'DKIM-Signature fields found',
      detail: malformed.length
        ? `${malformed.length} DKIM-Signature field(s) are missing one or more required tags.`
        : `${parsedSignatures.length} DKIM-Signature field(s) include version, algorithm, signing domain, selector, body hash, and signature tags.`,
      recommendation: 'This checks header shape only. It does not verify the signature, DNS key, or message body hash.'
    });
  }

  if (authHeaders.length > 1) {
    const signatures = parsedAuthHeaders.map(parsed =>
      ['spf', 'dkim', 'dmarc'].map(method => parsed.methods.find(item => item.method === method)?.result || 'missing').join('/')
    );
    const conflict = new Set(signatures).size > 1;
    checks.push({
      status: conflict ? 'warn' : 'info',
      title: `${authHeaders.length} Authentication-Results headers`,
      detail: conflict
        ? 'Different authentication outcomes appear in the header chain. Only the topmost report is used in the summary.'
        : 'Multiple receivers recorded consistent authentication outcomes.',
      recommendation: conflict
        ? 'Prefer the topmost header added by your final receiving provider and inspect where the outcome changed.'
        : ''
    });
  }

  if (!fromDomain) {
    checks.push({
      status: 'fail',
      title: 'Visible From domain not parsed',
      detail: from || 'The From header is missing.',
      recommendation: 'Treat a missing, malformed, or multi-address From header as suspicious and inspect the raw message.'
    });
  }
  if ((headers.from || []).length > 1) {
    checks.push({
      status: 'fail',
      title: 'Multiple From headers',
      detail: `Found ${headers.from.length} visible From fields. A normal message should contain exactly one.`,
      recommendation: 'Treat the message as malformed or suspicious. Do not rely on the displayed sender without independent verification.'
    });
  } else {
    // RFC 9989 §5.3.1 normally stops DMARC validation when RFC5322.From
    // contains more than one Author Domain. Several mailboxes at the same
    // domain still yield one Author Domain and remain unambiguous here.
    const authorDomains = authorDomainsFromField(from);
    if (authorDomains.length > 1) {
      checks.push({
        status: 'fail',
        title: 'From field lists multiple domains',
        detail: `RFC 9989 Author Domain extraction found several domains (${authorDomains.join(', ')}), so DMARC validation is not normally possible.`,
        recommendation: 'Treat the receiver-reported DMARC result as ambiguous. Verify the visible authors and the Sender field before trusting the message.'
      });
    }
  }

  if (returnDomain && fromDomain) {
    const result = alignment(fromDomain, returnDomain);
    checks.push({
      status: result.aligned ? 'pass' : 'warn',
      title: `Envelope sender ${result.aligned ? `${result.mode} alignment` : 'does not align'}`,
      detail: `Visible From: ${fromDomain} · Return-Path: ${returnDomain}`,
      recommendation: result.aligned
        ? ''
        : 'A different envelope domain is common for mailing platforms, but it does not provide SPF alignment. Confirm the sender is expected and rely on the receiver’s DMARC result.'
    });
  } else if (!returnDomain) {
    checks.push({
      status: 'info',
      title: 'Return-Path not found',
      detail: 'The envelope sender is unavailable in the pasted headers.',
      recommendation: 'Use the full post-delivery message source; draft or pre-delivery headers often omit Return-Path.'
    });
  }

  if (replyDomain && fromDomain) {
    const result = alignment(fromDomain, replyDomain);
    checks.push({
      status: result.aligned ? 'pass' : 'warn',
      title: `Reply-To ${result.aligned ? `${result.mode} alignment` : 'points elsewhere'}`,
      detail: `Visible From: ${fromDomain} · Reply-To: ${replyDomain}`,
      recommendation: result.aligned
        ? ''
        : 'A different Reply-To can be legitimate, but verify it before replying or sending credentials, payment details, or sensitive data.'
    });
  }

  if (dkim?.headerD && fromDomain) {
    const result = alignment(fromDomain, dkim.headerD);
    checks.push({
      status: result.aligned ? 'pass' : dkim.result === 'pass' ? 'warn' : 'info',
      title: `DKIM signing domain ${result.aligned ? `${result.mode} alignment` : 'does not align'}`,
      detail: `Visible From: ${fromDomain} · DKIM d=: ${dkim.headerD}`,
      recommendation: result.aligned
        ? ''
        : 'A valid signature from another domain does not satisfy DMARC alignment. Check for another aligned DKIM signature or aligned SPF.'
    });
  }

  const received = headers.received || [];
  const hops = received.map((value, index) => parseReceived(value, index, received.length));
  const ips = [...new Set(hops.flatMap(hop => hop.ips))].slice(0, 10);
  if (!hops.length) {
    checks.push({
      status: 'warn',
      title: 'No Received chain found',
      detail: 'There are no Received headers showing how the message reached the mailbox.',
      recommendation: 'Use the complete post-delivery source from the receiving mailbox. Authentication claims without a delivery chain are easier to fabricate or take out of context.'
    });
  } else {
    const datedHops = hops.filter(hop => hop.parsedDate);
    const chronologyProblem = datedHops.some((hop, index) => {
      if (!index) return false;
      return Date.parse(hop.parsedDate) > Date.parse(datedHops[index - 1].parsedDate) + 5 * 60 * 1000;
    });
    if (chronologyProblem) {
      checks.push({
        status: 'warn',
        title: 'Delivery timestamps are out of sequence',
        detail: 'An earlier sender-side hop appears more than five minutes newer than the receiving hop above it.',
        recommendation: 'Clock skew is possible, but inspect the affected Received headers and other inconsistencies before trusting the delivery chain.'
      });
    }
  }
  const passCount = [spf, dkim, dmarc].filter(item => item?.result === 'pass').length;
  const failCount = [spf, dkim, dmarc].filter(item => ['fail', 'softfail', 'permerror', 'policy'].includes(item?.result)).length;
  const headerFailure = checks.some(check => check.status === 'fail');
  const hasFailure = failCount || headerFailure;
  const hasWarning = checks.some(check => check.status === 'warn');
  const status = hasFailure ? 'fail' : hasWarning ? 'warn' : passCount === 3 ? 'pass' : authHeaders.length ? 'warn' : 'info';

  return {
    summary: {
      status,
      verdict: failCount
        ? 'Authentication problems reported'
        : headerFailure
          ? 'Suspicious header structure found'
          : passCount === 3
            ? 'All three methods reported pass'
            : 'Authentication evidence incomplete',
      confidence: authHeaders.length ? 'Reported by pasted headers' : 'No receiver report',
      authservId: selectedAuth.authservId || null,
      passCount,
      from,
      returnPath,
      replyTo,
      subject: first('subject'),
      date: first('date'),
      messageId: first('message-id'),
      fromDomain,
      returnDomain,
      replyDomain,
      spf: spf?.result || 'not found',
      dkim: dkim?.result || 'not found',
      dmarc: dmarc?.result || 'not found',
      dkimDomain: dkim?.headerD || ''
    },
    checks,
    hops,
    ips,
    enrichment: [],
    evidence: {
      authenticationResults: authHeaders,
      receivedSpf: receivedSpfHeaders.map(parseReceivedSpf),
      dkimSignatures: dkimSignatureHeaders.map(parseDkimSignature)
    },
    limits: { maxHeaderBytes: MAX_HEADER_BYTES, maxEnrichedIps: 10 }
  };
}

module.exports = {
  MAX_HEADER_BYTES,
  alignment,
  analyzeEmailHeaders,
  domainFromAddress,
  authorDomainsFromField,
  organisationalDomain,
  parseHeaders
};
