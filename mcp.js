const MCP_PROTOCOL_VERSION = '2025-11-25';
const SUPPORTED_PROTOCOL_VERSIONS = new Set([MCP_PROTOCOL_VERSION, '2025-06-18', '2024-11-05']);
const MCP_SERVER_VERSION = '2.0.0';
const MAX_MCP_REQUEST_BYTES = 280 * 1024;
const MCP_SECURITY_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Accept, MCP-Protocol-Version, MCP-Session-Id, Authorization',
  'Access-Control-Expose-Headers': 'MCP-Protocol-Version',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Robots-Tag': 'noindex, nofollow'
};

async function handleMcp(request, execute) {
  const accept = request.headers.get('Accept') || '';
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: MCP_SECURITY_HEADERS });
  }
  if (request.method === 'GET') {
    return new Response(null, { status: 405, headers: { ...MCP_SECURITY_HEADERS, Allow: 'POST, OPTIONS' } });
  }
  if (request.method !== 'POST') {
    return new Response(null, { status: 405, headers: { ...MCP_SECURITY_HEADERS, Allow: 'POST, OPTIONS' } });
  }
  if (!accept.includes('application/json') || !accept.includes('text/event-stream')) {
    return rpcError(null, -32600, 'Accept must include application/json and text/event-stream', 406);
  }
  const contentType = (request.headers.get('Content-Type') || '').toLowerCase().split(';')[0].trim();
  if (contentType !== 'application/json') {
    return rpcError(null, -32600, 'Content-Type must be application/json', 415);
  }

  // Parse failure (-32700) and structural invalidity (-32600) are distinct
  // JSON-RPC conditions: garbage bytes are not a well-formed-but-invalid
  // request, and clients debug them differently.
  let message;
  try {
    message = await readMessage(request);
  } catch (error) {
    if (error instanceof MessageTooLargeError) {
      return rpcError(null, -32600, error.message, 413);
    }
    return rpcError(null, -32700, error instanceof Error ? error.message : 'Invalid JSON', 400);
  }
  if (!isPlainObject(message)) {
    // JSON-RPC 2.0 arrays are batch requests. They were legal under the
    // 2024-11-5 revision and removed in 2025-06-18+; this server rejects
    // them outright because one rate-limited HTTP request must not execute
    // several tool calls under a single limiter token.
    const batchId = Array.isArray(message) && message.length === 1 && isPlainObject(message[0])
      ? message[0].id ?? null
      : null;
    return rpcError(batchId, -32600, 'Batch requests are not supported; send one JSON-RPC message per request', 400);
  }
  if (message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
    return rpcError(isPlainObject(message) ? message.id ?? null : null, -32600, 'Invalid JSON-RPC request', 400);
  }
  // Presence of an id makes a message a request that MUST be answered, even
  // when the method is named like a notification; replying 202 would leave
  // strict clients waiting forever on that id.
  if (message.id === undefined) {
    return new Response(null, {
      status: 202,
      headers: { ...MCP_SECURITY_HEADERS, 'Cache-Control': 'no-store' }
    });
  }
  if (message.method.startsWith('notifications/')) {
    return rpcError(message.id, -32600, 'Notification methods must not carry an id', 400);
  }

  if (message.method === 'initialize') {
    const requested = message.params?.protocolVersion || request.headers.get('MCP-Protocol-Version') || MCP_PROTOCOL_VERSION;
    // Lifecycle spec: a server that does not support the requested version
    // MUST reply with another version it supports, so a future-versioned
    // client negotiates down instead of hard-failing against this server.
    const negotiated = SUPPORTED_PROTOCOL_VERSIONS.has(requested) ? requested : MCP_PROTOCOL_VERSION;
    return rpcResult(message.id, {
      protocolVersion: negotiated,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'email-security-checker', title: 'Email Security Checker', version: MCP_SERVER_VERSION },
      instructions: 'The tools cover domain and batch posture, SPF inspection and evaluation, guarded SPF or DMARC building and validation, pasted-header analysis and hop enrichment, and stored-report retrieval. Never publish a built record when publishReady is false. Findings are observations and policy guidance, not deliverability guarantees; pasted authentication is receiver-reported rather than cryptographically reverified.',
    }, negotiated);
  }
  const requestVersion = request.headers.get('MCP-Protocol-Version');
  if (requestVersion && !SUPPORTED_PROTOCOL_VERSIONS.has(requestVersion)) {
    // Versioning spec: an unsupported MCP-Protocol-Version header on later
    // requests MUST be answered with HTTP 400.
    return rpcError(message.id ?? null, -32602, `Unsupported MCP protocol version: ${requestVersion}`, 400);
  }
  if (message.method === 'ping') return rpcResult(message.id, {});
  if (message.method === 'tools/list') return rpcResult(message.id, { tools: tools() });
  if (message.method !== 'tools/call') return rpcError(message.id, -32601, `Method not found: ${message.method}`);

  const params = message.params && typeof message.params === 'object' ? message.params : {};
  const args = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
  if (!params.name || !tools().some(tool => tool.name === params.name)) {
    // A missing name and an unrecognized name are the same failure for the
    // caller, but "undefined" in the error text would be a debugging trap.
    return rpcError(message.id, -32602, `Unknown tool name: ${String(params.name ?? '(missing)')}`);
  }
  try {
    const result = await execute(params.name, args);
    return rpcResult(message.id, {
      content: [{ type: 'text', text: JSON.stringify(result) }],
      structuredContent: result,
      isError: false,
    });
  } catch (error) {
    // Validation errors thrown by the dispatcher are intentional guidance
    // agents can act on (exposed marker or an explicit HTTP-style status).
    // Anything else is an unexpected fault: answer with a reference instead
    // of engine text and log the detail server-side.
    const intentional = error?.exposed === true || Number.isInteger(error?.status);
    if (!intentional) {
      const reference = [...crypto.getRandomValues(new Uint8Array(4))].map(byte => byte.toString(16).padStart(2, '0')).join('');
      console.error(JSON.stringify({
        level: 'error',
        message: 'Unhandled MCP tool fault',
        reference,
        tool: params.name,
        errorName: error?.name || 'Unknown',
        detail: String(error?.message || error)
      }));
      return rpcResult(message.id, { content: [{ type: 'text', text: `Email security analysis failed internally (${reference}).` }], isError: true });
    }
    return rpcResult(message.id, { content: [{ type: 'text', text: error.message || 'Email security analysis failed' }], isError: true });
  }
}

function tools() {
  return [
    {
      name: 'analyze_email_domain',
      title: 'Analyze email security for a domain',
      description: 'Inspect public SPF, DKIM selector evidence, DMARC, MX, MTA-STS, TLS-RPT, CAA, and inbound MX reverse-DNS observations for a domain. Use for email security posture; do not present the score as a deliverability guarantee.',
      inputSchema: {
        type: 'object', additionalProperties: false, required: ['domain'],
        properties: { domain: { type: 'string', maxLength: 253, description: 'Public DNS domain, for example example.com.' } },
      },
      outputSchema: {
        type: 'object',
        required: ['domain', 'timestamp', 'source_revision', 'spf', 'dkim', 'dmarc', 'mx', 'caa', 'ptr', 'transport', 'dns', 'provenance', 'score_confidence', 'unknown_controls', 'request_budget', 'overall_score', 'overall_status', 'share'],
        properties: {
          domain: { type: 'string' }, timestamp: { type: 'string', format: 'date-time' }, source_revision: { type: 'string' },
          overall_score: { type: 'integer', minimum: 0, maximum: 100 },
          overall_status: { type: 'string', enum: ['excellent', 'good', 'fair', 'poor'] },
          score_confidence: { type: 'string', enum: ['high', 'medium', 'low'] }, unknown_controls: { type: 'array', items: { type: 'string' } },
          spf: { type: 'object' }, dkim: { type: 'object' }, dmarc: { type: 'object' },
          mx: { type: 'object' }, caa: { type: 'object' }, ptr: { type: 'object' },
          transport: { type: 'object' }, dns: { type: 'object' }, provenance: { type: 'object' },
          request_budget: { type: 'object' }, share: { type: 'object' },
        },
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    {
      name: 'analyze_email_headers',
      title: 'Analyze received email headers',
      description: 'Interpret pasted RFC-style message headers, Authentication-Results claims, alignment, conflicts, and delivery hops. This does not cryptographically re-evaluate signatures.',
      inputSchema: {
        type: 'object', additionalProperties: false, required: ['headers'],
        properties: { headers: { type: 'string', maxLength: 262144, description: 'Complete raw message headers only; do not include the message body.' } },
      },
      outputSchema: {
        type: 'object',
        required: ['summary', 'checks', 'hops', 'ips', 'enrichment', 'limits'],
        properties: {
          summary: { type: 'object', required: ['status', 'verdict', 'confidence', 'passCount', 'spf', 'dkim', 'dmarc'], properties: {
            // The summary status is never 'info': a paste without receiver
            // reports always carries the no-report warning.
            status: { type: 'string', enum: ['pass', 'warn', 'fail'] },
            verdict: { type: 'string' }, confidence: { type: 'string' },
            passCount: { type: 'integer', minimum: 0, maximum: 3 },
            spf: { type: 'string' }, dkim: { type: 'string' }, dmarc: { type: 'string' },
          } },
          checks: { type: 'array', items: { type: 'object' } },
          hops: { type: 'array', items: { type: 'object' } },
          ips: { type: 'array', items: { type: 'string' } },
          enrichment: { type: 'array', items: { type: 'object' } },
          limits: { type: 'object' },
        },
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    {
      name: 'analyze_email_domains_batch', title: 'Compare email security across domains',
      description: 'Analyze and compare public SPF, DKIM selector evidence, DMARC, MX, and transport posture for up to 3 unique domains. Each domain receives an equal share of the request DNS budget; rows whose share was exhausted report an incomplete request_budget rather than a definitive score.',
      inputSchema: { type: 'object', additionalProperties: false, required: ['domains'], properties: { domains: { type: 'array', minItems: 1, maxItems: 3, uniqueItems: true, items: { type: 'string', maxLength: 253 } } } },
      outputSchema: { type: 'object', required: ['_reportType', 'domains', 'results', 'created_at', 'validation', 'request_budget', 'share'], properties: { _reportType: { type: 'string', enum: ['batch'] }, domains: { type: 'array', items: { type: 'string' } }, results: { type: 'array', items: { type: 'object' } }, created_at: { type: 'string', format: 'date-time' }, source_revision: { type: 'string' }, id: { type: 'string' }, validation: { type: 'object' }, request_budget: { type: 'object' }, share: { type: 'object' } } },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    {
      name: 'inspect_spf', title: 'Inspect an SPF policy',
      description: 'Resolve and recursively inspect a domain SPF policy, lookup and void-lookup limits, provider mechanisms, and a bounded flattening preview.',
      inputSchema: { type: 'object', additionalProperties: false, required: ['domain'], properties: { domain: { type: 'string', maxLength: 253 } } },
      outputSchema: { type: 'object', required: ['domain', 'spf', 'flatten', 'request_budget'], properties: { domain: { type: 'string' }, spf: { type: 'object' }, flatten: { type: 'object' }, request_budget: { type: 'object' } } },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    {
      name: 'evaluate_spf', title: 'Evaluate SPF for a sender',
      description: 'Evaluate an SPF policy for a client IP, envelope sender, and HELO using RFC processing and bounded DNS lookup limits. An optional record evaluates a proposed policy without publishing it.',
      inputSchema: { type: 'object', additionalProperties: false, required: ['ip'], properties: { ip: { type: 'string', maxLength: 45, description: 'Public IPv4 or IPv6 address of the connecting sender.' }, sender: { type: 'string', maxLength: 320 }, helo: { type: 'string', maxLength: 253 }, domain: { type: 'string', maxLength: 253 }, record: { type: 'string', maxLength: 4096 } }, anyOf: [{ required: ['domain'] }, { required: ['sender'] }] },
      outputSchema: { type: 'object', required: ['status', 'lookups', 'request_budget'], properties: { status: { type: 'object' }, lookups: { type: 'object' }, request_budget: { type: 'object' } } },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    {
      name: 'validate_email_record', title: 'Validate an SPF or DMARC record',
      description: 'Validate a proposed SPF or DMARC TXT record, including syntax, policy semantics, DNS processing limits, and actionable warnings before publication.',
      inputSchema: { type: 'object', additionalProperties: false, required: ['type', 'record'], properties: { type: { type: 'string', enum: ['spf', 'dmarc'] }, domain: { type: 'string', maxLength: 253 }, record: { type: 'string', maxLength: 4096 } } },
      outputSchema: { type: 'object', required: ['valid', 'errors', 'warnings', 'request_budget'], properties: { valid: { type: 'boolean' }, errors: { type: 'array', items: { type: 'string' } }, warnings: { type: 'array', items: { type: 'string' } }, request_budget: { type: 'object' } }, additionalProperties: true },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    {
      name: 'build_email_record', title: 'Build a validated SPF or DMARC record',
      description: 'Construct an SPF or DMARC record using the same guarded planner as the web tool, validate it, and return publication-readiness plus rollout safety warnings. Never publish when publishReady is false.',
      inputSchema: { type: 'object', additionalProperties: false, required: ['type', 'domain'], properties: {
        type: { type: 'string', enum: ['spf', 'dmarc'] }, domain: { type: 'string', maxLength: 253 },
        mechanisms: { type: 'array', maxItems: 30, items: { type: 'string', maxLength: 253 }, description: 'SPF mechanisms in evaluation order.' },
        policy: { type: 'string', maxLength: 16, pattern: '^(?:~all|-all|\\?all|\\+all|none|quarantine|reject)?$', description: 'SPF all policy (~all, -all, ?all, +all, or empty to omit) or DMARC policy (none, quarantine, reject). An unrecognized explicit value is rejected instead of silently substituted.' },
        rolloutStage: { type: 'string', enum: ['testing', 'confirmed'] }, confirmsNoSenders: { type: 'boolean' },
        testing: { type: 'string', enum: ['y', 'n'] }, rua: { type: 'string', maxLength: 320 },
        subdomainPolicy: { type: 'string', enum: ['none', 'quarantine', 'reject'] }, alignment: { type: 'string', enum: ['relaxed', 'strict'] }, reviewedReports: { type: 'boolean' },
      } },
      outputSchema: { type: 'object', required: ['type', 'host', 'record', 'validation', 'safetyWarnings', 'publishReady', 'request_budget'], properties: {
        type: { type: 'string', enum: ['spf', 'dmarc'] }, host: { type: 'string' }, record: { type: 'string' }, validation: { type: 'object' },
        safetyWarnings: { type: 'array', items: { type: 'string' } }, publishReady: { type: 'boolean' }, request_budget: { type: 'object' },
      } },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    {
      name: 'enrich_email_hops', title: 'Enrich public email delivery-hop IPs',
      description: 'Enrich up to 10 public IP addresses observed in received headers with bounded reverse-DNS and network registration evidence.',
      inputSchema: { type: 'object', additionalProperties: false, required: ['ips'], properties: { ips: { type: 'array', minItems: 1, maxItems: 10, uniqueItems: true, items: { type: 'string', maxLength: 45 } } } },
      outputSchema: { type: 'object', required: ['enriched', 'limit', 'request_budget'], properties: { enriched: { type: 'array', items: { type: 'object' } }, limit: { type: 'integer', enum: [10] }, request_budget: { type: 'object' } } },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    {
      name: 'get_email_security_report', title: 'Retrieve an email security report',
      description: 'Retrieve a previously created, unexpired single-domain or batch report by its 16-character report ID.',
      inputSchema: { type: 'object', additionalProperties: false, required: ['reportId'], properties: { reportId: { type: 'string', pattern: '^[A-Za-z0-9_-]{16}$' } } },
      outputSchema: { type: 'object', additionalProperties: true },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
  ];
}

class MessageTooLargeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MessageTooLargeError';
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

async function readMessage(request) {
  // Stream with the same byte cap the REST paths use instead of buffering
  // the whole body via arrayBuffer() before checking the limit.
  const reader = request.body?.getReader?.();
  if (!reader) throw new Error('Request body is required');
  const chunks = [];
  let totalBytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > MAX_MCP_REQUEST_BYTES) {
      await reader.cancel();
      throw new MessageTooLargeError('MCP request exceeds the 280 KiB limit');
    }
    chunks.push(value);
  }
  return JSON.parse(new TextDecoder().decode(bytes(chunks, totalBytes)));
}

function bytes(chunks, totalBytes) {
  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function rpcResult(id, result, version = MCP_PROTOCOL_VERSION) {
  return rpc({ jsonrpc: '2.0', id, result }, 200, version);
}

function rpcError(id, code, message, status = 200) {
  return rpc({ jsonrpc: '2.0', id, error: { code, message } }, status);
}

function rpc(payload, status = 200, version = MCP_PROTOCOL_VERSION) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      ...MCP_SECURITY_HEADERS,
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'MCP-Protocol-Version': version,
    },
  });
}

module.exports = { handleMcp };
