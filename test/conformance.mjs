import assert from 'node:assert/strict';
import net from 'node:net';
import { spawn } from 'node:child_process';

// A stale dev server left by a crashed or previous run must never answer for
// this suite, so bind an ephemeral listener to reserve a free port instead of
// racing every run onto one hard-coded number.
const port = await new Promise((resolve, reject) => {
  const probe = net.createServer();
  probe.once('error', reject);
  probe.listen(0, '127.0.0.1', () => {
    const address = probe.address();
    probe.close(() => resolve(address.port));
  });
});
const base = `http://127.0.0.1:${port}`;
const worker = spawn('./node_modules/.bin/wrangler', ['dev', '--local', '--host', '127.0.0.1', '--port', String(port)], { stdio: ['ignore', 'pipe', 'pipe'] });
// Drain the child streams and retain only unexpected fault diagnostics.
let workerFaults = '';
for (const stream of [worker.stdout, worker.stderr]) stream.on('data', chunk => {
  for (const line of String(chunk).split('\n')) {
    if (line.includes('Unhandled request fault')) workerFaults = `${workerFaults}\n${line}`.slice(-4000);
  }
});
let postSequence = 0;

async function waitForWorker() {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      if ((await fetch(base)).ok) return;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error('Local Worker did not start');
}

async function post(path, body) {
  const response = await fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'CF-Connecting-IP': `203.0.113.${(postSequence++ % 200) + 1}` },
    body: JSON.stringify(body)
  });
  const data = await response.json();
  assert.equal(response.ok, true, JSON.stringify(data));
  return data;
}

async function postResponse(path, body, headers = {}) {
  return fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body)
  });
}

  try {
    await waitForWorker();
    assert.equal((await fetch(base, { method: 'HEAD' })).status, 200, 'HEAD serves the app shell');
    assert.equal((await fetch(base + '/api/health', { method: 'HEAD' })).status, 200, 'HEAD probes the health endpoint');
    const health = await fetch(base + '/api/health');
    assert.equal(health.headers.get('access-control-allow-origin'), '*', 'health answers cross-origin monitors');

    // Machine surfaces must answer with the documented JSON error envelope.
    const wrongMethod = await fetch(base + '/api/check');
    assert.equal(wrongMethod.status, 405, 'known API path hit with the wrong verb answers 405');
    assert.equal(wrongMethod.headers.get('allow'), 'POST', 'Allow lists supported methods');
    assert.match((await wrongMethod.json()).error, /Method GET is not allowed/, '405 body stays parseable JSON');
    const unknownApi = await fetch(base + '/api/nope');
    assert.equal(unknownApi.status, 404, 'unknown API paths answer 404');
    assert.ok(unknownApi.headers.get('content-type').includes('application/json'), 'unknown API paths stay JSON');
    assert.deepEqual(await unknownApi.json(), { error: 'Not found' });

    // Report routes are dynamic resources: wrong verbs get the same 405 +
    // Allow contract as static routes, and unknown paths stay free of charge.
    const wrongReportMethod = await fetch(base + '/api/reports/aaaaaaaaaaaaaaaa', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(wrongReportMethod.status, 405, 'report routes answer 405 for unsupported verbs');
    assert.equal(wrongReportMethod.headers.get('allow'), 'GET, HEAD, DELETE', 'Allow lists report retrieval methods');
    const postUnknownApi = await fetch(base + '/api/nope', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'CF-Connecting-IP': `203.0.113.${(postSequence++ % 200) + 1}` },
      body: '{}'
    });
    assert.equal(postUnknownApi.status, 404, 'unrouted POST paths answer 404 without reaching a limiter');

    // MCP paths speak their own preflight contract (POST, OPTIONS) instead
    // of inheriting the REST surface's global CORS advertisement.
    const mcpPreflight = await fetch(base + '/mcp/v2', { method: 'OPTIONS' });
    assert.equal(mcpPreflight.status, 204, 'MCP answers its own preflight');
    assert.equal(mcpPreflight.headers.get('access-control-allow-methods'), 'POST, OPTIONS');
    assert.equal((await fetch(base + '/api/check', { method: 'OPTIONS' })).headers.get('access-control-allow-methods'), 'GET, POST, DELETE, OPTIONS', 'REST keeps the global preflight');
    assert.equal((await fetch(base + '/api/check', { method: 'OPTIONS' })).headers.get('access-control-allow-headers')?.toLowerCase().includes('authorization'), false, 'REST does not advertise unused Authorization');

    // MCP end-to-end over HTTP: everything above only proves routing; the
    // JSON-RPC lifecycle, tool dispatch, and error shapes must work against
    // a real running worker too.
    const mcpCall = async (message, headers = {}) => fetch(base + '/mcp/v2', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'accept': 'application/json, text/event-stream',
        'CF-Connecting-IP': `203.0.113.${(postSequence++ % 200) + 1}`,
        ...headers
      },
      body: JSON.stringify(message)
    });
    const initialized = await (await mcpCall({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25' } })).json();
    assert.equal(initialized.result.protocolVersion, '2025-11-25', 'initialize negotiates a supported version');
    assert.ok(initialized.result.serverInfo?.name, 'initialize names the server');
    const downgrade = await (await mcpCall({ jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '2999-01-01' } })).json();
    assert.equal(downgrade.result.protocolVersion, '2025-11-25', 'a future version negotiates down instead of stranding the client');
    const listed = await (await mcpCall({ jsonrpc: '2.0', id: 3, method: 'tools/list' })).json();
    assert.equal(listed.result.tools.length, 9, 'tools/list serves the nine documented tools');
    const headerToolCall = await (await mcpCall({
      jsonrpc: '2.0', id: 4, method: 'tools/call',
      params: { name: 'analyze_email_headers', arguments: { headers: 'From: sender@example.com\r\n' } }
    })).json();
    assert.equal(headerToolCall.result.isError, false);
    assert.equal(headerToolCall.result.structuredContent.summary.status, 'warn', 'a receiver-report-less paste warns through MCP like REST');
    const unknownTool = await (await mcpCall({
      jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'no_such_tool', arguments: {} }
    })).json();
    assert.match(unknownTool.error.message, /Unknown tool name: no_such_tool/, 'unknown-tool errors name the tool');
    const emptyEnrich = await (await mcpCall({
      jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'enrich_email_hops', arguments: { ips: [] } }
    })).json();
    assert.equal(emptyEnrich.result.isError, true, 'an empty enrichment is refused like its REST twin');
    assert.match(emptyEnrich.result.content[0].text, /1 to 10 unique public/);
    const notification = await mcpCall({ jsonrpc: '2.0', method: 'notifications/initialized' });
    assert.equal(notification.status, 202, 'notifications answer 202');
    const batched = await mcpCall([{ jsonrpc: '2.0', id: 7, method: 'ping' }]);
    assert.equal(batched.status, 400, 'batch requests are refused');
    const badAccept = await fetch(base + '/mcp/v2', {
      method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json', 'CF-Connecting-IP': `203.0.113.${(postSequence++ % 200) + 1}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'ping' })
    });
    assert.equal(badAccept.status, 406, 'the Accept contract is enforced');

    // A trailing slash names the same resource, so wrong verbs still get the
    // route's own 405+Allow contract and HEAD probes stay available.
    const slashWrongVerb = await fetch(base + '/api/check/');
    assert.equal(slashWrongVerb.status, 405, 'trailing-slash API paths answer their resource contract');
    assert.equal(slashWrongVerb.headers.get('allow'), 'POST');
    const doubleSlashWrongVerb = await fetch(base + '/api/check//');
    assert.equal(doubleSlashWrongVerb.status, 405, 'multi-slash API paths answer their resource contract too');
    assert.equal(doubleSlashWrongVerb.headers.get('allow'), 'POST');
    const headMalformedReport = await fetch(base + '/api/reports/short', { method: 'HEAD' });
    assert.equal(headMalformedReport.status, 404, 'HEAD report probes share the GET id validation');

    // An explicit but unrecognized builder policy must fail loudly instead
    // of silently publishing a different record than the caller asked for.
    const badPolicy = await fetch(base + '/api/v2/record-build', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'CF-Connecting-IP': `203.0.113.${(postSequence++ % 200) + 1}` },
      body: JSON.stringify({ type: 'spf', domain: 'example.com', policy: 'strict' })
    });
    assert.equal(badPolicy.status, 400, 'unrecognized explicit policy values are rejected');
    assert.match((await badPolicy.json()).error, /policy must be one of/);

  const evaluationCases = [
    ['IPv4 pass', 'v=spf1 ip4:192.0.2.0/24 -all', '192.0.2.44', 'pass'],
    ['IPv4 fail', 'v=spf1 ip4:192.0.2.0/24 -all', '198.51.100.7', 'fail'],
    ['softfail', 'v=spf1 ~all', '198.51.100.7', 'softfail'],
    ['neutral', 'v=spf1 ?all', '198.51.100.7', 'neutral'],
    ['IPv6 pass', 'v=spf1 ip6:2001:db8::/32 -all', '2001:db8::1', 'pass'],
    ['unknown mechanism', 'v=spf1 madeup:example.test -all', '192.0.2.1', 'permerror'],
    ['bad IPv4 CIDR', 'v=spf1 ip4:192.0.2.1/99 -all', '192.0.2.1', 'permerror']
  ];
  for (const [name, record, ip, expected] of evaluationCases) {
    const data = await post('/api/spf/evaluate', {
      domain: 'fixture.example', sender: 'sender@fixture.example',
      helo: 'helo.fixture.example', record, ip
    });
    assert.equal(data.status.result, expected, name);
  }

  for (const record of [
    'v=spf1 ip4:192.0.2.1/24/7 -all',
    'v=spf1 ip6:1:2:3:4:5:6:7 -all',
    'v=spf1 a/999 -all'
  ]) {
    const data = await post('/api/records/validate', { type: 'spf', domain: '', record });
    assert.equal(data.valid, false, record);
  }

  for (const record of [
    'V=SpF1 -ALL',
    'v=SPF1 ip4:192.0.2.1 ~ALL'
  ]) {
    const data = await post('/api/records/validate', { type: 'spf', domain: '', record });
    assert.equal(data.valid, true, `case-insensitive SPF validation: ${record}`);
  }

  for (const [index, [path, body, expectedStatus]] of [
    ['/api/check', null, 400],
    ['/api/header/enrich', { ips: '8.8.8.8' }, 400],
    ['/api/check', { domain: 'bad..example.com' }, 400],
    ['/api/check', { domain: 'office.lan' }, 400],
    ['/api/batch', { domains: Array.from({ length: 26 }, (_, item) => `host${item}.example.com`) }, 413]
  ].entries()) {
    const response = await postResponse(path, body, { 'CF-Connecting-IP': `203.0.113.${100 + index}` });
    assert.equal(response.status, expectedStatus, `stable input status for ${path}`);
  }

  const batchWithRejection = await post('/api/batch', { domains: ['example.com', 'bad..example.com'] });
  assert.equal(batchWithRejection.validation.rejected.length, 1);
  assert.equal(batchWithRejection.validation.rejected[0].error, 'Invalid public domain');

  // Budget-priority regression: on a worst-case multi-MX domain, scored
  // controls must complete before the unscored PTR observation consumes the
  // remaining subrequests. gmail.com publishes five MX hosts and only
  // date-based (2023…) DKIM selectors, so an exhausted-before-DKIM run shows
  // up as zero discovered selectors.
  const worstCase = await post('/api/check', { domain: 'gmail.com' });
  // gmail.com publishes `v=spf1 redirect=_spf.google.com` and the target ends
  // in ~all, so the honest terminal-strength verdict is warn (soft fail), not
  // the pass this record earned before redirect strength was evaluated.
  assert.equal(worstCase.spf.status, 'warn', 'gmail.com SPF resolves within budget to its real ~all strength');
  assert.equal(worstCase.spf.unknown, false, 'gmail.com SPF must not be inconclusive');
  assert.ok(
    (worstCase.dkim.selectors || []).length > 0,
    `DKIM selector discovery must get budget before PTR; got ${(worstCase.dkim.selectors || []).length} selectors`
  );
  assert.ok(
    !worstCase.unknown_controls.includes('dkim'),
    `DKIM must not be budget-starved; unknown_controls: ${worstCase.unknown_controls.join(', ')}`
  );
  assert.equal(
    worstCase.transport.policy?.fetched, true,
    `MTA-STS policy fetch must succeed via manual redirect handling; got: ${worstCase.transport.policy?.error || 'no policy object'}`
  );

  // Report lifecycle: analysis does not persist unless share is requested.
  // The gmail.com check above is a cacheable analysis; a follow-up with
  // share:true must mint a bearer id without re-running the DoH ladder as a
  // required side effect of sharing.
  assert.equal(worstCase.share?.available, false, 'domain checks do not persist unless share is requested');
  assert.equal(worstCase.id || null, null, 'unshared domain checks must not mint a report id');
  const shared = await post('/api/check', { domain: 'gmail.com', share: true });
  assert.equal(shared.freshness?.cached, true, 'the share follow-up may reuse the analysis cache');
  const shareId = shared.share?.id;
  assert.match(shareId || '', /^[A-Za-z0-9_-]{16}(?:[A-Za-z0-9_-]{16})?$/, 'an opted-in domain check mints a bearer report id');
  assert.equal(shareId.length, 32, 'new report ids are 128-bit');
  const storedGet = await fetch(base + `/api/reports/${shareId}`);
  assert.equal(storedGet.status, 200);
  assert.equal(storedGet.headers.get('cache-control'), 'private, no-store', 'stored reports are not cacheable');
  assert.equal(storedGet.headers.get('x-report-retention-days'), '14');
  assert.equal((await storedGet.json()).domain, worstCase.domain);
  assert.equal((await fetch(base + `/api/reports/${shareId}`, { method: 'HEAD' })).status, 200, 'HEAD probes a live report');
  const exported = await fetch(base + `/api/reports/${shareId}/export`);
  assert.equal(exported.status, 200);
  assert.match(exported.headers.get('content-disposition') || '', /^attachment; filename="email-security-gmail\.com\.json"$/);
  const mcpReport = await (await mcpCall({
    jsonrpc: '2.0', id: 9, method: 'tools/call',
    params: { name: 'get_email_security_report', arguments: { reportId: shareId } }
  })).json();
  assert.equal(mcpReport.result.isError, false, 'MCP retrieves an opted-in report');
  assert.equal(mcpReport.result.structuredContent.domain, 'gmail.com');
  const revoked = await fetch(base + `/api/reports/${shareId}`, { method: 'DELETE' });
  assert.equal(revoked.status, 200, 'DELETE revokes a bearer report');
  assert.equal((await revoked.json()).revoked, true);
  assert.equal((await fetch(base + `/api/reports/${shareId}`)).status, 404, 'a revoked report is gone');

  const current = await post('/api/records/validate', {
    type: 'dmarc', domain: '',
    record: 'v=DMARC1; p=reject; t=y; np=quarantine; psd=n; fo=0:1; rua=mailto:dmarc@example.com;'
  });
  assert.equal(current.valid, true);
  const currentDefaultPsd = await post('/api/records/validate', {
    type: 'dmarc', domain: '', record: ' V = DMARC1 ; p=reject; psd=u;'
  });
  assert.equal(currentDefaultPsd.valid, true, 'RFC 9989 accepts whitespace around v= and the default psd=u value');
  for (const record of [
    'v=dmarc1; p=reject;',
    'v=DMARC1; p=reject; t=invalid;',
    'v=DMARC1; p=reject; np=banana;',
    'v=DMARC1; p=reject; psd=maybe;'
  ]) {
    const data = await post('/api/records/validate', { type: 'dmarc', domain: '', record });
    assert.equal(data.valid, false, record);
  }
  const historic = await post('/api/records/validate', {
    type: 'dmarc', domain: '', record: 'v=DMARC1; p=reject; pct=50;'
  });
  assert.equal(historic.valid, true);
  assert.match(historic.warnings.join(' '), /historic/i);

  const headers = await post('/api/header/analyze', {
    headers: [
      'From: Example <sender@example.com>',
      'Return-Path: <bounce@mail.example.com>',
      'Authentication-Results: mx.receiver.example; spf=pass smtp.mailfrom=bounce@mail.example.com; dkim=pass header.d=mail.example.com; dmarc=pass header.from=example.com',
      'Received: from sender.example (sender.example [8.8.8.8]) by mx.receiver.example; Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n')
  });
  assert.equal(headers.summary.status, 'pass');
  assert.equal(headers.summary.authservId, 'mx.receiver.example');
  assert.equal(headers.hops.length, 1);

  const oversizedBody = JSON.stringify({ record: 'x'.repeat(17 * 1024) });
  const oversizedResponse = await fetch(base + '/api/records/validate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(oversizedBody));
        controller.close();
      }
    }),
    duplex: 'half'
  });
  assert.equal(oversizedResponse.status, 413);
  assert.equal(oversizedResponse.headers.get('access-control-allow-origin'), '*');

  // Negative transport cases: malformed bodies answer the documented JSON
  // envelope instead of an opaque failure.
  const invalidJson = await fetch(base + '/api/check', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'CF-Connecting-IP': `203.0.113.${(postSequence++ % 200) + 1}` },
    body: '{not json'
  });
  assert.equal(invalidJson.status, 400, `invalid JSON answers 400${workerFaults}`);
  assert.match((await invalidJson.json()).error, /valid JSON/);
  const wrongContentType = await postResponse('/api/check', { domain: 'example.com' }, { 'content-type': 'text/plain', 'CF-Connecting-IP': `203.0.113.${(postSequence++ % 200) + 1}` });
  assert.equal(wrongContentType.status, 415, 'REST analysis POSTs require application/json');

  // Standard-limiter warmup: /api/header/analyze is the cheapest POST route
  // (stateless, no DNS), and record validation moved to the expensive class.
  const runToken = `${process.pid}-${Date.now()}`;
  const client = `conformance-${runToken}-standard`;
  const standardBody = { headers: 'From: sender@example.com\r\n' };
  for (let attempt = 0; attempt < 60; attempt++) {
    let response = await postResponse('/api/header/analyze', standardBody, { 'CF-Connecting-IP': client });
    // workerd's simulated limiter binding fails intermittently under load
    // (observed as a bare 503 on warmup request 8). A 503 is a dependency
    // outage, not a rate-limit answer, so retry that attempt once.
    if (response.status === 503) {
      await new Promise(resolve => setTimeout(resolve, 250));
      response = await postResponse('/api/header/analyze', standardBody, { 'CF-Connecting-IP': client });
    }
    assert.equal(response.status, 200, `rate-limit warmup request ${attempt + 1}`);
  }
  assert.equal((await fetch(base + '/api/health', { headers: { 'CF-Connecting-IP': client } })).status, 200);
  assert.equal((await fetch(base + '/api/header/analyze', {
    method: 'OPTIONS', headers: { 'CF-Connecting-IP': client }
  })).status, 200);
  const limited = await postResponse('/api/header/analyze', standardBody, { 'CF-Connecting-IP': client });
  assert.equal(limited.status, 429);
  assert.match(limited.headers.get('retry-after') || '', /^\d+$/);
  assert.equal(limited.headers.get('access-control-allow-origin'), '*');

  // Invalid payloads stop before DNS, enrichment, or SPF evaluation while still
  // exercising each expensive route's shared namespace.
  const expensiveClient = `conformance-${runToken}-expensive`;
  for (const [path, body, expectedStatus] of [
    ['/api/check', {}, 400],
    ['/api/header/enrich', { ips: [] }, 400],
    ['/api/spf/inspect', { domain: '' }, 400],
    ['/api/spf/evaluate', { domain: '', ip: '' }, 400]
  ]) {
    const response = await postResponse(path, body, { 'CF-Connecting-IP': expensiveClient });
    assert.equal(response.status, expectedStatus, `expensive route warmup ${path}`);
  }
  for (let attempt = 4; attempt < 10; attempt++) {
    const response = await postResponse('/api/spf/evaluate', {
      domain: '', ip: ''
    }, { 'CF-Connecting-IP': expensiveClient });
    assert.equal(response.status, 400, `expensive rate-limit warmup request ${attempt + 1}`);
  }
  const expensiveLimited = await postResponse('/api/spf/evaluate', {
    domain: '', ip: ''
  }, { 'CF-Connecting-IP': expensiveClient });
  assert.equal(expensiveLimited.status, 429);
  assert.match(expensiveLimited.headers.get('retry-after') || '', /^\d+$/);
  assert.equal(expensiveLimited.headers.get('access-control-allow-origin'), '*');

  console.log(`Conformance corpus passed: ${evaluationCases.length + 12} cases plus request-boundary, rate-limit, MCP, and report-lifecycle checks`);
} finally {
  worker.kill('SIGTERM');
}
