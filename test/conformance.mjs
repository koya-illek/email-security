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
  assert.equal(worstCase.spf.status, 'pass', 'gmail.com SPF should resolve within budget');
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

  const current = await post('/api/records/validate', {
    type: 'dmarc', domain: '',
    record: 'v=DMARC1; p=reject; t=y; np=quarantine; psd=n; fo=0:1; rua=mailto:dmarc@example.com;'
  });
  assert.equal(current.valid, true);
  for (const record of [
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

  const runToken = `${process.pid}-${Date.now()}`;
  const client = `conformance-${runToken}-standard`;
  for (let attempt = 0; attempt < 60; attempt++) {
    const response = await postResponse('/api/records/validate', {
      type: 'spf', domain: '', record: 'v=spf1 -all'
    }, { 'CF-Connecting-IP': client });
    assert.equal(response.status, 200, `rate-limit warmup request ${attempt + 1}`);
  }
  assert.equal((await fetch(base + '/api/health', { headers: { 'CF-Connecting-IP': client } })).status, 200);
  assert.equal((await fetch(base + '/api/records/validate', {
    method: 'OPTIONS', headers: { 'CF-Connecting-IP': client }
  })).status, 200);
  const limited = await postResponse('/api/records/validate', {
    type: 'spf', domain: '', record: 'v=spf1 -all'
  }, { 'CF-Connecting-IP': client });
  assert.equal(limited.status, 429);
  assert.match(limited.headers.get('retry-after') || '', /^\d+$/);
  assert.equal(limited.headers.get('access-control-allow-origin'), '*');

  // Invalid payloads stop before DNS, enrichment, or SPF evaluation while still
  // exercising each expensive route's shared namespace.
  const expensiveClient = `conformance-${runToken}-expensive`;
  for (const [path, body, expectedStatus] of [
    ['/api/check', {}, 400],
    ['/api/header/enrich', { ips: [] }, 200],
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

  console.log(`Conformance corpus passed: ${evaluationCases.length + 10} cases plus request-boundary and rate-limit checks`);
} finally {
  worker.kill('SIGTERM');
}
