import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

const port = 8797;
const base = `http://127.0.0.1:${port}`;
const worker = spawn('./node_modules/.bin/wrangler', ['dev', '--local', '--port', String(port)], { stdio: ['ignore', 'pipe', 'pipe'] });

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
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await response.json();
  assert.equal(response.ok, true, JSON.stringify(data));
  return data;
}

try {
  await waitForWorker();
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

  console.log(`Conformance corpus passed: ${evaluationCases.length + 9} cases`);
} finally {
  worker.kill('SIGTERM');
}
