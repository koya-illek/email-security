'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const {
  MAX_HEADER_BYTES,
  alignment,
  analyzeEmailHeaders,
  domainFromAddress,
  parseHeaders
} = require('../header-analyzer');

const baseHeaders = [
  'From: Example Billing <billing@example.com>',
  'Return-Path: <bounce@mail.example.com>',
  'Reply-To: support@example.com',
  'Subject: Your monthly invoice',
  'Message-ID: <invoice-123@mail.example.com>',
  'Date: Thu, 23 Jul 2026 20:00:00 +0100',
  'Authentication-Results: mx.receiver.example;',
  ' spf=pass smtp.mailfrom=bounce@mail.example.com;',
  ' dkim=pass header.d=mail.example.com;',
  ' dmarc=pass header.from=example.com',
  'Received: from outbound.example.net (outbound.example.net [8.8.8.8])',
  ' by mx.receiver.example with ESMTPS id abc123; Thu, 23 Jul 2026 20:00:00 +0100',
  'Received: from app.internal (app.internal [10.0.0.4])',
  ' by outbound.example.net with ESMTP id xyz789; Thu, 23 Jul 2026 19:59:00 +0100'
].join('\r\n');

describe('Header Analyzer', () => {
  it('accepts strict and relaxed organisational-domain alignment', () => {
    assert.deepEqual(alignment('example.com', 'example.com'), { aligned: true, mode: 'strict' });
    assert.deepEqual(alignment('example.com', 'mail.example.com'), { aligned: true, mode: 'relaxed' });
    assert.deepEqual(alignment('example.co.uk', 'bounce.example.co.uk'), { aligned: true, mode: 'relaxed' });
  });

  it('requires a DNS label boundary and rejects deceptive suffixes', () => {
    assert.equal(alignment('example.com', 'notexample.com').aligned, false);
    assert.equal(alignment('example.com', 'example.com.attacker.test').aligned, false);
  });

  it('parses quoted display names and angle-bracket addresses', () => {
    assert.equal(domainFromAddress('"Billing, Example" <billing@mail.example.com>'), 'mail.example.com');
  });

  it('reports a complete receiver pass without contradictory alignment warnings', () => {
    const result = analyzeEmailHeaders(baseHeaders);
    assert.equal(result.summary.status, 'pass');
    assert.equal(result.summary.passCount, 3);
    assert.equal(result.summary.authservId, 'mx.receiver.example');
    assert.equal(result.ips.includes('8.8.8.8'), true);
    assert.equal(result.ips.includes('10.0.0.4'), false);
    assert.equal(result.checks.some(check => check.status === 'warn' || check.status === 'fail'), false);
    assert.match(result.checks.find(check => check.title.startsWith('Envelope sender')).title, /relaxed alignment/);
    assert.match(result.checks.find(check => check.title.startsWith('DKIM signing')).title, /relaxed alignment/);
  });

  it('does not treat an unaligned DKIM suffix as aligned', () => {
    const result = analyzeEmailHeaders([
      'From: Accounts <accounts@example.com>',
      'Return-Path: <attacker@evil.test>',
      'Authentication-Results: mx.receiver.example; spf=pass smtp.mailfrom=attacker@evil.test; dkim=pass header.d=notexample.com; dmarc=fail header.from=example.com'
    ].join('\r\n'));
    assert.equal(result.summary.status, 'fail');
    assert.equal(result.checks.some(check => check.title === 'DKIM signing domain does not align'), true);
  });

  it('labels pasted authentication as receiver-reported rather than verified', () => {
    const result = analyzeEmailHeaders(
      'From: Accounts <accounts@example.com>\r\nAuthentication-Results: attacker.invalid; spf=pass; dkim=pass header.d=example.com; dmarc=pass'
    );
    assert.equal(result.summary.status, 'warn');
    assert.equal(result.summary.confidence, 'Reported by pasted headers');
    assert.match(result.checks[0].detail, /does not cryptographically re-run/);
    assert.match(result.checks[0].recommendation, /can be forged or incomplete/);
  });

  it('uses the topmost receiver report and flags conflicting downstream results', () => {
    const result = analyzeEmailHeaders([
      'From: Sender <sender@example.com>',
      'Authentication-Results: final.receiver; spf=fail; dkim=fail; dmarc=fail',
      'Authentication-Results: earlier.receiver; spf=pass; dkim=pass header.d=example.com; dmarc=pass'
    ].join('\r\n'));
    assert.equal(result.summary.authservId, 'final.receiver');
    assert.equal(result.summary.status, 'fail');
    assert.equal(result.checks.some(check => /Different authentication outcomes/.test(check.detail)), true);
  });

  it('does not count bestguesspass or missing evidence as pass', () => {
    const result = analyzeEmailHeaders([
      'From: Sender <sender@example.com>',
      'Authentication-Results: receiver.example; spf=none; dkim=none; dmarc=bestguesspass'
    ].join('\r\n'));
    assert.equal(result.summary.passCount, 0);
    assert.equal(result.summary.status, 'warn');
  });

  it('stops parsing at the message body', () => {
    const parsed = parseHeaders('From: sender@example.com\r\nSubject: Test\r\n\r\nAuthentication-Results: attacker; spf=pass');
    assert.equal(parsed.headers['authentication-results'], undefined);
  });

  it('flags duplicate From fields and implausible hop chronology', () => {
    const result = analyzeEmailHeaders([
      'From: First <first@example.com>',
      'From: Second <second@attacker.test>',
      'Received: from relay.example by receiver.example; Thu, 23 Jul 2026 19:00:00 +0100',
      'Received: from sender.example by relay.example; Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n'));
    assert.equal(result.summary.status, 'fail');
    assert.equal(result.checks.some(check => check.title === 'Multiple From headers'), true);
    assert.equal(result.checks.some(check => check.title === 'Delivery timestamps are out of sequence'), true);
  });

  it('rejects oversized input', () => {
    assert.throws(
      () => analyzeEmailHeaders(`Subject: ${'x'.repeat(MAX_HEADER_BYTES)}`),
      /256 KB/
    );
  });
});
