'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const {
  MAX_HEADER_BYTES,
  alignment,
  analyzeEmailHeaders,
  authorDomainsFromField,
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

  it('flags several Author Domains inside a single From field', () => {
    const result = analyzeEmailHeaders([
      'From: a@example.com, b@evil.example',
      'Authentication-Results: mx.receiver.example; spf=pass; dkim=pass header.d=example.com; dmarc=pass'
    ].join('\r\n'));
    assert.equal(result.summary.status, 'fail');
    assert.equal(result.summary.verdict, 'Suspicious header structure found');
    assert.equal(result.checks.some(check => check.title === 'From field lists multiple domains'), true);
  });

  it('does not treat display names, comments, or same-domain mailboxes as extra Author Domains', () => {
    assert.deepEqual(authorDomainsFromField('Alice (old alice@legacy.example) <alice@example.com>'), ['example.com']);
    assert.deepEqual(authorDomainsFromField('Alice <alice@example.com>, Bob <bob@example.com>'), ['example.com']);
    const result = analyzeEmailHeaders([
      'From: "billing@example.com accounts" (old billing@legacy.example) <billing@example.com>',
      'Authentication-Results: mx.receiver.example; spf=pass'
    ].join('\r\n'));
    assert.equal(result.checks.some(check => check.title === 'From field lists multiple domains'), false);
  });

  describe('hop IP extraction', () => {
    const receivedWith = address =>
      `Received: from mail.example (${address}) by mx.receiver.example; Thu, 23 Jul 2026 20:00:00 +0100`;

    function ipsFor(address) {
      return analyzeEmailHeaders([
        'From: Sender <sender@example.com>',
        receivedWith(address)
      ].join('\r\n')).ips;
    }

    it('keeps plain IPv4 and globally routable hexadecimal IPv6', () => {
      assert.deepEqual(ipsFor('[93.184.216.34]').filter(ip => ip === '93.184.216.34'), ['93.184.216.34']);
      assert.deepEqual(ipsFor('[2606:4700:4700::1111]'), ['2606:4700:4700::1111']);
    });

    it('unwraps RFC 5321 IPv6 address literals instead of gluing on the label', () => {
      assert.deepEqual(ipsFor('[IPv6:2606:4700:4700::1111]'), ['2606:4700:4700::1111']);
      // The fabricated "6:2001:db8::1" shape must never appear.
      assert.equal(ipsFor('[IPv6:2001:db8::1]').includes('6:2001:db8::1'), false);
    });

    it('reads IPv4-embedded IPv6 whole or drops it whole, never a truncation', () => {
      // ::ffff:/96 is ipv4-mapped, which this tool deliberately filters.
      const mapped = ipsFor('[::ffff:198.51.100.9]');
      assert.equal(mapped.includes('::ffff:198'), false);
      assert.equal(mapped.includes('198.51.100.9'), false);
      assert.deepEqual(mapped, []);

      // Documentation-prefix embedded form must not surface "::192" either.
      assert.equal(ipsFor('[2001:db8::192.0.2.1]').includes('2001:db8::192'), false);

      // A routable embedded form is extracted intact for enrichment.
      assert.deepEqual(ipsFor('[2606:4700::192.0.2.25]'), ['2606:4700::192.0.2.25']);
    });

    it('rejects impossible octets instead of parsing a neighbouring token', () => {
      assert.deepEqual(ipsFor('(999.1.2.3)'), []);
    });
  });

  it('rejects oversized input', () => {
    assert.throws(
      () => analyzeEmailHeaders(`Subject: ${'x'.repeat(MAX_HEADER_BYTES)}`),
      /256 KB/
    );
  });
});
