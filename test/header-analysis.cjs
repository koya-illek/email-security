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

  it('resolves the From domain through RFC 5322 comments, not display-name asides', () => {
    // The bare-address scan used to take the last @-sign, so the comment
    // address drove alignment while the multi-author-domain check stayed
    // silent — a misanalysis with no failing check.
    assert.equal(domainFromAddress('alice@example.com (Bob@example.net)'), 'example.com');
    assert.equal(domainFromAddress('"Alice" <alice@example.com> (sent from phone@example.net)'), 'example.com');
    assert.deepEqual(authorDomainsFromField('alice@example.com (old alice@example.net)'), ['example.com']);
  });

  it('keeps Received keyword parsing out of comments', async () => {
    const result = analyzeEmailHeaders([
      'From: alice@example.com',
      'Received: from x.example (note by fake.example here) by mx.real.example;',
      ' Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n'));
    const hop = result.hops[0];
    assert.equal(hop.from, 'x.example');
    assert.equal(hop.by, 'mx.real.example');
    assert.ok(hop.date.includes('20:00:00'), 'date clause survives a semicolon-free comment');
  });

  it('reads the authserv-id past a leading comment and keeps quoted ids intact', () => {
    const commented = analyzeEmailHeaders([
      'From: alice@example.com',
      'Authentication-Results: (mx1.example server) mx1.example; spf=pass smtp.mailfrom=alice@example.com'
    ].join('\r\n'));
    assert.equal(commented.summary.authservId, 'mx1.example');

    const quoted = analyzeEmailHeaders([
      'From: alice@example.com',
      'Authentication-Results: "mx1.example"; spf=pass smtp.mailfrom=alice@example.com'
    ].join('\r\n'));
    assert.equal(quoted.summary.authservId, '"mx1.example"');
  });

  it('prefers the envelope-from SPF clause over a HELO clause in one header', () => {
    // First-wins used to report the HELO clause's fail; the mailfrom clause
    // is the message-level verdict per RFC 8601.
    const result = analyzeEmailHeaders([
      'From: alice@example.com',
      'Authentication-Results: mx.example; spf=fail smtp.helo=helo.example; spf=pass smtp.mailfrom=alice@example.com',
      'Received: from helo.example (helo.example [198.51.100.9]) by mx.example; Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n'));
    assert.equal(result.summary.spf, 'pass');
    assert.ok(result.checks.some(check => check.status === 'pass' && check.title.startsWith('SPF reported pass')));
  });
});

describe('TLS transport evidence', () => {
  it('extracts receiver-reported version and cipher from Received comments', () => {
    const result = analyzeEmailHeaders([
      'From: Example Billing <billing@example.com>',
      'Received: from outbound.example.net (outbound.example.net [8.8.8.8])',
      ' by mx.receiver.example with ESMTPS id abc123',
      ' (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384); Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n'));
    const hop = result.hops[0];
    assert.deepEqual(hop.tls, { version: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384' });
    assert.equal(hop.transportClass, 'tls');
    const transport = result.checks.find(check => check.title.includes('Every recorded hop shows TLS'));
    assert.ok(transport, 'a chain where every hop shows TLS earns the covered verdict');
    assert.match(transport.detail, /TLS 1\.3/);
    assert.match(transport.detail, /Cipher: TLS_AES_256_GCM_SHA384/);
  });

  it('reads Exchange-style "using TLSv1.2 with cipher" comments and partial coverage', () => {
    const result = analyzeEmailHeaders([
      'From: Example Billing <billing@example.com>',
      'Received: from edge.example (edge.example [198.51.100.9])',
      ' by mail.receiver.example with Microsoft SMTP Server (TLS)',
      ' id 123; Thu, 23 Jul 2026 20:00:00 +0100',
      'Received: from sender.example (sender.example [203.0.113.5])',
      ' by edge.example with ESMTP id 456 (using TLSv1.2 with cipher ECDHE-RSA-AES256-SHA384)',
      '; Thu, 23 Jul 2026 19:59:00 +0100'
    ].join('\r\n'));
    assert.equal(result.hops[0].tls, undefined, 'no decisive evidence on the topmost hop');
    assert.equal(result.hops[1].tls.version, 'TLS 1.2');
    assert.equal(result.hops[1].tls.cipher, 'ECDHE-RSA-AES256-SHA384');
    const partial = result.checks.find(check => check.title === 'TLS recorded on 1 of 2 hops');
    assert.ok(partial, 'partial coverage stays informational');
    assert.equal(partial.status, 'info');
  });

  it('warns only on positive cleartext tokens, never on missing evidence', () => {
    const cleartext = analyzeEmailHeaders([
      'From: Example Billing <billing@example.com>',
      'Received: from legacy.sender.example ([203.0.113.7])',
      ' by mx.receiver.example with ESMTP id abc; Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n'));
    const warning = cleartext.checks.find(check => check.title === 'Cleartext delivery recorded');
    assert.ok(warning, 'an ESMTP token positively claims no STARTTLS');
    assert.equal(warning.status, 'warn');

    const silent = analyzeEmailHeaders([
      'From: Example Billing <billing@example.com>',
      'Received: from mystery.example ([203.0.113.9]) by mx.receiver.example;',
      ' Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n'));
    assert.ok(!silent.checks.some(check => check.title.includes('Every recorded hop')), 'no token means no TLS claim');
    assert.ok(!silent.checks.some(check => check.title.includes('TLS') || check.title.includes('Cleartext')),
      'no comment and no token is no claim at all');
  });
});

describe('ARC chain evidence', () => {
  const arcHeaders = [
    'ARC-Authentication-Results: i=1; mx.origin.example; spf=pass smtp.mailfrom=bounce@origin.example; dkim=pass header.d=origin.example; dmarc=pass header.from=origin.example',
    'ARC-Message-Signature: i=1; a=rsa-sha256; d=origin.example; s=sel; b=AAA',
    'ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=sel; t=1; b=BBB',
    'ARC-Authentication-Results: i=2; mx.list.example; spf=fail smtp.mailfrom=bounce@origin.example; dkim=none; dmarc=fail header.from=origin.example',
    'ARC-Message-Signature: i=2; a=rsa-sha256; d=list.example; s=list; b=CCC',
    'ARC-Seal: i=2; a=rsa-sha256; d=list.example; s=list; t=2; b=DDD'
  ];

  it('reports a consistent chain with its newest archived results', () => {
    const result = analyzeEmailHeaders([
      'From: Example Billing <billing@example.com>',
      ...arcHeaders,
      'Authentication-Results: mx.final.example; spf=softfail smtp.mailfrom=bounce@origin.example; dkim=none; dmarc=fail header.from=example.com',
      'Received: from list.example ([192.0.2.10]) by mx.final.example with ESMTPS id z; Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n').replace(/^(?=[A-Z])/gm, '').replace(/\r\n(?![A-Z])/g, '\r\n '));
    const arcCheck = result.checks.find(check => check.title === 'ARC chain of 2 instance(s) recorded');
    assert.ok(arcCheck, 'a consistent two-instance chain is reported');
    assert.match(arcCheck.detail, /spf=fail, dkim=none, dmarc=fail/, 'the newest archived results are surfaced');
  });

  it('preserves an earlier pass when forwarding broke current authentication', () => {
    const result = analyzeEmailHeaders([
      'From: Example Billing <billing@example.com>',
      'ARC-Authentication-Results: i=1; mx.origin.example; spf=pass smtp.mailfrom=bounce@origin.example; dkim=pass header.d=origin.example; dmarc=pass header.from=origin.example',
      'ARC-Message-Signature: i=1; a=rsa-sha256; d=origin.example; s=sel; b=AAA',
      'ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=sel; t=1; b=BBB',
      'Authentication-Results: mx.final.example; spf=softfail smtp.mailfrom=bounce@list.example; dkim=none; dmarc=fail header.from=example.com',
      'Received: from list.example ([192.0.2.10]) by mx.final.example with ESMTPS id z; Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n'));
    const preserved = result.checks.find(check => check.title.includes('ARC preserves an earlier pass'));
    assert.ok(preserved, 'the archived pass is disclosed next to the current failure');
    assert.match(preserved.detail, /forwarding or list handling/);
  });

  it('warns on inconsistent instance numbering instead of trusting the chain', () => {
    const result = analyzeEmailHeaders([
      'From: Example Billing <billing@example.com>',
      'ARC-Authentication-Results: i=1; mx.origin.example; spf=pass smtp.mailfrom=bounce@origin.example; dmarc=pass header.from=origin.example',
      'ARC-Message-Signature: i=1; a=rsa-sha256; d=origin.example; s=sel; b=AAA',
      'ARC-Message-Signature: i=2; a=rsa-sha256; d=list.example; s=list; b=CCC',
      'ARC-Seal: i=2; a=rsa-sha256; d=list.example; s=list; t=2; b=DDD',
      'Received: from list.example ([192.0.2.10]) by mx.final.example with ESMTPS id z; Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n'));
    const broken = result.checks.find(check => check.title === 'ARC chain is inconsistent');
    assert.ok(broken, 'two signatures against one results header cannot extend trust');
    assert.equal(broken.status, 'warn');
    assert.match(broken.detail, /1 ARC-Authentication-Results/);
  });

  it('stays silent when no ARC headers exist', () => {
    const result = analyzeEmailHeaders([
      'From: Example Billing <billing@example.com>',
      'Received: from outbound.example.net ([8.8.8.8]) by mx.receiver.example with ESMTPS; Thu, 23 Jul 2026 20:00:00 +0100'
    ].join('\r\n'));
    assert.ok(!result.checks.some(check => /^ARC\b/.test(check.title)), 'no ARC verdict appears without ARC headers');
    assert.equal(result.evidence.arc, undefined);
  });
});
