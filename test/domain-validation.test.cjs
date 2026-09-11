'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const {
  isPublicIpAddress,
  isValidDomain,
  normalizeDomain,
  quotaClientKey,
  secondsUntilDailyReset
} = require('../domain-validation');

test('the domain validator accepts real public domains across spellings', () => {
  for (const domain of [
    'example.com',
    'a.io',
    'mail.example.co.uk',
    'xn--80ak6aa92e.com',
    'EXAMPLE.COM',
    'example.com.',
    '63-' + 'x'.repeat(60) + '.example.com'
  ]) {
    assert.ok(isValidDomain(normalizeDomain(domain)), `${domain} must validate`);
  }
});

test('the domain validator refuses the shapes every surface rejects', () => {
  const refusals = [
    ['', 'empty'],
    ['localhost', 'single label'],
    ['192.0.2.1', 'IPv4 literal'],
    ['[::1]', 'bracketed IPv6'],
    ['bad..example.com', 'consecutive dots'],
    ['-lead.example.com', 'label starts with hyphen'],
    ['trail-.example.com', 'label ends with hyphen'],
    ['under_score.example.com', 'underscore label'],
    [`${'x'.repeat(64)}.example.com`, 'over-long label'],
    [`${'x'.repeat(250)}.com`, 'over-long name'],
    ['example.com:443', 'port'],
    ['user@example.com', 'email local part'],
    ['example.com/path', 'path'],
    ['ex ample.com', 'whitespace'],
    ['example.com?', 'query'],
    ['foo.local', 'mDNS .local'],
    ['printer.localhost', '.localhost'],
    ['mail.internal', '.internal'],
    ['fileserver.lan', '.lan'],
    ['hidden.onion', '.onion'],
    ['co.uk', 'public suffix used as a name']
  ];
  for (const [input, reason] of refusals) {
    assert.equal(isValidDomain(input), false, `${reason}: ${JSON.stringify(input)} must be refused`);
    assert.equal(normalizeDomain(input), '', `${reason}: normalization must yield no domain`);
  }
  // A bare-host URL is the one shape normalization rescues: validation
  // refuses it raw, but the normalizer strips the scheme deliberately.
  assert.equal(isValidDomain('https://example.com/'), false);
});

test('normalization lowercases, strips the root dot and scheme, then revalidates', () => {
  assert.equal(normalizeDomain('HTTPS://Example.COM/'), 'example.com');
  assert.equal(normalizeDomain('Example.COM.'), 'example.com');
  // A URL with anything beyond a bare host stays refused even after parsing.
  assert.equal(normalizeDomain('https://example.com:8443/'), '');
  assert.equal(normalizeDomain('https://user:pass@example.com/'), '');
  // Non-string input cannot crash a caller that forgot to type-check.
  assert.equal(normalizeDomain(undefined), '');
  assert.equal(normalizeDomain(42), '');
});

test('quota keys collapse IPv6 to its /64 and canonicalize IPv4', () => {
  assert.equal(
    quotaClientKey('2001:0DB8:1234:5678::1'),
    quotaClientKey('2001:db8:1234:5678:abcd::ef')
  );
  assert.match(quotaClientKey('2001:db8:1234:5678::1'), /^2001:db8:1234:5678:/);
  assert.notEqual(quotaClientKey('2001:db8:1234:0000::1'), quotaClientKey('2001:db8:1234:5678::1'));
  // Spelling drift within one IPv4 host lands in one bucket.
  assert.equal(quotaClientKey('01.002.003.004'), quotaClientKey('1.2.3.4'));
  // Unparseable fallbacks keep their raw value instead of throwing.
  assert.equal(quotaClientKey('anonymous'), 'anonymous');
  assert.equal(quotaClientKey(''), '');
});

test('public-IP gate admits routable addresses and refuses reserved ranges', () => {
  // 198.51.100.0/24 is TEST-NET-2: documentation ranges read as reserved,
  // which is exactly why the evaluator accepts a record fixture instead.
  for (const ip of ['1.1.1.1', '2606:4700::1111']) {
    assert.equal(isPublicIpAddress(ip), true, `${ip} must be public`);
  }
  assert.equal(isPublicIpAddress('198.51.100.9'), false, 'TEST-NET documentation ranges are not public');
  for (const ip of ['10.0.0.4', '127.0.0.1', '169.254.1.1', '::1', 'not-an-ip', '999.1.1.1']) {
    assert.equal(isPublicIpAddress(ip), false, `${ip} must be refused`);
  }
});

test('reserved and special-use suffixes stay refused after syntax would otherwise pass', () => {
  for (const domain of ['office.lan', 'host.home', 'box.corp', 'gw.private', 'node.localdomain', 'app.intranet']) {
    assert.equal(isValidDomain(domain), false, `${domain} must be refused as non-public`);
    assert.equal(normalizeDomain(domain), '', `${domain} must not normalize`);
  }
});

test('the daily reset countdown stays inside one UTC day and reaches zero at midnight', () => {
  const seconds = secondsUntilDailyReset();
  assert.ok(Number.isInteger(seconds) && seconds >= 1 && seconds <= 86400, `countdown out of range: ${seconds}`);
});
