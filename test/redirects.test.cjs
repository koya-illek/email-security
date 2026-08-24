'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { redirectForRequest } = require('../redirects');

test('HTTP email homepage redirects permanently to canonical HTTPS', () => {
  const response = redirectForRequest(new Request('http://email.illek.ie/?from=test'));
  assert.equal(response.status, 308);
  assert.equal(response.headers.get('location'), 'https://email.illek.ie/?from=test');
});

test('HTTP email API paths redirect while preserving path and query', () => {
  const response = redirectForRequest(new Request('http://email.illek.ie/api/header/analyze?mode=full'));
  assert.equal(response.status, 308);
  assert.equal(response.headers.get('location'), 'https://email.illek.ie/api/header/analyze?mode=full');
});

test('spoofable local-looking headers cannot bypass the production HTTP redirect', () => {
  const headers = {
    Host: '127.0.0.1:8799',
    'CF-Connecting-IP': '127.0.0.1',
    'MF-Original-Hostname': 'localhost',
  };
  const response = redirectForRequest(new Request('http://email.illek.ie/?spoofed=1', { headers }));
  assert.equal(response.status, 308);
  assert.equal(response.headers.get('location'), 'https://email.illek.ie/?spoofed=1');
});

test('legacy checker alias uses one-hop canonical HTTPS redirect', () => {
  const response = redirectForRequest(new Request('http://checker.illek.ie/api/check?x=1'));
  assert.equal(response.status, 308);
  assert.equal(response.headers.get('location'), 'https://email.illek.ie/api/check?x=1');
});

test('alias redirects strip ports from the unroutable spelling', () => {
  const response = redirectForRequest(new Request('http://checker.illek.ie:8080/?x=1'));
  assert.equal(response.headers.get('location'), 'https://email.illek.ie/?x=1');
});

test('redirect responses keep the security header set', () => {
  const response = redirectForRequest(
    new Request('http://email.illek.ie/'),
    { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY' }
  );
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
});

test('canonical HTTPS email requests are not redirected', () => {
  assert.equal(redirectForRequest(new Request('https://email.illek.ie/')), null);
});

test('local development hosts stay unredirected, including bracketed IPv6', () => {
  for (const host of ['http://localhost:8787/', 'http://127.0.0.1:8787/', 'http://[::1]:8787/']) {
    assert.equal(redirectForRequest(new Request(host)), null, `${host} must not be upgraded`);
  }
  // The URL API keeps brackets in the hostname; a bare-string comparison
  // against '::1' never matches it.
  assert.equal(new URL('http://[::1]:8787/').hostname, '[::1]');
});
