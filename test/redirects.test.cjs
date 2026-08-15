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

test('canonical HTTPS email requests are not redirected', () => {
  assert.equal(redirectForRequest(new Request('https://email.illek.ie/')), null);
});
