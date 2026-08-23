import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const require = createRequire(import.meta.url);
const {
  assessReportAuthorisation,
  isExternalReportDestination,
  reportAuthorisationName
} = require('../dmarc-reporting.js');

function records(values, dnsStatus) {
  const result = [...values];
  Object.defineProperty(result, 'dnsStatus', { value: dnsStatus, enumerable: false });
  return result;
}

test('external reporting compares organisational domains', () => {
  assert.equal(isExternalReportDestination('mail.example.co.uk', 'reports@example.co.uk'), false);
  assert.equal(isExternalReportDestination('example.com', 'reports@processor.example'), true);
  assert.equal(
    reportAuthorisationName('example.com', 'reports@processor.example'),
    'example.com._report._dmarc.processor.example'
  );
});

test('authorisation results keep positive, negative, and transient DNS states distinct', () => {
  assert.equal(
    assessReportAuthorisation('example.com', 'reports@processor.example', records(['v=DMARC1;'], 'ok')).status,
    'authorised'
  );
  assert.equal(
    assessReportAuthorisation('example.com', 'reports@processor.example', records([], 'nodata')).status,
    'unauthorised'
  );
  assert.equal(
    assessReportAuthorisation('example.com', 'reports@processor.example', records([], 'timeout')).status,
    'unknown'
  );
  assert.equal(
    assessReportAuthorisation('example.com', 'reports@processor.example', records(['v=dmarc1;'], 'ok')).status,
    'unauthorised'
  );
});
