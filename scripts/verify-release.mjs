#!/usr/bin/env node
// Post-deployment gate for the exact checks required by the August 2026 review.
// This command sends two validation requests, so do not use it for a read-only
// production review.
//
// Browser workflows (`npm run test:browser`) are a separate release-time UI
// check and are not invoked here: this probe hits the live host and must stay
// small. Run Playwright locally (or via the documented GitHub Action notes)
// before shipping UI changes.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const PLACEHOLDER_REVISIONS = new Set(['dirty', 'unknown', 'unpinned']);

export function assertReleaseRevision(revision) {
  assert.match(revision || '', /^[0-9a-f]{7,40}$/i, 'expected revision must be a 7 to 40 character git hash');
  assert.ok(!PLACEHOLDER_REVISIONS.has(revision.toLowerCase()), 'expected revision must identify a committed release');
  return revision;
}

function assertBaseUrl(value) {
  const base = new URL(value);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname);
  assert.ok(base.protocol === 'https:' || (loopback && base.protocol === 'http:'), 'base URL must use HTTPS except on loopback');
  assert.equal(base.username, '', 'base URL must not contain credentials');
  assert.equal(base.password, '', 'base URL must not contain credentials');
  base.pathname = base.pathname.replace(/\/$/, '');
  base.search = '';
  base.hash = '';
  return base.toString().replace(/\/$/, '');
}

async function readJson(response, label) {
  assert.equal(response.status, 200, `${label} returned HTTP ${response.status}`);
  assert.match(response.headers.get('content-type') || '', /^application\/json\b/i, `${label} did not return JSON`);
  return response.json();
}

export async function verifyHealth(base, expectedRevision, fetchImpl = fetch) {
  const health = await readJson(await fetchImpl(`${base}/api/health`, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(15_000)
  }), 'health check');
  assert.equal(health.ok, true, 'health check did not report ok');
  assert.equal(health.liveness, true, 'health check did not report liveness');
  assert.equal(health.source_revision, expectedRevision, `health check reports revision ${health.source_revision || 'missing'}`);
  return health;
}

async function validateDmarc(base, record, fetchImpl) {
  return readJson(await fetchImpl(`${base}/api/records/validate`, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'dmarc', domain: 'example.com', record }),
    signal: AbortSignal.timeout(15_000)
  }), `DMARC validation for ${record}`);
}

export async function verifyDmarcExamples(base, fetchImpl = fetch) {
  const valid = await validateDmarc(base, 'V = DMARC1 ; p=reject; psd=u;', fetchImpl);
  assert.equal(valid.valid, true, `valid RFC 9989 record was rejected: ${(valid.errors || []).join('; ')}`);

  const invalid = await validateDmarc(base, 'v=dmarc1; p=reject;', fetchImpl);
  assert.equal(invalid.valid, false, 'lower-case DMARC version was accepted');
  assert.ok((invalid.errors || []).some(error => /v=DMARC1/.test(error)), 'lower-case version failure did not identify the DMARC version rule');
}

export function runHtmlAudit(base) {
  const audit = fileURLToPath(new URL('./audit-html.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [audit, base], { stdio: 'inherit' });
  assert.equal(result.status, 0, 'HTML and contract audit failed');
}

export async function verifyRelease(baseValue, expectedRevision, fetchImpl = fetch) {
  const base = assertBaseUrl(baseValue);
  assertReleaseRevision(expectedRevision);
  const health = await verifyHealth(base, expectedRevision, fetchImpl);
  console.log(`ok   health reports released revision ${health.source_revision}`);
  runHtmlAudit(base);
  await verifyDmarcExamples(base, fetchImpl);
  console.log('ok   RFC 9989 whitespace and psd=u record accepted');
  console.log('ok   lower-case DMARC version rejected');
  console.log(`\nRelease verification passed for ${base}`);
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : '';
if (invokedPath === import.meta.url) {
  const [base, expectedRevision] = process.argv.slice(2);
  if (!base || !expectedRevision) {
    console.error('Usage: node scripts/verify-release.mjs <https://base-url> <expected-git-revision>');
    process.exit(2);
  }
  verifyRelease(base, expectedRevision).catch(error => {
    console.error(`Release verification failed: ${error.message}`);
    process.exit(1);
  });
}
