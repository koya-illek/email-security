import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertReleaseRevision,
  verifyDmarcExamples,
  verifyHealth
} from '../scripts/verify-release.mjs';

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

test('release revisions must identify a clean git commit', () => {
  assert.equal(assertReleaseRevision('f85857f'), 'f85857f');
  for (const revision of ['', 'unknown', 'unpinned', 'f85857f-dirty', 'not-a-hash']) {
    assert.throws(() => assertReleaseRevision(revision));
  }
});

test('health verification rejects a stale deployment revision', async () => {
  const fetchImpl = async () => jsonResponse({
    ok: true,
    liveness: true,
    source_revision: '62e6fbc'
  });

  await assert.rejects(
    verifyHealth('https://email.example', 'f85857f', fetchImpl),
    /reports revision 62e6fbc/
  );
});

test('health verification accepts the exact released revision', async () => {
  const fetchImpl = async () => jsonResponse({
    ok: true,
    liveness: true,
    source_revision: 'f85857f'
  });

  const health = await verifyHealth('https://email.example', 'f85857f', fetchImpl);
  assert.equal(health.source_revision, 'f85857f');
});

test('DMARC release examples pin RFC whitespace, psd=u, and version case', async () => {
  const records = [];
  const fetchImpl = async (_url, init) => {
    const request = JSON.parse(init.body);
    records.push(request.record);
    if (request.record.startsWith('V = DMARC1')) {
      return jsonResponse({ valid: true, errors: [], warnings: [] });
    }
    return jsonResponse({
      valid: false,
      errors: ['DMARC record must begin with v=DMARC1.'],
      warnings: []
    });
  };

  await verifyDmarcExamples('https://email.example', fetchImpl);
  assert.deepEqual(records, [
    'V = DMARC1 ; p=reject; psd=u;',
    'v=dmarc1; p=reject;'
  ]);
});
