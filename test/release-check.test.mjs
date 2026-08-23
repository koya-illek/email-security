import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

test('the deploy command refuses source bytes that no commit identifies', (context) => {
  const repository = mkdtempSync(join(tmpdir(), 'email-release-check-'));
  context.after(() => rmSync(repository, { recursive: true, force: true }));
  execFileSync('git', ['init', '--quiet'], { cwd: repository });
  writeFileSync(join(repository, 'tracked.txt'), 'committed\n');
  execFileSync('git', ['add', 'tracked.txt'], { cwd: repository });
  execFileSync('git', [
    '-c', 'user.name=Release Check',
    '-c', 'user.email=release-check@example.invalid',
    'commit', '--quiet', '-m', 'fixture'
  ], { cwd: repository });
  writeFileSync(join(repository, 'tracked.txt'), 'dirty\n');

  const deployScript = new URL('../scripts/deploy.mjs', import.meta.url);
  const result = spawnSync(process.execPath, [deployScript.pathname, '--dry-run'], {
    cwd: repository,
    encoding: 'utf8'
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Refusing to deploy a dirty worktree/);
  assert.doesNotMatch(result.stdout, /wrangler/i, 'the release must stop before Wrangler starts');
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
