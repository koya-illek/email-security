const assert = require('node:assert/strict');
const { readFile } = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const {
  EXPIRED_REPORTS_DELETE_SQL,
  runScheduledCleanup
} = require('../retention');

test('scheduled cleanup deletes reports at or before the deterministic cutoff', async () => {
  const calls = [];
  const result = { success: true, meta: { changes: 2 } };
  const db = {
    prepare(sql) {
      calls.push({ type: 'prepare', sql });
      return {
        bind(value) {
          calls.push({ type: 'bind', value });
          return {
            run() {
              calls.push({ type: 'run' });
              return Promise.resolve(result);
            }
          };
        }
      };
    }
  };

  const cleanupResult = await runScheduledCleanup(
    { DB: db },
    '2026-08-12T12:00:00.000Z'
  );

  assert.deepEqual(cleanupResult, result);
  assert.deepEqual(calls, [
    { type: 'prepare', sql: EXPIRED_REPORTS_DELETE_SQL },
    { type: 'bind', value: '2026-08-12T12:00:00.000Z' },
    { type: 'run' }
  ]);
});

test('the Worker scheduled handler and Wrangler cron are wired to cleanup', async () => {
  const worker = await readFile(path.join(__dirname, '..', 'worker.js'), 'utf8');
  const wrangler = await readFile(path.join(__dirname, '..', 'wrangler.toml'), 'utf8');

  assert.match(worker, /async scheduled\(_controller, env\)/);
  assert.match(worker, /await runScheduledCleanup\(env\)/);
  assert.match(wrangler, /\[triggers\][\s\S]*crons\s*=\s*\["17 \* \* \* \*"\]/);
});
