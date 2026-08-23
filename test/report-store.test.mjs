import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';

const {
  REPORT_ID_RE,
  REPORT_RETENTION_DAYS,
  ReportStorageError,
  generateReportId,
  loadReport,
  reportExpiry,
  reportShareMetadata,
  storeReport
} = await import('../report-store.js');

const worker = await readFile(new URL('../worker.js', import.meta.url), 'utf8');

function stubDb({ selectRow = null, selectThrows = false, insertFails = false } = {}) {
  const statements = [];
  return {
    statements,
    prepare(sql) {
      const statement = {
        sql,
        bindArgs: null,
        bind(...args) {
          this.bindArgs = args;
          statements.push(this);
          return {
            first: async () => {
              if (selectThrows) throw new Error('D1_ERROR: storage unreachable');
              return typeof selectRow === 'function' ? selectRow() : selectRow;
            },
            run: async () => {
              if (insertFails) throw new Error('D1_ERROR: write failed');
              return { success: true };
            }
          };
        }
      };
      return statement;
    }
  };
}

test('loadReport treats a missing database binding as storage trouble, not absence', async () => {
  // A well-formed id promises a retrievable report; without usable storage
  // that is a failure (503), while only malformed ids may answer "absent".
  await assert.rejects(() => loadReport({}, '1234567890abcdef'), ReportStorageError);
  assert.equal(await loadReport({ DB: stubDb() }, 'short'), null);
  assert.equal(await loadReport({ DB: stubDb() }, 'not-a-report-id!!'), null);
});

test('loadReport returns null only for absent or expired rows', async () => {
  const env = { DB: stubDb({ selectRow: null }) };
  assert.equal(await loadReport(env, '1234567890abcdef'), null);
});

test('loadReport returns the parsed report and backfills its id', async () => {
  const stored = { _reportType: 'domain', domain: 'example.com', overall_score: 80 };
  const env = { DB: stubDb({ selectRow: { report_json: JSON.stringify(stored) } }) };
  const report = await loadReport(env, '1234567890abcdef');
  assert.equal(report.domain, 'example.com');
  assert.equal(report.id, '1234567890abcdef');
});

test('loadReport throws ReportStorageError instead of faking absence on DB failure', async () => {
  const env = { DB: stubDb({ selectThrows: true }) };
  await assert.rejects(
    () => loadReport(env, '1234567890abcdef'),
    (error) => {
      assert.ok(error instanceof ReportStorageError);
      assert.equal(error.status, 503);
      assert.match(error.message, /could not be read/);
      return true;
    }
  );
});

test('loadReport treats unreadable stored bytes as a storage failure, not a missing report', async () => {
  const env = { DB: stubDb({ selectRow: { report_json: '{not json' } }) };
  await assert.rejects(() => loadReport(env, '1234567890abcdef'), ReportStorageError);
});

test('storeReport returns null without a database or on write failure, ids otherwise', async () => {
  assert.equal(await storeReport({}, { _reportType: 'domain' }), null);
  const failing = { DB: stubDb({ insertFails: true }) };
  assert.equal(await storeReport(failing, { _reportType: 'domain' }), null);

  const working = { DB: stubDb() };
  const id = await storeReport(working, { _reportType: 'domain', domain: 'example.com' });
  assert.match(id, REPORT_ID_RE);
  const [statement] = working.DB.statements;
  assert.match(statement.sql, /INSERT INTO reports/);
  assert.equal(statement.bindArgs[0], id);
  assert.equal(statement.bindArgs[1], 'domain');
  const payload = JSON.parse(statement.bindArgs[3]);
  assert.equal(payload.id, id);
  assert.equal(payload.share.available, true);
});

test('share metadata and expiry describe an honest bearer link', () => {
  const expires = reportExpiry();
  const share = reportShareMetadata('1234567890abcdef', expires, true);
  assert.equal(share.retentionDays, REPORT_RETENTION_DAYS);
  assert.equal(share.bearer, true);
  assert.equal(share.cacheControl, 'private, no-store');
  assert.ok(new Date(expires) > new Date(), 'expiry must sit in the future');
  const unavailable = reportShareMetadata(null);
  assert.equal(unavailable.available, false);
});

test('generated report ids always satisfy the retrieval pattern', () => {
  const ids = new Set();
  for (let i = 0; i < 20; i++) {
    const id = generateReportId();
    assert.match(id, REPORT_ID_RE);
    ids.add(id);
  }
  assert.equal(ids.size, 20);
});

test('report ids carry no UUID structure so they cannot be fingerprinted as truncated UUIDs', () => {
  // Truncated UUIDv4s always show version nibble '4' at index 8 and a
  // constrained variant nibble at index 12; bearer credentials should be
  // indistinguishable from uniform randomness.
  for (let i = 0; i < 50; i++) {
    const id = generateReportId();
    assert.notEqual(id[8], '4', 'version nibble must not be pinned');
    assert.match(id, /^[0-9a-f]{16}$/);
  }
});

test('report routes keep absence and storage failure distinct end to end', () => {
  // The route must map the controlled storage error to 503 while reserving
  // 404 for genuine absence, and must not blame rate limiting for read outages.
  assert.match(worker, /stored = await loadReport\(env, reportId\)/);
  assert.match(worker, /return requestErrorResponse\(err, corsHeaders, 503\)/);
  assert.match(worker, /error: 'Report not found or expired'/);
  assert.match(worker, /error: 'Report retrieval is temporarily unavailable\. Try again shortly\.'/);
});
