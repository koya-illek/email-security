// Shareable report storage: opaque bearer ids, 14-day retention, and a
// retrieval contract that keeps "absent" distinct from "storage failed".
const REPORT_RETENTION_DAYS = 14;
// New ids are 128-bit (32 hex chars). Existing 16-character ids remain
// retrievable until they expire.
const REPORT_ID_RE = /^[A-Za-z0-9_-]{16}(?:[A-Za-z0-9_-]{16})?$/;
const REPORT_ID_BYTES = 16;

class ReportStorageError extends Error {
  constructor(message = 'The report could not be read from storage.') {
    super(message);
    this.name = 'ReportStorageError';
    this.status = 503;
  }
}

// Generate an unguessable report ID. These ids are bearer credentials, so
// the full 128 bits are uniformly random: a truncated UUIDv4 leaks its
// version/variant structure in access logs and dumps.
function generateReportId() {
  const bytes = crypto.getRandomValues(new Uint8Array(REPORT_ID_BYTES));
  return [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function reportExpiry() {
  const d = new Date();
  d.setDate(d.getDate() + REPORT_RETENTION_DAYS);
  return d.toISOString();
}

function reportShareMetadata(id, expiresAt = null, available = Boolean(id)) {
  return {
    available,
    id: id || null,
    retentionDays: REPORT_RETENTION_DAYS,
    expiresAt,
    bearer: true,
    cacheControl: 'private, no-store'
  };
}

// D1 rows are bounded by the platform (~2 MB); a payload past the guard is
// refused intentionally instead of surfacing as an incidental insert error
// that degrades sharing with no explanation in the logs.
const MAX_REPORT_JSON_CHARS = 1024 * 1024;

async function storeReport(env, report) {
  if (!env.DB) return null;
  const id = generateReportId();
  const now = new Date().toISOString();
  const expires = reportExpiry();
  const storedReport = {
    ...report,
    id,
    share: reportShareMetadata(id, expires, true)
  };
  const serialized = JSON.stringify(storedReport);
  if (serialized.length > MAX_REPORT_JSON_CHARS) {
    console.error(JSON.stringify({
      level: 'error',
      message: 'Report payload exceeds storage guard',
      type: report._reportType || 'domain',
      domain: report.domain || null,
      bytes: serialized.length
    }));
    return null;
  }
  try {
    await env.DB.prepare(
      'INSERT INTO reports (id, type, domain, report_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(
      id,
      report._reportType || 'domain',
      report.domain || null,
      serialized,
      now,
      expires
    ).run();
    return id;
  } catch (error) {
    // Sharing still degrades to unavailable for the user; the failure itself
    // must be visible to operators instead of collapsing into a silent null.
    console.error(JSON.stringify({
      level: 'error',
      message: 'Report storage insert failed',
      type: report._reportType || 'domain',
      domain: report.domain || null,
      errorName: error?.name || 'Unknown',
      detail: String(error?.message || error)
    }));
    return null;
  }
}

async function loadReport(env, id) {
  if (!REPORT_ID_RE.test(id)) return null;
  if (!env?.DB || typeof env.DB.prepare !== 'function') {
    // A missing or unusable binding is storage trouble. Answering "not found"
    // here would tell every share-link visitor their report is gone while the
    // row may be intact; only absence and expiry are allowed to say that.
    throw new ReportStorageError();
  }
  let row;
  try {
    row = await env.DB.prepare(
      'SELECT report_json FROM reports WHERE id = ? AND expires_at > ?'
    ).bind(id, new Date().toISOString()).first();
  } catch {
    throw new ReportStorageError();
  }
  if (!row) return null;
  try {
    const report = JSON.parse(row.report_json);
    if (!report.id) report.id = id;
    return report;
  } catch {
    throw new ReportStorageError('The stored report is unreadable.');
  }
}

async function deleteReport(env, id) {
  if (!REPORT_ID_RE.test(id)) return false;
  if (!env?.DB || typeof env.DB.prepare !== 'function') {
    throw new ReportStorageError('The report could not be removed from storage.');
  }
  let row;
  try {
    row = await env.DB.prepare(
      "DELETE FROM reports WHERE id = ? AND expires_at > ? AND type IN ('domain', 'batch') RETURNING id"
    ).bind(id, new Date().toISOString()).first();
  } catch {
    throw new ReportStorageError('The report could not be removed from storage.');
  }
  return Boolean(row?.id);
}

module.exports = {
  REPORT_ID_RE,
  REPORT_ID_BYTES,
  REPORT_RETENTION_DAYS,
  ReportStorageError,
  deleteReport,
  generateReportId,
  loadReport,
  reportExpiry,
  reportShareMetadata,
  storeReport
};
