// Shareable report storage: opaque bearer ids, 14-day retention, and a
// retrieval contract that keeps "absent" distinct from "storage failed".
const REPORT_RETENTION_DAYS = 14;
const REPORT_ID_RE = /^[A-Za-z0-9_-]{16}$/;

class ReportStorageError extends Error {
  constructor(message = 'The report could not be read from storage.') {
    super(message);
    this.name = 'ReportStorageError';
    this.status = 503;
  }
}

// Generate a 16-character unguessable report ID. These ids are bearer
// credentials, so the full 64 bits are uniformly random: a truncated
// UUIDv4 leaks its version/variant structure in access logs and dumps.
function generateReportId() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
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
  try {
    await env.DB.prepare(
      'INSERT INTO reports (id, type, domain, report_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(
      id,
      report._reportType || 'domain',
      report.domain || null,
      JSON.stringify(storedReport),
      now,
      expires
    ).run();
    return id;
  } catch {
    // Sharing degrades to unavailable; the analysis result itself is unaffected.
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

module.exports = {
  REPORT_ID_RE,
  REPORT_RETENTION_DAYS,
  ReportStorageError,
  generateReportId,
  loadReport,
  reportExpiry,
  reportShareMetadata,
  storeReport
};
