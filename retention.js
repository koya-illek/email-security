const EXPIRED_REPORTS_DELETE_SQL = 'DELETE FROM reports WHERE expires_at <= ?';

async function cleanupExpiredReports(db, now = new Date().toISOString()) {
  if (!db || typeof db.prepare !== 'function') {
    throw new Error('D1 database binding is required for report cleanup');
  }

  return db.prepare(EXPIRED_REPORTS_DELETE_SQL).bind(now).run();
}

async function runScheduledCleanup(env, now) {
  return cleanupExpiredReports(env?.DB, now);
}

module.exports = {
  EXPIRED_REPORTS_DELETE_SQL,
  cleanupExpiredReports,
  runScheduledCleanup
};
