-- Email Security Analyzer — D1 schema for shareable reports

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL DEFAULT 'domain',      -- 'domain' | 'batch'
  domain TEXT,                               -- primary domain (nullable for batch)
  report_json TEXT NOT NULL,                 -- full JSON report
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_expires_at ON reports(expires_at);
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(type);
