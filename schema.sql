-- Email Security Analyzer — D1 schema for shareable reports

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL DEFAULT 'domain',      -- 'domain' | 'batch' | 'rate_limit'
  domain TEXT,                               -- primary domain (nullable for batch)
  report_json TEXT NOT NULL,                 -- full JSON report (rate-limit rows store a counter)
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

-- Every access is by primary key (report loads, rate-limit upsert) or by
-- expiry (the hourly cleanup DELETE); a type index taxed writes for nothing.
CREATE INDEX IF NOT EXISTS idx_reports_expires_at ON reports(expires_at);
