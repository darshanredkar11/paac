pub const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);
"#,
    r#"
CREATE TABLE IF NOT EXISTS policy_revisions (
  revision TEXT PRIMARY KEY,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL,
  content_sha256 TEXT,
  signature_key_id TEXT,
  signature_b64 TEXT,
  dsl TEXT NOT NULL,
  cedar TEXT NOT NULL,
  deployed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS identity_cache (
  principal_id TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  source TEXT NOT NULL,
  synced_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  decision_id TEXT NOT NULL UNIQUE,
  principal TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  subject TEXT,
  decision TEXT NOT NULL,
  policy_revision TEXT NOT NULL,
  signature_key_id TEXT,
  latency_ms INTEGER NOT NULL,
  timestamp TEXT NOT NULL,
  evidence_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_log(principal);
CREATE TABLE IF NOT EXISTS resource_catalog (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_mappings (
  tool_name TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decision_evidence (
  decision_id TEXT PRIMARY KEY,
  evidence_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"#,
];
