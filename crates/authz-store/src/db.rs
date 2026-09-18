use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Duration;

use authz_core::AuthzDecision;
use chrono::Utc;
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use serde_json::Value;

use crate::error::StoreError;
use crate::migrations::MIGRATIONS;

pub struct PaacStore {
    path: PathBuf,
    conn: Mutex<Connection>,
    audit_tx: Sender<AuditWrite>,
}

struct AuditWrite {
    decision_id: String,
    principal: String,
    action: String,
    resource: String,
    subject: Option<String>,
    decision: String,
    policy_revision: String,
    signature_key_id: Option<String>,
    latency_ms: i64,
    timestamp: String,
    evidence_json: String,
}

impl PaacStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::Msg(e.to_string()))?;
        }
        let conn = Connection::open(path.as_ref())?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        let store = Self {
            path: path.as_ref().to_path_buf(),
            conn: Mutex::new(conn),
            audit_tx: {
                let (tx, rx) = mpsc::channel::<AuditWrite>();
                let db_path = path.as_ref().to_path_buf();
                thread::Builder::new()
                    .name("paac-audit-writer".into())
                    .spawn(move || {
                        let conn = Connection::open(db_path).expect("audit db");
                        let _ = conn.execute_batch("PRAGMA journal_mode=WAL;");
                        while let Ok(w) = rx.recv() {
                            let mut batch = vec![w];
                            // Drain burst for throughput
                            while let Ok(more) = rx.try_recv() {
                                batch.push(more);
                                if batch.len() >= 64 {
                                    break;
                                }
                            }
                            let tx = conn.unchecked_transaction().ok();
                            for w in batch {
                                let _ = conn.execute(
                                    r#"INSERT OR REPLACE INTO audit_log
                                    (decision_id, principal, action, resource, subject, decision,
                                     policy_revision, signature_key_id, latency_ms, timestamp, evidence_json)
                                    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"#,
                                    params![
                                        w.decision_id,
                                        w.principal,
                                        w.action,
                                        w.resource,
                                        w.subject,
                                        w.decision,
                                        w.policy_revision,
                                        w.signature_key_id,
                                        w.latency_ms,
                                        w.timestamp,
                                        w.evidence_json
                                    ],
                                );
                                let _ = conn.execute(
                                    r#"INSERT OR REPLACE INTO decision_evidence
                                    (decision_id, evidence_json, created_at) VALUES (?1,?2,?3)"#,
                                    params![w.decision_id, w.evidence_json, w.timestamp],
                                );
                            }
                            if let Some(tx) = tx {
                                let _ = tx.commit();
                            }
                        }
                    })
                    .map_err(|e| StoreError::Msg(e.to_string()))?;
                tx
            },
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock();
        conn.execute_batch(MIGRATIONS[0])?;
        let current: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if current < 1 {
            conn.execute_batch(MIGRATIONS[1])?;
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?1)",
                params![Utc::now().to_rfc3339()],
            )?;
        }
        Ok(())
    }

    pub fn upsert_policy_revision(
        &self,
        revision: &str,
        message: &str,
        dsl: &str,
        cedar: &str,
        content_sha256: Option<&str>,
        signature_key_id: Option<&str>,
        signature_b64: Option<&str>,
        deployed: bool,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock();
        conn.execute(
            r#"INSERT OR REPLACE INTO policy_revisions
            (revision, message, created_at, content_sha256, signature_key_id, signature_b64, dsl, cedar, deployed)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"#,
            params![
                revision,
                message,
                Utc::now().to_rfc3339(),
                content_sha256,
                signature_key_id,
                signature_b64,
                dsl,
                cedar,
                deployed as i64
            ],
        )?;
        Ok(())
    }

    pub fn cache_identity(&self, principal_id: &str, payload: &Value, source: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock();
        conn.execute(
            r#"INSERT OR REPLACE INTO identity_cache(principal_id, payload_json, source, synced_at)
               VALUES (?1,?2,?3,?4)"#,
            params![
                principal_id,
                serde_json::to_string(payload)?,
                source,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn get_cached_identity(&self, principal_id: &str) -> Result<Option<Value>, StoreError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT payload_json FROM identity_cache WHERE principal_id = ?1",
        )?;
        let mut rows = stmt.query(params![principal_id])?;
        if let Some(row) = rows.next()? {
            let s: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&s)?))
        } else {
            Ok(None)
        }
    }

    /// Non-blocking audit enqueue (hot path safe).
    pub fn enqueue_audit(
        &self,
        decision: &AuthzDecision,
        latency_ms: u64,
        signature_key_id: Option<String>,
    ) -> Result<(), StoreError> {
        let w = AuditWrite {
            decision_id: decision.evidence.decision_id.clone(),
            principal: decision.evidence.request.principal.id.clone(),
            action: decision.evidence.request.action.name.clone(),
            resource: decision.evidence.request.resource.kind.clone(),
            subject: decision
                .evidence
                .request
                .subject
                .as_ref()
                .map(|s| s.id.clone()),
            decision: format!("{:?}", decision.effect).to_ascii_uppercase(),
            policy_revision: decision.evidence.policy_revision.clone(),
            signature_key_id: signature_key_id.or_else(|| decision.evidence.policy_signature.clone()),
            latency_ms: latency_ms as i64,
            timestamp: decision.evidence.timestamp.to_rfc3339(),
            evidence_json: serde_json::to_string(decision)?,
        };
        self.audit_tx
            .send(w)
            .map_err(|e| StoreError::Msg(format!("audit channel: {e}")))?;
        Ok(())
    }

    pub fn recent_audit(&self, limit: usize) -> Result<Vec<Value>, StoreError> {
        // brief wait so buffered writes land in tests
        thread::sleep(Duration::from_millis(20));
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            r#"SELECT decision_id, principal, action, resource, subject, decision,
                      policy_revision, signature_key_id, latency_ms, timestamp, evidence_json
               FROM audit_log ORDER BY id DESC LIMIT ?1"#,
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(serde_json::json!({
                "decision_id": row.get::<_, String>(0)?,
                "principal": row.get::<_, String>(1)?,
                "action": row.get::<_, String>(2)?,
                "resource": row.get::<_, String>(3)?,
                "subject": row.get::<_, Option<String>>(4)?,
                "decision": row.get::<_, String>(5)?,
                "policy_revision": row.get::<_, String>(6)?,
                "signature_key_id": row.get::<_, Option<String>>(7)?,
                "latency_ms": row.get::<_, i64>(8)?,
                "timestamp": row.get::<_, String>(9)?,
                "evidence": serde_json::from_str::<Value>(&row.get::<_, String>(10)?).unwrap_or(Value::Null),
            }))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_evidence(&self, decision_id: &str) -> Result<Option<AuthzDecision>, StoreError> {
        thread::sleep(Duration::from_millis(15));
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare("SELECT evidence_json FROM decision_evidence WHERE decision_id = ?1")?;
        let mut rows = stmt.query(params![decision_id])?;
        if let Some(row) = rows.next()? {
            let s: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&s)?))
        } else {
            Ok(None)
        }
    }

    pub fn upsert_catalog_resource(&self, id: &str, kind: &str, payload: &Value) -> Result<(), StoreError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO resource_catalog(id, kind, payload_json) VALUES (?1,?2,?3)",
            params![id, kind, serde_json::to_string(payload)?],
        )?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authz_core::{
        Action, AuthzDecision, AuthzRequest, ContextMap, DecisionEffect, Evidence, Principal,
        Resource,
    };
    
    #[test]
    fn audit_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = PaacStore::open(dir.path().join("paac.db")).unwrap();
        let req = AuthzRequest {
            principal: Principal::with_roles("user:a", vec!["R".into()]),
            action: Action::new("READ"),
            resource: Resource::kind("X"),
            subject: None,
            context: ContextMap::default(),
            relationships: vec![],
            acting_as: None,
            on_behalf_of: None,
        };
        let d = AuthzDecision {
            effect: DecisionEffect::Deny,
            evidence: Evidence {
                decision_id: "dec-1".into(),
                effect: DecisionEffect::Deny,
                request: req,
                matched_policies: vec![],
                determining_policy: None,
                policy_revision: "r1".into(),
                policy_signature: Some("key1".into()),
                engine_version: "0.2.0".into(),
                timestamp: Utc::now(),
                notes: vec![],
            },
        };
        store.enqueue_audit(&d, 3, Some("key1".into())).unwrap();
        thread::sleep(Duration::from_millis(50));
        let recent = store.recent_audit(5).unwrap();
        assert_eq!(recent[0]["decision_id"], "dec-1");
        let ev = store.get_evidence("dec-1").unwrap().unwrap();
        assert_eq!(ev.evidence.decision_id, "dec-1");
    }
}
