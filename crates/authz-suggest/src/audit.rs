use std::fs;
use std::io::Write;
use std::path::Path;

use authz_core::{AuthzDecision, DecisionEffect};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::SuggestError;

/// Append-only production audit record (JSONL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub decision_id: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub subject: Option<String>,
    pub decision: DecisionEffect,
    pub policy_revision: String,
    #[serde(default)]
    pub signature_key_id: Option<String>,
    pub latency_ms: u64,
    pub timestamp: DateTime<Utc>,
    /// Full decision evidence for `authz explain`.
    pub decision_full: AuthzDecision,
}

impl AuditRecord {
    pub fn from_decision(decision: &AuthzDecision, latency_ms: u64) -> Self {
        Self {
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
            decision: decision.effect,
            policy_revision: decision.evidence.policy_revision.clone(),
            signature_key_id: decision.evidence.policy_signature.clone(),
            latency_ms,
            timestamp: decision.evidence.timestamp,
            decision_full: decision.clone(),
        }
    }
}

pub fn append_audit_record(
    path: impl AsRef<Path>,
    record: &AuditRecord,
) -> Result<(), SuggestError> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{}", serde_json::to_string(record).unwrap())?;
    Ok(())
}

pub fn append_audit(path: impl AsRef<Path>, decision: &AuthzDecision) -> Result<(), SuggestError> {
    let record = AuditRecord::from_decision(decision, 0);
    append_audit_record(path, &record)
}

pub fn read_audit_records(path: impl AsRef<Path>) -> Result<Vec<AuditRecord>, SuggestError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Support both new AuditRecord and legacy AuthzDecision lines.
        if let Ok(r) = serde_json::from_str::<AuditRecord>(line) {
            out.push(r);
        } else if let Ok(d) = serde_json::from_str::<AuthzDecision>(line) {
            out.push(AuditRecord::from_decision(&d, 0));
        }
    }
    Ok(out)
}

pub fn find_decision(
    path: impl AsRef<Path>,
    decision_id: &str,
) -> Result<Option<AuthzDecision>, SuggestError> {
    for r in read_audit_records(path)? {
        if r.decision_id == decision_id {
            return Ok(Some(r.decision_full));
        }
    }
    Ok(None)
}

pub fn recent_decisions(
    path: impl AsRef<Path>,
    limit: usize,
) -> Result<Vec<AuditRecord>, SuggestError> {
    let mut all = read_audit_records(path)?;
    let skip = all.len().saturating_sub(limit);
    Ok(all.split_off(skip))
}
