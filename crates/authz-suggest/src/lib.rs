//! Propose draft policies from identity sync + audit history. Humans commit.

mod audit;

use std::path::Path;

use authz_core::{AuthzDecision, DecisionEffect};
use authz_identity::{IdentitySnapshot, LdapAdapter};
use authz_policy::PolicyStore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use audit::{
    append_audit, append_audit_record, find_decision, read_audit_records, recent_decisions,
    AuditRecord,
};

#[derive(Debug, Error)]
pub enum SuggestError {
    #[error("{0}")]
    Msg(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suggestion {
    pub name: String,
    pub rationale: String,
    pub dsl: String,
}

pub fn suggest_from_snapshot(snapshot: &IdentitySnapshot) -> Vec<Suggestion> {
    let dsl = LdapAdapter::draft_policies_from_groups(snapshot);
    vec![Suggestion {
        name: "ldap-group-drafts".into(),
        rationale: "Generated from LDAP/group sync; review before commit.".into(),
        dsl,
    }]
}

pub fn suggest_from_audit(audit_path: impl AsRef<Path>) -> Result<Vec<Suggestion>, SuggestError> {
    let records = read_audit_records(audit_path)?;
    use std::collections::HashMap;
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for r in &records {
        if r.decision == DecisionEffect::Deny {
            let key = (
                r.action.to_ascii_uppercase(),
                r.resource.to_ascii_uppercase(),
            );
            *counts.entry(key).or_default() += 1;
        }
    }

    let mut out = Vec::new();
    for ((action, resource), n) in counts {
        if n >= 2 {
            let name = format!(
                "audit_deny_{}_{}",
                action.to_ascii_lowercase(),
                resource.to_ascii_lowercase()
            );
            let dsl = format!(
                "policy \"{name}\"\ndeny {action} {resource}\n# suggested from {n} audit DENY events\n"
            );
            out.push(Suggestion {
                name,
                rationale: format!("{n} DENY decisions observed for {action} {resource}"),
                dsl,
            });
        }
    }
    Ok(out)
}

pub fn write_suggestions(
    store: &PolicyStore,
    suggestions: &[Suggestion],
) -> Result<Vec<String>, SuggestError> {
    let mut written = Vec::new();
    for s in suggestions {
        store
            .write_draft(&s.name, &s.dsl)
            .map_err(|e| SuggestError::Msg(e.to_string()))?;
        written.push(s.name.clone());
    }
    Ok(written)
}

/// Legacy helper kept for callers that still pass AuthzDecision lines.
pub fn load_legacy_decisions(path: impl AsRef<Path>) -> Result<Vec<AuthzDecision>, SuggestError> {
    Ok(read_audit_records(path)?
        .into_iter()
        .map(|r| r.decision_full)
        .collect())
}
