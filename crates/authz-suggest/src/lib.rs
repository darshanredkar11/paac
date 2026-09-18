//! Propose draft policies from identity sync + audit history. Humans commit.

use std::fs;
use std::path::Path;

use authz_core::{AuthzDecision, DecisionEffect};
use authz_identity::{IdentitySnapshot, LdapAdapter};
use authz_policy::PolicyStore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    let path = audit_path.as_ref();
    if !path.exists() {
        return Ok(vec![]);
    }
    let data = fs::read_to_string(path)?;
    let mut denies: Vec<AuthzDecision> = Vec::new();
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(d) = serde_json::from_str::<AuthzDecision>(line) {
            if d.effect == DecisionEffect::Deny {
                denies.push(d);
            }
        }
    }

    // Heuristic: repeated DENY on same action/resource → suggest explicit deny policy
    use std::collections::HashMap;
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for d in &denies {
        let key = (
            d.evidence.request.action.name.to_ascii_uppercase(),
            d.evidence.request.resource.kind.to_ascii_uppercase(),
        );
        *counts.entry(key).or_default() += 1;
    }

    let mut out = Vec::new();
    for ((action, resource), n) in counts {
        if n >= 2 {
            let name = format!("audit_deny_{}_{}", action.to_ascii_lowercase(), resource.to_ascii_lowercase());
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

pub fn append_audit(path: impl AsRef<Path>, decision: &AuthzDecision) -> Result<(), SuggestError> {
    use std::io::Write;
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{}", serde_json::to_string(decision).unwrap())?;
    Ok(())
}
