use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::request::AuthzRequest;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionEffect {
    Allow,
    Deny,
    Review,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchedPolicy {
    pub id: String,
    pub effect: DecisionEffect,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub decision_id: String,
    pub effect: DecisionEffect,
    pub request: AuthzRequest,
    pub matched_policies: Vec<MatchedPolicy>,
    pub determining_policy: Option<MatchedPolicy>,
    pub policy_revision: String,
    pub policy_signature: Option<String>,
    pub engine_version: String,
    pub timestamp: DateTime<Utc>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzDecision {
    pub effect: DecisionEffect,
    pub evidence: Evidence,
}

impl AuthzDecision {
    pub fn deny_default(request: AuthzRequest, policy_revision: &str, engine_version: &str) -> Self {
        let decision_id = Uuid::new_v4().to_string();
        Self {
            effect: DecisionEffect::Deny,
            evidence: Evidence {
                decision_id,
                effect: DecisionEffect::Deny,
                request,
                matched_policies: vec![],
                determining_policy: None,
                policy_revision: policy_revision.to_string(),
                policy_signature: None,
                engine_version: engine_version.to_string(),
                timestamp: Utc::now(),
                notes: vec![
                    "deny-by-default: no permitting policy matched".to_string(),
                ],
            },
        }
    }
}
