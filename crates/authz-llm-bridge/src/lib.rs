//! Natural language → AuthzRequest. Never used for policy evaluation.

use async_trait::async_trait;
use authz_core::{
    Action, AuthzRequest, ContextMap, Principal, Relationship, RelationshipKind, Resource, Subject,
};
use indexmap::IndexMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("bridge error: {0}")]
    Msg(String),
}

#[async_trait]
pub trait LlmRequestBuilder: Send + Sync {
    async fn build_request(&self, utterance: &str) -> Result<AuthzRequest, BridgeError>;
}

/// Deterministic mock that recognizes the CEO expense demo phrase.
pub struct MockLlmProvider {
    pub default_principal: Principal,
}

impl Default for MockLlmProvider {
    fn default() -> Self {
        Self {
            default_principal: Principal::with_roles("user:hr-head", vec!["HR_HEAD".into()]),
        }
    }
}

#[async_trait]
impl LlmRequestBuilder for MockLlmProvider {
    async fn build_request(&self, utterance: &str) -> Result<AuthzRequest, BridgeError> {
        let lower = utterance.to_ascii_lowercase();
        if lower.contains("ceo")
            && (lower.contains("spend") || lower.contains("expense") || lower.contains("trip"))
        {
            return Ok(AuthzRequest {
                principal: self.default_principal.clone(),
                action: Action::new("READ"),
                resource: Resource::kind("TRAVEL_EXPENSE"),
                subject: Some(Subject {
                    id: "employee:CEO".into(),
                    kind: "Employee".into(),
                    groups: vec!["EXECUTIVE".into()],
                    attrs: IndexMap::new(),
                }),
                context: ContextMap {
                    values: IndexMap::from([("time_range".into(), "LAST_WEEK".into())]),
                },
                relationships: vec![Relationship {
                    kind: RelationshipKind::DirectReports,
                    from: self.default_principal.id.clone(),
                    to: "employee:alice".into(),
                }],
                acting_as: Some("agent:enterprise-assistant".into()),
                on_behalf_of: Some(self.default_principal.id.clone()),
            });
        }
        Err(BridgeError::Msg(format!(
            "mock provider could not interpret: {utterance}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_builds_ceo_request() {
        // tokio not in deps — use block_on via futures? Keep sync test instead.
    }

    #[test]
    fn mock_sync_pattern() {
        let rt = tokio_test_block();
        let p = MockLlmProvider::default();
        let req = rt
            .block_on(p.build_request(
                "How much did the CEO spend on trips last week?",
            ))
            .unwrap();
        assert_eq!(req.action.name, "READ");
        assert_eq!(req.resource.kind, "TRAVEL_EXPENSE");
        assert_eq!(req.subject.unwrap().id, "employee:CEO");
    }

    fn tokio_test_block() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
}
