//! Embeddable PAAC Engine SDK for direct in-process Rust application integration.

use std::sync::Arc;
use cedar_policy::PolicySet;
use crate::decision::AuthzDecision;
use crate::evaluate::{evaluate, EvaluatorConfig};
use crate::error::AuthzError;

/// High-level embeddable PAAC authorization engine for Rust applications.
#[derive(Clone)]
pub struct PaacEngine {
    config: EvaluatorConfig,
}

impl PaacEngine {
    /// Create an in-process embeddable engine from a Cedar PolicySet.
    pub fn new(policy_set: PolicySet, revision: impl Into<String>) -> Self {
        Self {
            config: EvaluatorConfig {
                policy_set: Arc::new(policy_set),
                policy_revision: revision.into(),
                policy_signature: None,
                group_members: Default::default(),
            },
        }
    }

    /// Evaluate an AuthzRequest directly in memory (sub-millisecond latency).
    pub fn evaluate(&self, req: &crate::request::AuthzRequest) -> Result<AuthzDecision, AuthzError> {
        evaluate(req, &self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::AuthzRequestBuilder;
    use std::str::FromStr;

    #[test]
    fn test_embeddable_sdk_evaluation() {
        let cedar = r#"
permit (
  principal,
  action == Action::"READ",
  resource
) when {
  context.resource_kind == "EMPLOYEE_PROFILE"
};
"#;
        let set = PolicySet::from_str(cedar).unwrap();
        let engine = PaacEngine::new(set, "v1");
        let req = AuthzRequestBuilder::new()
            .principal("user:alex", vec!["EMPLOYEE".into()])
            .unwrap()
            .action("READ")
            .unwrap()
            .resource_kind("EMPLOYEE_PROFILE")
            .unwrap()
            .build()
            .unwrap();

        let decision = engine.evaluate(&req).unwrap();
        assert_eq!(decision.effect, crate::decision::DecisionEffect::Allow);
    }
}
