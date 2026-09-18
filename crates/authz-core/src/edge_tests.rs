#![cfg(test)]

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::PolicySet;
use crate::*;

fn cfg_from(cedar: &str) -> EvaluatorConfig {
    EvaluatorConfig {
        policy_set: Arc::new(PolicySet::from_str(cedar).unwrap()),
        policy_revision: "edge".into(),
        policy_signature: Some("k1".into()),
        group_members: HashMap::new(),
    }
}

#[test]
fn deny_by_default_no_policies() {
    let req = AuthzRequestBuilder::new()
        .principal("user:x", vec!["R".into()])
        .unwrap()
        .action("READ")
        .unwrap()
        .resource_kind("ANYTHING")
        .unwrap()
        .build()
        .unwrap();
    let cfg = cfg_from(
        r#"
@id("never")
permit(principal, action, resource) when { false };
"#,
    );
    let d = evaluate(&req, &cfg).unwrap();
    assert_eq!(d.effect, DecisionEffect::Deny);
}

#[test]
fn delegation_depth_in_context() {
    let req = AuthzRequestBuilder::new()
        .agent_principal("agent:bot", vec!["EMPLOYEE".into()], "user:hr-head")
        .unwrap()
        .action("READ")
        .unwrap()
        .resource_kind("EMPLOYEE_PROFILE")
        .unwrap()
        .delegation_hop("user:hr-head")
        .unwrap()
        .delegation_hop("agent:bot")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.context.values.get("delegation_depth").unwrap(), "2");
}

#[test]
fn builder_rejects_empty_principal() {
    assert!(AuthzRequestBuilder::new()
        .principal("  ", vec![])
        .is_err());
}
