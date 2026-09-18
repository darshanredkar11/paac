//! Agent-to-Agent (A2A) message authorization stubs with real request shapes.

use authz_core::{
    evaluate, Action, AuthzDecision, AuthzRequest, ContextMap, DecisionEffect, EvaluatorConfig,
    Principal, Resource,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aMessage {
    pub message_id: String,
    pub from_agent: String,
    pub to_agent: String,
    pub skill: String,
    #[serde(default)]
    pub payload: serde_json::Value,
    /// Delegation chain: human → agent1 → agent2 …
    #[serde(default)]
    pub delegation_chain: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aAuthzResult {
    pub allowed: bool,
    pub decision: AuthzDecision,
}

pub fn authorize_a2a_message(
    principal: Principal,
    msg: &A2aMessage,
    cfg: &EvaluatorConfig,
) -> Result<A2aAuthzResult, authz_core::AuthzError> {
    let mut ctx = IndexMap::new();
    ctx.insert("from_agent".into(), msg.from_agent.clone());
    ctx.insert("to_agent".into(), msg.to_agent.clone());
    ctx.insert("skill".into(), msg.skill.clone());
    ctx.insert("delegation_chain".into(), msg.delegation_chain.join(">"));
    ctx.insert(
        "delegation_depth".into(),
        msg.delegation_chain.len().to_string(),
    );
    // Abuse guard: deep delegation without on_behalf_of → still evaluated; policies may forbid.
    let req = AuthzRequest {
        principal,
        action: Action::new("A2A_SEND"),
        resource: Resource {
            kind: "AGENT_MESSAGE".into(),
            id: Some(msg.to_agent.clone()),
            attrs: IndexMap::from([("skill".into(), msg.skill.clone())]),
        },
        subject: None,
        context: ContextMap { values: ctx },
        relationships: vec![],
        acting_as: Some(msg.from_agent.clone()),
        on_behalf_of: msg.delegation_chain.first().cloned(),
    };
    let decision = evaluate(&req, cfg)?;
    Ok(A2aAuthzResult {
        allowed: decision.effect == DecisionEffect::Allow,
        decision,
    })
}
