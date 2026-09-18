//! MCP tool-call authorization hooks.
//! Every tools/call must be converted to AuthzRequest and evaluated before execution.

use authz_catalog::ResourceCatalog;
use authz_core::{evaluate, AuthzDecision, DecisionEffect, EvaluatorConfig, Principal};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolsCallRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: McpCallParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAuthzResult {
    pub allowed: bool,
    pub decision: AuthzDecision,
}

pub fn authorize_mcp_tool_call(
    principal: Principal,
    params: &McpCallParams,
    catalog: &ResourceCatalog,
    cfg: &EvaluatorConfig,
) -> Result<McpAuthzResult, authz_core::AuthzError> {
    let req = catalog.authz_for_tool(principal, &params.name, &params.arguments);
    let decision = evaluate(&req, cfg)?;
    Ok(McpAuthzResult {
        allowed: decision.effect == DecisionEffect::Allow,
        decision,
    })
}
