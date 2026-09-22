use std::sync::Arc;

use authz_board::{build_matrix, BOARD_HTML};
use authz_core::{DecisionEffect, Principal};
use authz_llm_bridge::{bind_extraction, extract_structured};
use authz_policy::parse_dsl;
use authz_suggest::recent_decisions;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::auth::resolve_principal;
use crate::connectors::ToolCall;
use crate::error::ProxyError;
use crate::openai::{last_user_text, ChatCompletionRequest, RetrieveRequest};
use crate::state::AppState;
use crate::a2a::{authorize_a2a_message, A2aMessage};
use crate::mcp::{authorize_mcp_tool_call, McpCallParams};

pub async fn health(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "paac-proxy",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": format!("{:?}", st.cfg.mode).to_ascii_lowercase(),
    }))
}

pub async fn ready(State(st): State<Arc<AppState>>) -> Result<Json<Value>, ProxyError> {
    st.engine.is_ready()?;
    let hot = st.engine.bundle.load();
    Ok(Json(json!({
        "ready": true,
        "policy_revision": hot.policy_revision,
        "signed": hot.policy_signature.is_some(),
        "signature_key_id": hot.signature_key_id,
    })))
}

pub async fn metrics(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let m = st.metrics.read().clone();
    format!(
        "# TYPE paac_checks_total counter\npaac_checks_total {}\n\
         # TYPE paac_denies_total counter\npaac_denies_total {}\n\
         # TYPE paac_allows_total counter\npaac_allows_total {}\n\
         # TYPE paac_upstream_calls counter\npaac_upstream_calls {}\n",
        m.checks_total, m.denies_total, m.allows_total, m.upstream_calls
    )
}

pub async fn chat_completions(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ChatCompletionRequest>,
) -> Result<Response, ProxyError> {
    let principal = resolve_principal(&headers, &st.cfg, &st.jwt, &st.identity_cache).await?;
    let utterance = last_user_text(&body.messages).unwrap_or_default();

    // NL → proposal → Cedar revalidation (LLM never decides; fail-closed)
    if !utterance.is_empty() {
        let extraction = extract_structured(&utterance).unwrap_or_else(|_| authz_llm_bridge::NlExtraction {
            action: "READ".into(),
            resource_kind: "GENERAL_CHAT".into(),
            resource_id: None,
            subject_id: None,
            subject_groups: vec![],
            direct_reports: vec![],
            confidence: 0.0,
            utterance: utterance.clone(),
        });
        let req = bind_extraction(principal.clone(), &extraction, Some(&st.engine.catalog))
            .map_err(|e| ProxyError::BadRequest(e.to_string()))?;
        {
            let mut m = st.metrics.write();
            m.checks_total += 1;
        }
        let decision = st.engine.check(&req)?;
        if decision.effect != DecisionEffect::Allow {
            st.metrics.write().denies_total += 1;
            return Err(ProxyError::Forbidden {
                message: format!(
                    "PAAC denied access: {} on {} (decision {})",
                    req.action.name, req.resource.kind, decision.evidence.decision_id
                ),
                decision_id: decision.evidence.decision_id.clone(),
                body: serde_json::to_value(&decision).unwrap_or_default(),
            });
        }
        st.metrics.write().allows_total += 1;
    }

    // Forward to upstream LLM
    st.metrics.write().upstream_calls += 1;
    let client = reqwest::Client::new();
    let url = format!(
        "{}/v1/chat/completions",
        st.cfg.upstream.base_url.trim_end_matches('/')
    );
    let mut rb = client.post(&url).json(&body);
    if let Some(key) = &st.cfg.upstream.api_key {
        rb = rb.bearer_auth(key);
    }
    if body.stream == Some(true) {
        let resp = rb
            .send()
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?;
        let status = resp.status();
        let response = Response::builder()
            .status(status.as_u16())
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .header("connection", "keep-alive")
            .body(axum::body::Body::from_stream(resp.bytes_stream()))
            .map_err(|e| ProxyError::Internal(e.to_string()))?;
        return Ok(response);
    }

    let resp = rb
        .send()
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
    let status = resp.status();
    let mut upstream_json: Value = resp
        .json()
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;

    // Intercept tool_calls before any connector runs
    if let Some(choices) = upstream_json.get_mut("choices").and_then(|c| c.as_array_mut()) {
        for choice in choices {
            if let Some(msg) = choice.get_mut("message") {
                if let Some(tcs) = msg.get("tool_calls").cloned() {
                    let filtered = filter_tool_calls(&st, &principal, tcs).await?;
                    if let Some(obj) = msg.as_object_mut() {
                        if filtered.is_empty() {
                            obj.remove("tool_calls");
                            obj.insert(
                                "content".into(),
                                json!("PAAC blocked all tool calls for this turn."),
                            );
                        } else {
                            obj.insert("tool_calls".into(), Value::Array(filtered));
                        }
                    }
                }
            }
        }
    }

    let mut res = Json(upstream_json).into_response();
    *res.status_mut() =
        axum::http::StatusCode::from_u16(status.as_u16()).unwrap_or(axum::http::StatusCode::OK);
    Ok(res)
}

async fn filter_tool_calls(
    st: &AppState,
    principal: &Principal,
    tcs: Value,
) -> Result<Vec<Value>, ProxyError> {
    let arr = match tcs.as_array() {
        Some(a) => a,
        None => return Ok(vec![]),
    };
    let mut out = Vec::new();
    for tc in arr {
        let name = tc
            .pointer("/function/name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let args_str = tc
            .pointer("/function/arguments")
            .and_then(|v| v.as_str())
            .unwrap_or("{}");
        let args: Value = serde_json::from_str(args_str).unwrap_or(json!({}));
        let req = st
            .engine
            .catalog
            .authz_for_tool(principal.clone(), name, &args);
        st.metrics.write().checks_total += 1;
        let decision = st.engine.check(&req)?;
        if decision.effect == DecisionEffect::Allow {
            st.metrics.write().allows_total += 1;
            if st.cfg.connectors.execute_tools {
                let call = ToolCall {
                    id: tc.get("id").and_then(|v| v.as_str()).unwrap_or("").into(),
                    name: name.into(),
                    arguments: args,
                };
                let _ = st.connector.execute(&call).await;
            }
            out.push(tc.clone());
        } else {
            st.metrics.write().denies_total += 1;
            // omit forbidden tool call
        }
    }
    Ok(out)
}

pub async fn retrieve(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RetrieveRequest>,
) -> Result<Json<Value>, ProxyError> {
    let principal = resolve_principal(&headers, &st.cfg, &st.jwt, &st.identity_cache).await?;
    let req = st.engine.catalog.authz_for_retrieve(
        principal,
        &body.collection,
        body.document_id.as_deref(),
    );
    st.engine.allow_or_forbid(&req)?;
    Ok(Json(json!({
        "collection": body.collection,
        "chunks": [],
        "note": "authz ALLOW — connector would return chunks here"
    })))
}

pub async fn check(
    State(st): State<Arc<AppState>>,
    Json(req): Json<authz_core::AuthzRequest>,
) -> Result<Json<authz_core::AuthzDecision>, ProxyError> {
    st.metrics.write().checks_total += 1;
    let d = st.engine.check(&req)?;
    match d.effect {
        DecisionEffect::Allow => st.metrics.write().allows_total += 1,
        _ => st.metrics.write().denies_total += 1,
    }
    Ok(Json(d))
}

pub async fn explain(
    State(st): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<Value>, ProxyError> {
    if let Some(store) = &st.engine.store {
        if let Ok(Some(d)) = store.get_evidence(&id) {
            return Ok(Json(serde_json::to_value(d).unwrap_or_default()));
        }
    }
    // fallback JSONL
    if let Ok(Some(d)) = authz_suggest::find_decision(&st.cfg.audit_path, &id) {
        return Ok(Json(serde_json::to_value(d).unwrap_or_default()));
    }
    Err(ProxyError::BadRequest(format!("decision {id} not found")))
}

pub async fn board_page() -> Html<&'static str> {
    Html(BOARD_HTML)
}

pub async fn board_matrix(State(st): State<Arc<AppState>>) -> Result<Json<Value>, ProxyError> {
    let dsl = authz_policy::PolicyStore::open(&st.cfg.policy_dir)
        .and_then(|s| s.read_active_dsl())
        .unwrap_or_default();
    let policies = parse_dsl(&dsl).unwrap_or_default();
    Ok(Json(serde_json::to_value(build_matrix(&policies)).unwrap()))
}

pub async fn board_decisions(
    State(st): State<Arc<AppState>>,
) -> Result<Json<Value>, ProxyError> {
    if let Some(store) = &st.engine.store {
        let rows = store
            .recent_audit(50)
            .map_err(|e| ProxyError::Internal(e.to_string()))?;
        return Ok(Json(json!({ "decisions": rows })));
    }
    let rows = recent_decisions(&st.cfg.audit_path, 50)
        .map_err(|e| ProxyError::Internal(e.to_string()))?;
    Ok(Json(json!({ "decisions": rows })))
}

pub async fn mcp_tools_call(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(params): Json<McpCallParams>,
) -> Result<Json<Value>, ProxyError> {
    let principal = resolve_principal(&headers, &st.cfg, &st.jwt, &st.identity_cache).await?;
    let cfg = st.engine.bundle.evaluator_config();
    let result = authorize_mcp_tool_call(principal, &params, &st.engine.catalog, &cfg)
        .map_err(|e| ProxyError::BadRequest(e.to_string()))?;
    if !result.allowed {
        return Err(ProxyError::Forbidden {
            message: "MCP tools/call denied".into(),
            decision_id: result.decision.evidence.decision_id.clone(),
            body: serde_json::to_value(&result.decision).unwrap_or_default(),
        });
    }
    let call = ToolCall {
        id: uuid::Uuid::new_v4().to_string(),
        name: params.name,
        arguments: params.arguments,
    };
    let data = st
        .connector
        .execute(&call)
        .await
        .map_err(ProxyError::Internal)?;
    Ok(Json(json!({ "content": data, "decision_id": result.decision.evidence.decision_id })))
}

pub async fn a2a_authorize(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(msg): Json<A2aMessage>,
) -> Result<Json<Value>, ProxyError> {
    let principal = resolve_principal(&headers, &st.cfg, &st.jwt, &st.identity_cache).await?;
    let cfg = st.engine.bundle.evaluator_config();
    let result = authorize_a2a_message(principal, &msg, &cfg)
        .map_err(|e| ProxyError::BadRequest(e.to_string()))?;
    Ok(Json(serde_json::to_value(result).unwrap_or_default()))
}
