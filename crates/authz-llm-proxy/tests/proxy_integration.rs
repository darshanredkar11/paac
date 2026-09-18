use std::net::SocketAddr;
use std::sync::Arc;

use authz_core::{Action, AuthzRequest, ContextMap, DecisionEffect, Principal, Resource};
use authz_llm_proxy::config::{
    ConnectorsConfig, IdentityConfig, ProxyConfig, RunMode, UpstreamConfig,
};
use authz_llm_proxy::engine::AuthzEngine;
use authz_llm_proxy::routes;
use authz_llm_proxy::state::AppState;
use authz_policy::{LocalEd25519Signer, PolicyStore};
use axum::routing::{get, post};
use axum::Router;
use indexmap::IndexMap;
use serde_json::json;
use tower::ServiceExt;

async fn spawn_mock_llm() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|body: axum::Json<serde_json::Value>| async move {
            let has_tools = body.get("tools").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false);
            let msg = if has_tools || body["messages"].to_string().contains("sql_query") {
                json!({
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "sql_query",
                            "arguments": "{\"table\":\"db.finance.ledger\",\"sql\":\"select 1\"}"
                        }
                    }]
                })
            } else {
                json!({"role":"assistant","content":"ok from upstream"})
            };
            axum::Json(json!({
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "choices": [{"index":0,"message": msg, "finish_reason":"stop"}]
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, handle)
}

fn prepare_policies(dir: &std::path::Path) {
    let store = PolicyStore::open(dir).unwrap();
    let dsl = include_str!("../../../examples/policies/llm_data_rbac.dsl");
    store.write_active_dsl(dsl).unwrap();
    store.commit("test policies").unwrap();
    let (signer, pair) = LocalEd25519Signer::generate("test-key");
    let _ = pair;
    store.sign_head(&signer).unwrap();
    store.deploy_head().unwrap();
}

async fn build_app(mode: RunMode, upstream: String, allow_headers: bool) -> Arc<AppState> {
    let tmp = tempfile::tempdir().unwrap();
    let policy_dir = tmp.path().join("policies");
    prepare_policies(&policy_dir);
    // keep tmp alive by leaking for test process
    let catalog = std::path::PathBuf::from("examples/catalog/company_resources.yaml");
    let cfg = ProxyConfig {
        listen: "127.0.0.1:0".into(),
        mode: mode.clone(),
        require_signed_bundle: mode == RunMode::Production,
        policy_dir,
        catalog_path: catalog,
        audit_path: tmp.path().join("audit.jsonl"),
        identity_dir: tmp.path().join("identity"),
        upstream: UpstreamConfig {
            base_url: upstream,
            api_key: None,
            timeout_secs: 5,
        },
        identity: IdentityConfig {
            jwt_hmac_secret: Some("test-secret".into()),
            jwks_url: None,
            prefer_jwt_roles: true,
            allow_header_identity: allow_headers,
            ldap: None,
            cache_ttl_secs: 60,
        },
        connectors: ConnectorsConfig::default(),
    };
    // leak tempdir
    std::mem::forget(tmp);
    let engine = AuthzEngine::from_config(&cfg, None).expect("engine");
    Arc::new(AppState::new(cfg, engine))
}

fn router(st: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/ready", get(routes::ready))
        .route("/v1/chat/completions", post(routes::chat_completions))
        .route("/v1/check", post(routes::check))
        .route("/v1/mcp/tools/call", post(routes::mcp_tools_call))
        .with_state(st)
}

#[tokio::test]
async fn unauthorized_nl_query_denied_without_upstream_data() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_app(
        RunMode::Development,
        format!("http://{addr}"),
        true,
    )
    .await;
    let app = router(st);
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-paac-user", "user:hr-head")
                .header("x-paac-roles", "HR_HEAD")
                .body(axum::body::Body::from(
                    json!({
                        "model": "test",
                        "messages": [{"role":"user","content":"How much did the CEO spend on trips last week?"}]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"]["code"], "paac_deny");
}

#[tokio::test]
async fn authorized_query_calls_upstream() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_app(RunMode::Development, format!("http://{addr}"), true).await;
    let app = router(st);
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-paac-user", "user:hr-head")
                .header("x-paac-roles", "HR_HEAD")
                .body(axum::body::Body::from(
                    json!({
                        "model": "test",
                        "messages": [{"role":"user","content":"show alice travel expenses"}]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .contains("upstream"));
}

#[tokio::test]
async fn tool_call_forbidden_resource_blocked() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_app(RunMode::Development, format!("http://{addr}"), true).await;
    // Engineer may chat but tool sql on finance must be stripped
    let app = router(st);
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-paac-user", "employee:alice")
                .header("x-paac-roles", "ENGINEER")
                .body(axum::body::Body::from(
                    // utterance that does NOT extract to a denied NL request,
                    // so upstream is called and returns tool_calls which must be filtered
                    json!({
                        "model": "test",
                        "messages": [{"role":"user","content":"hello"}],
                        "tools": [{"type":"function","function":{"name":"sql_query"}}]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let msg = &v["choices"][0]["message"];
    // tool_calls should be removed / blocked for ENGINEER
    assert!(
        msg.get("tool_calls").is_none()
            || msg["tool_calls"].as_array().map(|a| a.is_empty()).unwrap_or(true)
            || msg["content"].as_str().unwrap_or("").contains("blocked")
    );
}

#[tokio::test]
async fn production_rejects_spoofed_headers() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_app(RunMode::Production, format!("http://{addr}"), false).await;
    let app = router(st);
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-paac-user", "user:hr-head")
                .header("x-paac-roles", "HR_HEAD")
                .body(axum::body::Body::from(
                    json!({
                        "model": "test",
                        "messages": [{"role":"user","content":"hello"}]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn check_deny_by_default_empty_roles() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_app(RunMode::Development, format!("http://{addr}"), true).await;
    let app = router(st);
    let req = AuthzRequest {
        principal: Principal::with_roles("user:nobody", vec![]),
        action: Action::new("READ"),
        resource: Resource::kind("TRAVEL_EXPENSE"),
        subject: None,
        context: ContextMap::default(),
        relationships: vec![],
        acting_as: None,
        on_behalf_of: None,
    };
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/check")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_string(&req).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["effect"], "DENY");
}

#[tokio::test]
async fn concurrent_checks() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_app(RunMode::Development, format!("http://{addr}"), true).await;
    let mut handles = vec![];
    for _ in 0..32 {
        let st = st.clone();
        handles.push(tokio::spawn(async move {
            let req = AuthzRequest {
                principal: Principal::with_roles("user:hr-head", vec!["HR_HEAD".into()]),
                action: Action::new("TOOL_INVOKE"),
                resource: Resource {
                    kind: "DB_TABLE".into(),
                    id: Some("db.hr.employees".into()),
                    attrs: IndexMap::new(),
                },
                subject: None,
                context: ContextMap::default(),
                relationships: vec![],
                acting_as: None,
                on_behalf_of: None,
            };
            let d = st.engine.check(&req).unwrap();
            d.effect
        }));
    }
    for h in handles {
        let effect = h.await.unwrap();
        assert_eq!(effect, DecisionEffect::Allow);
    }
}

