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
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower::ServiceExt;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    roles: Vec<String>,
    exp: usize,
}

async fn spawn_mock_llm_with_mixed_tools() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async move {
            axum::Json(json!({
                "id": "chatcmpl-regression",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [
                            {
                                "id": "call_allowed",
                                "type": "function",
                                "function": {
                                    "name": "sql_query",
                                    "arguments": "{\"table\":\"db.hr.employees\",\"sql\":\"select name from employees\"}"
                                }
                            },
                            {
                                "id": "call_forbidden",
                                "type": "function",
                                "function": {
                                    "name": "export_payroll",
                                    "arguments": "{\"employee_id\":\"all\"}"
                                }
                            }
                        ]
                    },
                    "finish_reason": "tool_calls"
                }]
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
    store.commit("regression test policies").unwrap();
    let (signer, pair) = LocalEd25519Signer::generate("regr-key");
    let _ = pair;
    store.sign_head(&signer).unwrap();
    store.deploy_head().unwrap();
}

fn resolve_catalog_path() -> std::path::PathBuf {
    let p1 = std::path::PathBuf::from("examples/catalog/company_resources.yaml");
    if p1.exists() {
        return p1;
    }
    let p2 = std::path::PathBuf::from("../../examples/catalog/company_resources.yaml");
    if p2.exists() {
        return p2;
    }
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/catalog/company_resources.yaml")
}

async fn build_app(mode: RunMode, upstream: String, allow_headers: bool) -> Arc<AppState> {
    let tmp = tempfile::tempdir().unwrap();
    let policy_dir = tmp.path().join("policies");
    prepare_policies(&policy_dir);
    let catalog = resolve_catalog_path();
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
            jwt_hmac_secret: Some("secret-hmac-key-12345".into()),
            jwks_url: None,
            prefer_jwt_roles: true,
            allow_header_identity: allow_headers,
            ldap: None,
            cache_ttl_secs: 60,
        },
        connectors: ConnectorsConfig::default(),
    };
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
        .with_state(st)
}

#[tokio::test]
async fn edge_case_jwt_auth_success_and_invalid_signature_rejection() {
    let st = build_app(RunMode::Production, "http://127.0.0.1:9999".into(), false).await;
    let app = router(st);

    let my_claims = Claims {
        sub: "user:hr-head".to_string(),
        roles: vec!["HR_HEAD".to_string()],
        exp: 2000000000,
    };

    // Valid JWT signed with matching secret
    let valid_token = encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(b"secret-hmac-key-12345"),
    )
    .unwrap();

    // Invalid JWT signed with wrong secret
    let invalid_token = encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(b"wrong-secret-key"),
    )
    .unwrap();

    // 1. Invalid JWT should yield HTTP 401
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {invalid_token}"))
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

    // 2. Valid JWT should pass auth phase
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {valid_token}"))
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
    // Upstream doesn't exist so it returns 502 Bad Gateway / Upstream Error, but NOT 401 Unauthorized
    assert_ne!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn edge_case_unknown_tool_maps_to_tool_unknown_and_denies() {
    let st = build_app(RunMode::Development, "http://127.0.0.1:9999".into(), true).await;
    let catalog = authz_catalog::ResourceCatalog::default();

    let req = catalog.authz_for_tool(
        Principal::with_roles("user:hr-head", vec!["HR_HEAD".into()]),
        "unknown_invented_tool_name",
        &json!({"arg1": "val1"}),
    );

    assert_eq!(req.action.name, "TOOL_INVOKE");
    assert_eq!(req.resource.kind, "TOOL_UNKNOWN");
    assert_eq!(req.resource.id.as_deref(), Some("unknown_invented_tool_name"));

    let decision = st.engine.check(&req).unwrap();
    assert_eq!(decision.effect, DecisionEffect::Deny);
}

#[tokio::test]
async fn edge_case_partial_tool_filtering_strips_forbidden_calls() {
    let (addr, _h) = spawn_mock_llm_with_mixed_tools().await;
    let st = build_app(RunMode::Development, format!("http://{addr}"), true).await;
    let app = router(st);

    // HR_HEAD can execute sql_query on DB_TABLE, but NOT export_payroll (requires PAYROLL_ADMIN)
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

    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let tcs = v["choices"][0]["message"]["tool_calls"].as_array().unwrap();
    // Only 1 tool call should remain (call_allowed for sql_query), while export_payroll is stripped
    assert_eq!(tcs.len(), 1);
    assert_eq!(tcs[0]["id"], "call_allowed");
}

#[tokio::test]
async fn stress_test_high_concurrency_policy_checks() {
    let st = build_app(RunMode::Development, "http://127.0.0.1:9999".into(), true).await;
    let mut tasks = vec![];

    for i in 0..64 {
        let st = st.clone();
        tasks.push(tokio::spawn(async move {
            let role = if i % 2 == 0 { "HR_HEAD" } else { "ENGINEER" };
            let req = AuthzRequest {
                principal: Principal::with_roles(&format!("user:{i}"), vec![role.into()]),
                action: Action::new("READ"),
                resource: Resource::kind("EMPLOYEE_PROFILE"),
                subject: Some(authz_core::Subject {
                    id: format!("user:{i}"),
                    kind: "Employee".into(),
                    groups: vec![],
                    attrs: indexmap::IndexMap::new(),
                }),
                context: ContextMap::default(),
                relationships: vec![],
                acting_as: None,
                on_behalf_of: None,
            };
            st.engine.check(&req).unwrap()
        }));
    }

    for task in tasks {
        let decision = task.await.unwrap();
        // Self profile read allows all roles
        assert_eq!(decision.effect, DecisionEffect::Allow);
    }
}
