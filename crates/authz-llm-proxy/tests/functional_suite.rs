use std::net::SocketAddr;
use std::sync::Arc;

use authz_llm_proxy::config::{
    ConnectorsConfig, IdentityConfig, ProxyConfig, RunMode, UpstreamConfig,
};
use authz_llm_proxy::engine::AuthzEngine;
use authz_llm_proxy::routes;
use authz_llm_proxy::state::AppState;
use authz_policy::{LocalEd25519Signer, PolicyStore};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use axum::response::{sse::Event, IntoResponse, Sse};
use tower::ServiceExt;

async fn spawn_mock_llm() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(|axum::Json(req): axum::Json<serde_json::Value>| async move {
            if req.get("stream").and_then(|v| v.as_bool()) == Some(true) {
                let stream = futures_util::stream::iter(vec![
                    Ok::<_, std::convert::Infallible>(Event::default().data("mock streaming token")),
                    Ok(Event::default().data("[DONE]")),
                ]);
                Sse::new(stream).into_response()
            } else {
                axum::Json(json!({
                    "id": "chatcmpl-func-test",
                    "object": "chat.completion",
                    "choices": [{"index":0, "message": {"role":"assistant","content":"mock llm response"}, "finish_reason":"stop"}]
                })).into_response()
            }
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
    store.commit("functional test policies").unwrap();
    let (signer, pair) = LocalEd25519Signer::generate("func-key");
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

async fn build_functional_app(upstream: String) -> Arc<AppState> {
    let tmp = tempfile::tempdir().unwrap();
    let policy_dir = tmp.path().join("policies");
    prepare_policies(&policy_dir);
    let catalog = resolve_catalog_path();
    let cfg = ProxyConfig {
        listen: "127.0.0.1:0".into(),
        mode: RunMode::Development,
        require_signed_bundle: false,
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
            jwt_hmac_secret: Some("func-test-secret".into()),
            jwks_url: None,
            prefer_jwt_roles: true,
            allow_header_identity: true,
            ldap: None,
            cache_ttl_secs: 60,
        },
        connectors: ConnectorsConfig::default(),
    };
    std::mem::forget(tmp);
    let engine = AuthzEngine::from_config(&cfg, None).expect("engine");
    Arc::new(AppState::new(cfg, engine))
}

fn functional_router(st: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/ready", get(routes::ready))
        .route("/metrics", get(routes::metrics))
        .route("/v1/chat/completions", post(routes::chat_completions))
        .route("/v1/retrieve", post(routes::retrieve))
        .route("/v1/mcp/tools/call", post(routes::mcp_tools_call))
        .route("/v1/a2a/authorize", post(routes::a2a_authorize))
        .route("/v1/board/matrix", get(routes::board_matrix))
        .route("/v1/board/decisions", get(routes::board_decisions))
        .with_state(st)
}

#[tokio::test]
async fn test_health_ready_and_metrics_endpoints() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_functional_app(format!("http://{addr}")).await;
    let app = functional_router(st);

    // GET /health
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // GET /ready
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/ready")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // GET /metrics
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/metrics")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("paac_checks_total"));
}

#[tokio::test]
async fn test_rag_retrieve_authorization() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_functional_app(format!("http://{addr}")).await;
    let app = functional_router(st);

    // HR_HEAD authorized to read VECTOR_COLLECTION
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/retrieve")
                .header("content-type", "application/json")
                .header("x-paac-user", "user:hr-head")
                .header("x-paac-roles", "HR_HEAD")
                .body(axum::body::Body::from(
                    json!({
                        "collection": "vec.hr.policies",
                        "document_id": "doc_hr_1"
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
    assert_eq!(v["collection"], "vec.hr.policies");
    assert!(v["note"].as_str().unwrap().contains("authz ALLOW"));
}

#[tokio::test]
async fn test_mcp_tools_call_authorization() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_functional_app(format!("http://{addr}")).await;
    let app = functional_router(st);

    // HR_HEAD authorized to invoke DB_TABLE sql_query tool
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/mcp/tools/call")
                .header("content-type", "application/json")
                .header("x-paac-user", "user:hr-head")
                .header("x-paac-roles", "HR_HEAD")
                .body(axum::body::Body::from(
                    json!({
                        "name": "sql_query",
                        "arguments": {"table": "db.hr.employees", "sql": "select * from employees"}
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // ENGINEER forbidden from invoking DB_TABLE sql_query tool
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/mcp/tools/call")
                .header("content-type", "application/json")
                .header("x-paac-user", "employee:alice")
                .header("x-paac-roles", "ENGINEER")
                .body(axum::body::Body::from(
                    json!({
                        "name": "sql_query",
                        "arguments": {"table": "db.finance.ledger", "sql": "select * from ledger"}
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_board_matrix_and_decisions_api() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_functional_app(format!("http://{addr}")).await;
    let app = functional_router(st);

    // GET /v1/board/matrix
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/board/matrix")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    // GET /v1/board/decisions
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/board/decisions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn test_sse_streaming_chat_completions() {
    let (addr, _h) = spawn_mock_llm().await;
    let st = build_functional_app(format!("http://{addr}")).await;
    let app = functional_router(st);

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
                        "model": "gpt-4o",
                        "messages": [{"role": "user", "content": "show alice travel expenses"}],
                        "stream": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(content_type.contains("text/event-stream"));

    let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("data:"));
    assert!(text.contains("[DONE]"));
}
