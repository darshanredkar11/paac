use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use authz_board::{build_matrix, BOARD_HTML};
use authz_core::{evaluate, AuthzDecision, AuthzRequest, EvaluatorConfig};
use authz_policy::{parse_dsl, PolicyStore};
use authz_suggest::append_audit;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::{Router};
use clap::Parser;
use parking_lot::RwLock;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "authz-gateway")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
    #[arg(long, default_value = "data/policies")]
    policy_dir: PathBuf,
    #[arg(long, default_value = "data/audit/decisions.jsonl")]
    audit_path: PathBuf,
}

struct AppState {
    store: PolicyStore,
    audit_path: PathBuf,
    decisions: RwLock<HashMap<String, AuthzDecision>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args = Args::parse();
    let store = PolicyStore::open(&args.policy_dir)?;
    let state = Arc::new(AppState {
        store,
        audit_path: args.audit_path,
        decisions: RwLock::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/check", post(check))
        .route("/v1/explain/{id}", get(explain))
        .route("/v1/board", get(board_page))
        .route("/v1/board/matrix", get(board_matrix))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr: SocketAddr = args.listen.parse().context("listen addr")?;
    tracing::info!("authz-gateway listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "service": "authz-gateway", "version": "0.1.0" }))
}

async fn check(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthzRequest>,
) -> Result<Json<AuthzDecision>, (axum::http::StatusCode, String)> {
    let (policy_set, rev) = state
        .store
        .policy_set_from_deployed()
        .map_err(|e| (axum::http::StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;

    let sig = rev
        .bundle
        .as_ref()
        .map(|b| format!("{}:{}", b.key_id, &b.signature_b64[..16.min(b.signature_b64.len())]));

    let cfg = EvaluatorConfig {
        policy_set,
        policy_revision: rev.revision.clone(),
        policy_signature: sig,
        group_members: HashMap::new(),
    };

    let decision = evaluate(&req, &cfg)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;

    let _ = append_audit(&state.audit_path, &decision);
    state
        .decisions
        .write()
        .insert(decision.evidence.decision_id.clone(), decision.clone());

    Ok(Json(decision))
}

async fn explain(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<AuthzDecision>, (axum::http::StatusCode, String)> {
    state
        .decisions
        .read()
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or((axum::http::StatusCode::NOT_FOUND, "decision not found".into()))
}

async fn board_page() -> Html<&'static str> {
    Html(BOARD_HTML)
}

async fn board_matrix(
    State(state): State<Arc<AppState>>,
) -> Result<Json<authz_board::PolicyMatrix>, (axum::http::StatusCode, String)> {
    let dsl = state
        .store
        .read_active_dsl()
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let policies = parse_dsl(&dsl).unwrap_or_default();
    Ok(Json(build_matrix(&policies)))
}
