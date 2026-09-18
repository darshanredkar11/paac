use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use authz_llm_proxy::config::ProxyConfig;
use authz_llm_proxy::engine::AuthzEngine;
use authz_llm_proxy::routes;
use authz_llm_proxy::state::AppState;
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "paac-proxy", about = "PAAC LLM Authorization Gateway")]
struct Args {
    #[arg(long, default_value = "paac.toml")]
    config: PathBuf,
    #[arg(long)]
    listen: Option<String>,
    #[arg(long, default_value = "data/paac.db")]
    sqlite: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args = Args::parse();
    let mut cfg = if args.config.exists() {
        ProxyConfig::load(&args.config)?
    } else {
        tracing::warn!("config {} missing — using env/defaults", args.config.display());
        let mut c = ProxyConfig {
            listen: "127.0.0.1:8080".into(),
            mode: authz_llm_proxy::RunMode::Development,
            require_signed_bundle: false,
            policy_dir: PathBuf::from("data/policies"),
            catalog_path: PathBuf::from("data/catalog/company_resources.yaml"),
            audit_path: PathBuf::from("data/audit/decisions.jsonl"),
            identity_dir: PathBuf::from("data/identity"),
            upstream: authz_llm_proxy::config::UpstreamConfig {
                base_url: std::env::var("PAAC_UPSTREAM_URL")
                    .unwrap_or_else(|_| "http://127.0.0.1:9000".into()),
                api_key: std::env::var("PAAC_UPSTREAM_API_KEY").ok(),
                timeout_secs: 120,
            },
            identity: Default::default(),
            connectors: Default::default(),
        };
        c.apply_env();
        c
    };
    if let Some(l) = args.listen {
        cfg.listen = l;
    }

    let engine = AuthzEngine::from_config(&cfg, Some(&args.sqlite))
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let state = Arc::new(AppState::new(cfg.clone(), engine));

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/ready", get(routes::ready))
        .route("/metrics", get(routes::metrics))
        .route("/v1/chat/completions", post(routes::chat_completions))
        .route("/v1/retrieve", post(routes::retrieve))
        .route("/v1/check", post(routes::check))
        .route("/v1/explain/{id}", get(routes::explain))
        .route("/v1/board", get(routes::board_page))
        .route("/v1/board/matrix", get(routes::board_matrix))
        .route("/v1/board/decisions", get(routes::board_decisions))
        .route("/v1/mcp/tools/call", post(routes::mcp_tools_call))
        .route("/v1/a2a/authorize", post(routes::a2a_authorize))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr: SocketAddr = cfg.listen.parse().context("listen addr")?;
    tracing::info!("paac-proxy listening on http://{addr} (upstream {})", cfg.upstream.base_url);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
