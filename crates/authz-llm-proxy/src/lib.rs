//! PAAC LLM Authorization Gateway library (embeddable).

pub mod a2a;
pub mod auth;
pub mod config;
pub mod connectors;
pub mod engine;
pub mod error;
pub mod mcp;
pub mod openai;
pub mod routes;
pub mod state;

pub use config::{ProxyConfig, RunMode};
pub use engine::AuthzEngine;
pub use state::AppState;
