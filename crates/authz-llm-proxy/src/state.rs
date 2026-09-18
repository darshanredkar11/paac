use std::sync::Arc;

use authz_identity::{IdentityCache, JwtOidcAdapter};
use parking_lot::RwLock;

use crate::config::ProxyConfig;
use crate::connectors::{DataConnector, MockDataConnector};
use crate::engine::AuthzEngine;

pub struct AppState {
    pub cfg: ProxyConfig,
    pub engine: AuthzEngine,
    pub jwt: JwtOidcAdapter,
    pub identity_cache: IdentityCache,
    pub connector: Arc<dyn DataConnector>,
    pub metrics: RwLock<Metrics>,
}

#[derive(Default, Clone)]
pub struct Metrics {
    pub checks_total: u64,
    pub denies_total: u64,
    pub allows_total: u64,
    pub upstream_calls: u64,
}

impl AppState {
    pub fn new(cfg: ProxyConfig, engine: AuthzEngine) -> Self {
        let jwt = JwtOidcAdapter {
            hmac_secret: cfg.identity.jwt_hmac_secret.clone(),
            jwks_url: cfg.identity.jwks_url.clone(),
            require_exp: cfg.mode == crate::config::RunMode::Production,
        };
        let connector: Arc<dyn DataConnector> = if let Some(url) = &cfg.connectors.http_base_url {
            Arc::new(crate::connectors::HttpDataConnector {
                base_url: url.clone(),
                client: reqwest::Client::new(),
            })
        } else {
            Arc::new(MockDataConnector)
        };
        Self {
            identity_cache: IdentityCache::new(std::time::Duration::from_secs(
                cfg.identity.cache_ttl_secs,
            )),
            cfg,
            engine,
            jwt,
            connector,
            metrics: RwLock::new(Metrics::default()),
        }
    }
}
