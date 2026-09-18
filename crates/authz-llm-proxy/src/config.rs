use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    Development,
    Production,
}

impl Default for RunMode {
    fn default() -> Self {
        Self::Development
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub mode: RunMode,
    #[serde(default = "default_true")]
    pub require_signed_bundle: bool,
    #[serde(default = "default_policy_dir")]
    pub policy_dir: PathBuf,
    #[serde(default = "default_catalog")]
    pub catalog_path: PathBuf,
    #[serde(default = "default_audit")]
    pub audit_path: PathBuf,
    #[serde(default = "default_identity_dir")]
    pub identity_dir: PathBuf,
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub connectors: ConnectorsConfig,
}

fn default_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_true() -> bool {
    true
}
fn default_policy_dir() -> PathBuf {
    PathBuf::from("data/policies")
}
fn default_catalog() -> PathBuf {
    PathBuf::from("data/catalog/company_resources.yaml")
}
fn default_audit() -> PathBuf {
    PathBuf::from("data/audit/decisions.jsonl")
}
fn default_identity_dir() -> PathBuf {
    PathBuf::from("data/identity")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub base_url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    120
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityConfig {
    #[serde(default)]
    pub jwt_hmac_secret: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default = "default_true")]
    pub prefer_jwt_roles: bool,
    /// Allow X-PAAC-User / X-PAAC-Roles headers (development only recommended).
    #[serde(default = "default_true")]
    pub allow_header_identity: bool,
    #[serde(default)]
    pub ldap: Option<LdapSection>,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_cache_ttl() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapSection {
    pub url: String,
    pub bind_dn: String,
    #[serde(default)]
    pub bind_password: String,
    pub base_dn: String,
    #[serde(default = "default_true")]
    pub mock: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectorsConfig {
    /// When true, proxy executes allowed tool_calls via connectors.
    #[serde(default)]
    pub execute_tools: bool,
    #[serde(default)]
    pub http_base_url: Option<String>,
}

impl ProxyConfig {
    pub fn load(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())?;
        let mut cfg: ProxyConfig = toml::from_str(&raw)?;
        cfg.apply_env();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("PAAC_LISTEN") {
            self.listen = v;
        }
        if let Ok(v) = std::env::var("PAAC_MODE") {
            self.mode = match v.to_ascii_lowercase().as_str() {
                "production" | "prod" => RunMode::Production,
                _ => RunMode::Development,
            };
        }
        if let Ok(v) = std::env::var("PAAC_UPSTREAM_URL") {
            self.upstream.base_url = v;
        }
        if let Ok(v) = std::env::var("PAAC_UPSTREAM_API_KEY") {
            self.upstream.api_key = Some(v);
        }
        if let Ok(v) = std::env::var("PAAC_JWT_SECRET") {
            self.identity.jwt_hmac_secret = Some(v);
        }
        if let Ok(v) = std::env::var("PAAC_JWKS_URL") {
            self.identity.jwks_url = Some(v);
        }
        if let Ok(v) = std::env::var("PAAC_AUDIT_PATH") {
            self.audit_path = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("PAAC_POLICY_DIR") {
            self.policy_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("PAAC_REQUIRE_SIGNED_BUNDLE") {
            self.require_signed_bundle = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        if let Ok(v) = std::env::var("PAAC_LDAP_URL") {
            let ldap = self.identity.ldap.get_or_insert(LdapSection {
                url: v.clone(),
                bind_dn: String::new(),
                bind_password: String::new(),
                base_dn: String::new(),
                mock: true,
            });
            ldap.url = v;
        }
        if self.mode == RunMode::Production {
            self.require_signed_bundle = true;
            self.identity.allow_header_identity = false;
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.upstream.base_url.trim().is_empty() {
            anyhow::bail!("upstream.base_url is required");
        }
        if self.mode == RunMode::Production {
            if self.identity.jwt_hmac_secret.is_none() && self.identity.jwks_url.is_none() {
                anyhow::bail!("production mode requires jwt_hmac_secret or jwks_url");
            }
            if self.identity.allow_header_identity {
                anyhow::bail!("production mode rejects spoofable header identity");
            }
        }
        Ok(())
    }
}
