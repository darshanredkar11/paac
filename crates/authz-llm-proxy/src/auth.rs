use axum::http::HeaderMap;

use authz_core::Principal;
use authz_identity::{CanonicalIdentity, IdentityCache, JwtOidcAdapter};

use crate::config::{ProxyConfig, RunMode};
use crate::error::ProxyError;

pub async fn resolve_principal(
    headers: &HeaderMap,
    cfg: &ProxyConfig,
    jwt: &JwtOidcAdapter,
    cache: &IdentityCache,
) -> Result<Principal, ProxyError> {
    // 1) Authorization: Bearer <jwt>
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")) {
            let cache_key = format!("jwt:{}", &token[..token.len().min(32)]);
            if let Some(id) = cache.get(&cache_key) {
                return Ok(identity_to_principal(id));
            }
            let id = if cfg.mode == RunMode::Production
                || cfg.identity.jwt_hmac_secret.is_some()
                || cfg.identity.jwks_url.is_some()
            {
                jwt.normalize(token)
                    .await
                    .map_err(|e| ProxyError::Unauthorized(e.to_string()))?
            } else {
                JwtOidcAdapter::normalize_unverified(token)
                    .map_err(|e| ProxyError::Unauthorized(e.to_string()))?
            };
            cache.put(&cache_key, id.clone(), id.source.clone());
            return Ok(identity_to_principal(id));
        }
    }

    // 2) Spoofable headers — development only
    if cfg.identity.allow_header_identity && cfg.mode != RunMode::Production {
        if let Some(user) = headers.get("x-paac-user").and_then(|v| v.to_str().ok()) {
            let roles = headers
                .get("x-paac-roles")
                .and_then(|v| v.to_str().ok())
                .map(|s| {
                    s.split(',')
                        .map(|r| r.trim().to_string())
                        .filter(|r| !r.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            return Ok(Principal::with_roles(user, roles));
        }
    }

    if cfg.mode == RunMode::Production {
        return Err(ProxyError::Unauthorized(
            "identity required (Authorization Bearer JWT)".into(),
        ));
    }

    Err(ProxyError::Unauthorized(
        "missing identity: provide Authorization Bearer JWT or X-PAAC-User (dev)".into(),
    ))
}

fn identity_to_principal(id: CanonicalIdentity) -> Principal {
    Principal {
        id: id.id,
        roles: id.roles,
        groups: id.groups,
        attrs: id.attrs,
    }
}
