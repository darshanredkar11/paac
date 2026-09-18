use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use authz_catalog::{load_catalog, ResourceCatalog};
use authz_core::{
    evaluate, AuthzDecision, AuthzRequest, BundleCache, DecisionEffect, HotBundle,
};
use authz_policy::{verify_bundle, BundleSigner, LocalEd25519Signer, PolicyStore, SigningKeyPair};
use authz_store::PaacStore;

use crate::config::{ProxyConfig, RunMode};
use crate::error::ProxyError;

pub struct AuthzEngine {
    pub bundle: BundleCache,
    pub catalog: Arc<ResourceCatalog>,
    pub store: Option<Arc<PaacStore>>,
    pub require_signed: bool,
    pub mode: RunMode,
}

impl AuthzEngine {
    pub fn from_config(cfg: &ProxyConfig, sqlite_path: Option<&Path>) -> Result<Self, ProxyError> {
        let policy_store = PolicyStore::open(&cfg.policy_dir)
            .map_err(|e| ProxyError::NotReady(e.to_string()))?;
        let (rev, policy_set) = match policy_store.policy_set_from_deployed() {
            Ok((set, rev)) => (rev, set),
            Err(e) => {
                if cfg.mode == RunMode::Production || cfg.require_signed_bundle {
                    return Err(ProxyError::NotReady(format!(
                        "signed deployed bundle required: {e}"
                    )));
                }
                // Dev fallback: active DSL
                let dsl = policy_store
                    .read_active_dsl()
                    .map_err(|e| ProxyError::NotReady(e.to_string()))?;
                let policies = policy_store
                    .validate_dsl(&dsl)
                    .map_err(|e| ProxyError::NotReady(e.to_string()))?;
                let set = Arc::new(
                    authz_policy::cedar_policy_set_from_dsl(&policies)
                        .map_err(|e| ProxyError::NotReady(e.to_string()))?,
                );
                return Ok(Self {
                    bundle: BundleCache::new(HotBundle {
                        policy_set: set,
                        policy_revision: "dev-unsigned".into(),
                        policy_signature: None,
                        signature_key_id: None,
                        content_sha256: None,
                        group_members: Arc::new(HashMap::new()),
                    }),
                    catalog: Arc::new(
                        load_catalog(&cfg.catalog_path).unwrap_or_default(),
                    ),
                    store: sqlite_path.and_then(|p| PaacStore::open(p).ok().map(Arc::new)),
                    require_signed: false,
                    mode: cfg.mode.clone(),
                });
            }
        };

        if cfg.require_signed_bundle || cfg.mode == RunMode::Production {
            let bundle = rev.bundle.as_ref().ok_or_else(|| {
                ProxyError::NotReady("deployed revision has no signature".into())
            })?;
            // Verify if we have a local key file (optional in tests).
            if let Ok(key_data) = std::fs::read_to_string("data/keys/signing.json") {
                if let Ok(pair) = serde_json::from_str::<SigningKeyPair>(&key_data) {
                    if let Ok(signer) = LocalEd25519Signer::from_keypair(&pair) {
                        verify_bundle(bundle, &signer.verifying_key_bytes()).map_err(|e| {
                            ProxyError::NotReady(format!("bundle signature invalid: {e}"))
                        })?;
                    }
                }
            }
        }

        let sig = rev.bundle.as_ref().map(|b| b.key_id.clone());
        let sha = rev.bundle.as_ref().map(|b| b.content_sha256.clone());
        let catalog = load_catalog(&cfg.catalog_path).unwrap_or_default();
        let store = match sqlite_path {
            Some(p) => Some(Arc::new(
                PaacStore::open(p).map_err(|e| ProxyError::Internal(e.to_string()))?,
            )),
            None => None,
        };

        if let Some(s) = &store {
            let _ = s.upsert_policy_revision(
                &rev.revision,
                &rev.message,
                &rev.dsl,
                &rev.cedar,
                sha.as_deref(),
                sig.as_deref(),
                rev.bundle.as_ref().map(|b| b.signature_b64.as_str()),
                true,
            );
        }

        Ok(Self {
            bundle: BundleCache::new(HotBundle {
                policy_set,
                policy_revision: rev.revision,
                policy_signature: sig.clone(),
                signature_key_id: sig,
                content_sha256: sha,
                group_members: Arc::new(HashMap::new()),
            }),
            catalog: Arc::new(catalog),
            store,
            require_signed: cfg.require_signed_bundle,
            mode: cfg.mode.clone(),
        })
    }

    pub fn check(&self, req: &AuthzRequest) -> Result<AuthzDecision, ProxyError> {
        let start = Instant::now();
        let hot = self.bundle.load();
        if self.require_signed && hot.policy_signature.is_none() {
            return Err(ProxyError::NotReady(
                "unsigned policy bundle rejected".into(),
            ));
        }
        let cfg = hot.to_evaluator_config();
        let decision =
            evaluate(req, &cfg).map_err(|e| ProxyError::BadRequest(e.to_string()))?;
        let latency = start.elapsed().as_millis() as u64;
        if let Some(store) = &self.store {
            let _ = store.enqueue_audit(&decision, latency, hot.signature_key_id.clone());
        }
        Ok(decision)
    }

    pub fn is_ready(&self) -> Result<(), ProxyError> {
        let hot = self.bundle.load();
        if self.require_signed && hot.policy_signature.is_none() {
            return Err(ProxyError::NotReady("signed bundle not loaded".into()));
        }
        Ok(())
    }

    pub fn allow_or_forbid(&self, req: &AuthzRequest) -> Result<AuthzDecision, ProxyError> {
        let d = self.check(req)?;
        if d.effect != DecisionEffect::Allow {
            return Err(ProxyError::Forbidden {
                message: format!(
                    "PAAC denied {} on {}",
                    req.action.name, req.resource.kind
                ),
                decision_id: d.evidence.decision_id.clone(),
                body: serde_json::to_value(&d).unwrap_or_default(),
            });
        }
        Ok(d)
    }
}
