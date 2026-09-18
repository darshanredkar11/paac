//! ArcSwap-backed signed policy bundle cache for the authz hot path.

use std::sync::Arc;

use arc_swap::ArcSwap;
use cedar_policy::PolicySet;

use crate::evaluate::EvaluatorConfig;

#[derive(Clone)]
pub struct HotBundle {
    pub policy_set: Arc<PolicySet>,
    pub policy_revision: String,
    pub policy_signature: Option<String>,
    pub signature_key_id: Option<String>,
    pub content_sha256: Option<String>,
    pub group_members: Arc<std::collections::HashMap<String, Vec<String>>>,
}

impl HotBundle {
    pub fn to_evaluator_config(&self) -> EvaluatorConfig {
        EvaluatorConfig {
            policy_set: self.policy_set.clone(),
            policy_revision: self.policy_revision.clone(),
            policy_signature: self.policy_signature.clone(),
            group_members: (*self.group_members).clone(),
        }
    }
}

/// Lock-free swap of the active signed bundle (check path only loads Arc).
pub struct BundleCache {
    inner: ArcSwap<HotBundle>,
}

impl BundleCache {
    pub fn new(bundle: HotBundle) -> Self {
        Self {
            inner: ArcSwap::from_pointee(bundle),
        }
    }

    pub fn load(&self) -> Arc<HotBundle> {
        self.inner.load_full()
    }

    pub fn store(&self, bundle: HotBundle) {
        self.inner.store(Arc::new(bundle));
    }

    pub fn evaluator_config(&self) -> EvaluatorConfig {
        self.load().to_evaluator_config()
    }
}
