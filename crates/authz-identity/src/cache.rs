use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::model::CanonicalIdentity;

#[derive(Debug, Clone)]
pub struct CachedIdentity {
    pub identity: CanonicalIdentity,
    pub provenance: String,
    pub inserted_at: Instant,
}

/// Short-lived identity cache with provenance tracking.
pub struct IdentityCache {
    ttl: Duration,
    inner: RwLock<HashMap<String, CachedIdentity>>,
}

impl IdentityCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, key: &str) -> Option<CanonicalIdentity> {
        let guard = self.inner.read();
        let entry = guard.get(key)?;
        if entry.inserted_at.elapsed() > self.ttl {
            return None;
        }
        Some(entry.identity.clone())
    }

    pub fn get_with_provenance(&self, key: &str) -> Option<CachedIdentity> {
        let guard = self.inner.read();
        let entry = guard.get(key)?;
        if entry.inserted_at.elapsed() > self.ttl {
            return None;
        }
        Some(entry.clone())
    }

    pub fn put(&self, key: impl Into<String>, identity: CanonicalIdentity, provenance: impl Into<String>) {
        self.inner.write().insert(
            key.into(),
            CachedIdentity {
                identity,
                provenance: provenance.into(),
                inserted_at: Instant::now(),
            },
        );
    }

    pub fn invalidate(&self, key: &str) {
        self.inner.write().remove(key);
    }

    pub fn clear_expired(&self) {
        let mut guard = self.inner.write();
        guard.retain(|_, v| v.inserted_at.elapsed() <= self.ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn ttl_expires() {
        let cache = IdentityCache::new(Duration::from_millis(30));
        let id = CanonicalIdentity {
            id: "u1".into(),
            display_name: "U".into(),
            email: None,
            source: "test".into(),
            roles: vec![],
            groups: vec![],
            attrs: Default::default(),
        };
        cache.put("u1", id, "unit-test");
        assert!(cache.get("u1").is_some());
        thread::sleep(Duration::from_millis(40));
        assert!(cache.get("u1").is_none());
    }
}
