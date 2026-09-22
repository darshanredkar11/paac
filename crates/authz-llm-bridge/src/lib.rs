//! Natural language → AuthzRequest **proposal**.
//!
//! The bridge never grants authority. Callers must re-evaluate the returned
//! [`AuthzRequest`] with `authz_core::evaluate`.

mod extract;
mod error;
mod hybrid;

pub use error::BridgeError;
pub use extract::{extract_structured, NlExtraction, StructuredExtractor};
pub use hybrid::{ClassifierProvider, HybridExtractor, MockClassifierProvider};

use async_trait::async_trait;
use authz_catalog::ResourceCatalog;
use authz_core::{
    AuthzRequest, AuthzRequestBuilder, Principal, Relationship, RelationshipKind,
};
use indexmap::IndexMap;

#[async_trait]
pub trait LlmRequestBuilder: Send + Sync {
    async fn build_request(&self, utterance: &str) -> Result<AuthzRequest, BridgeError>;
}

/// Deterministic structured extractor + optional catalog binding.
pub struct CatalogAwareBridge {
    pub default_principal: Principal,
    pub catalog: Option<ResourceCatalog>,
}

impl Default for CatalogAwareBridge {
    fn default() -> Self {
        Self {
            default_principal: Principal::with_roles("user:hr-head", vec!["HR_HEAD".into()]),
            catalog: None,
        }
    }
}

#[async_trait]
impl LlmRequestBuilder for CatalogAwareBridge {
    async fn build_request(&self, utterance: &str) -> Result<AuthzRequest, BridgeError> {
        let extraction = extract_structured(utterance)?;
        bind_extraction(self.default_principal.clone(), &extraction, self.catalog.as_ref())
    }
}

pub fn bind_extraction(
    principal: Principal,
    extraction: &NlExtraction,
    catalog: Option<&ResourceCatalog>,
) -> Result<AuthzRequest, BridgeError> {
    let mut attrs = IndexMap::new();
    let mut resource_kind = extraction.resource_kind.clone();
    let mut resource_id = extraction.resource_id.clone();

    if let Some(cat) = catalog {
        if let Some(id) = &extraction.resource_id {
            if let Some(res) = cat.find_resource(id) {
                resource_kind = res.kind.clone();
                if let Some(d) = &res.department {
                    attrs.insert("department".into(), d.clone());
                }
                if let Some(s) = &res.sensitivity {
                    attrs.insert("sensitivity".into(), s.clone());
                }
            }
        } else if let Some(res) = cat.resources.iter().find(|r| {
            r.kind.eq_ignore_ascii_case(&extraction.resource_kind)
                || r.name.to_ascii_lowercase().contains(&extraction.resource_kind.to_ascii_lowercase())
        }) {
            resource_id = Some(res.id.clone());
            resource_kind = res.kind.clone();
            if let Some(d) = &res.department {
                attrs.insert("department".into(), d.clone());
            }
            if let Some(s) = &res.sensitivity {
                attrs.insert("sensitivity".into(), s.clone());
            }
        }
    }

    let mut b = AuthzRequestBuilder::new()
        .principal_obj(principal.clone())?
        .action(&extraction.action)?
        .resource(resource_kind, resource_id, attrs)?;

    if let Some(subj) = &extraction.subject_id {
        b = b.subject(subj, extraction.subject_groups.clone())?;
    }
    b = b.context_kv("nl_utterance", &extraction.utterance);
    b = b.context_kv("extraction_confidence", extraction.confidence.to_string());
    b = b.context_kv("proposal_only", "true");

    for dr in &extraction.direct_reports {
        b = b.relationship(Relationship {
            kind: RelationshipKind::DirectReports,
            from: principal.id.clone(),
            to: dr.clone(),
        });
    }

    let mut req = b.build()?;
    req.acting_as = Some("agent:nl-bridge".into());
    req.on_behalf_of = Some(principal.id);
    Ok(req)
}

/// Backward-compatible mock that recognizes CEO expense phrases.
pub struct MockLlmProvider {
    pub default_principal: Principal,
}

impl Default for MockLlmProvider {
    fn default() -> Self {
        Self {
            default_principal: Principal::with_roles("user:hr-head", vec!["HR_HEAD".into()]),
        }
    }
}

#[async_trait]
impl LlmRequestBuilder for MockLlmProvider {
    async fn build_request(&self, utterance: &str) -> Result<AuthzRequest, BridgeError> {
        CatalogAwareBridge {
            default_principal: self.default_principal.clone(),
            catalog: None,
        }
        .build_request(utterance)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceo_expense_extraction() {
        let ext = extract_structured("How much did the CEO spend on trips last week?").unwrap();
        assert_eq!(ext.action, "READ");
        assert_eq!(ext.resource_kind, "TRAVEL_EXPENSE");
        assert_eq!(ext.subject_id.as_deref(), Some("employee:CEO"));
        assert!(ext.subject_groups.iter().any(|g| g == "EXECUTIVE"));
    }

    #[test]
    fn sql_toolish_query() {
        let ext = extract_structured("run sql_query on db.finance.ledger").unwrap();
        assert!(ext.action == "TOOL_INVOKE" || ext.resource_kind.contains("DB") || ext.resource_id.is_some());
    }
}
