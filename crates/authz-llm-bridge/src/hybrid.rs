//! Hybrid Natural Language Extractor: Deterministic heuristics with SLM/Classifier fallback.

use async_trait::async_trait;
use authz_catalog::ResourceCatalog;
use authz_core::{AuthzRequest, Principal};
use crate::bind_extraction;
use crate::error::BridgeError;
use crate::extract::{extract_structured, NlExtraction};

/// Trait for SLM / Guardrail Classifier models (e.g., Jev, Ollama structured output, or local SLMs).
#[async_trait]
pub trait ClassifierProvider: Send + Sync {
    async fn classify(&self, utterance: &str) -> Result<NlExtraction, BridgeError>;
}

/// Mock classifier provider for testing fallback intent extraction.
pub struct MockClassifierProvider;

#[async_trait]
impl ClassifierProvider for MockClassifierProvider {
    async fn classify(&self, utterance: &str) -> Result<NlExtraction, BridgeError> {
        let lower = utterance.to_lowercase();
        if lower.contains("salary") || lower.contains("pay") {
            Ok(NlExtraction {
                action: "EXPORT".into(),
                resource_kind: "SALARY".into(),
                resource_id: Some("api.export.payroll".into()),
                subject_id: None,
                subject_groups: vec!["PAYROLL".into()],
                direct_reports: vec![],
                confidence: 0.95,
                utterance: utterance.to_string(),
            })
        } else {
            Err(BridgeError::Msg("classifier intent unresolved".into()))
        }
    }
}

/// Hybrid NL Extractor that tries deterministic extraction first, falling back to a classifier model.
pub struct HybridExtractor {
    pub catalog: Option<ResourceCatalog>,
    pub classifier: Option<Box<dyn ClassifierProvider>>,
}

impl HybridExtractor {
    pub fn new(catalog: Option<ResourceCatalog>, classifier: Option<Box<dyn ClassifierProvider>>) -> Self {
        Self { catalog, classifier }
    }

    pub async fn build_proposal(
        &self,
        principal: Principal,
        utterance: &str,
    ) -> Result<AuthzRequest, BridgeError> {
        // Step 1: Fast deterministic extraction
        if let Ok(ext) = extract_structured(utterance) {
            if ext.confidence >= 0.7 {
                return bind_extraction(principal, &ext, self.catalog.as_ref());
            }
        }

        // Step 2: Fallback to structured classifier (e.g. Jev / SLM)
        if let Some(cls) = &self.classifier {
            if let Ok(ext) = cls.classify(utterance).await {
                return bind_extraction(principal, &ext, self.catalog.as_ref());
            }
        }

        // Default fallback proposal: bind unclassified utterance for Cedar evaluation
        let ext = NlExtraction {
            action: "READ".into(),
            resource_kind: "UNKNOWN".into(),
            resource_id: None,
            subject_id: None,
            subject_groups: vec![],
            direct_reports: vec![],
            confidence: 0.1,
            utterance: utterance.to_string(),
        };
        bind_extraction(principal, &ext, self.catalog.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hybrid_extractor_with_classifier_fallback() {
        let extractor = HybridExtractor::new(
            None,
            Some(Box::new(MockClassifierProvider)),
        );
        let principal = Principal::with_roles("user:payroll-admin", vec!["PAYROLL_ADMIN".into()]);
        let req = extractor
            .build_proposal(principal, "export salary breakdown for team")
            .await
            .unwrap();
        assert_eq!(req.action.name, "EXPORT");
        assert_eq!(req.resource.kind, "SALARY");
    }
}
