//! PAAC authorization kernel (embeddable).
//!
//! The LLM may interpret intent; only this crate grants ALLOW | DENY | REVIEW.
//! Deny-by-default. Evaluation is deterministic and explainable.
//!
//! # Extension points
//! - Build requests with [`AuthzRequestBuilder`] and validated [`ids`] newtypes.
//! - Call [`evaluate`] with an [`EvaluatorConfig`] holding an in-memory Cedar `PolicySet`.
//! - Never pass LLM output as an authority signal — only as a proposed request to revalidate.

mod builder;
mod decision;
mod entities;
mod error;
mod evaluate;
mod hot_cache;
mod ids;
mod request;

pub use builder::AuthzRequestBuilder;
pub use decision::{AuthzDecision, DecisionEffect, Evidence, MatchedPolicy};
pub use entities::{build_entities, EntityBuildInput};
pub use error::AuthzError;
pub use evaluate::{evaluate, EvaluatorConfig, ENGINE_VERSION};
pub use hot_cache::{BundleCache, HotBundle};
pub use ids::{ActionName, AgentId, DecisionId, PrincipalId, ResourceId, ResourceKind};
pub use request::{
    Action, AuthzRequest, ContextMap, Principal, Relationship, RelationshipKind, Resource,
    Subject,
};

#[cfg(test)]
mod edge_tests;
