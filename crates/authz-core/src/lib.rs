//! PAAC authorization kernel.
//!
//! The LLM may interpret intent; only this crate grants ALLOW | DENY | REVIEW.
//! Deny-by-default. Evaluation is deterministic and explainable.

mod decision;
mod entities;
mod error;
mod evaluate;
mod request;

pub use decision::{AuthzDecision, DecisionEffect, Evidence, MatchedPolicy};
pub use entities::{build_entities, EntityBuildInput};
pub use error::AuthzError;
pub use evaluate::{evaluate, EvaluatorConfig, ENGINE_VERSION};
pub use request::{
    Action, AuthzRequest, ContextMap, Principal, Relationship, RelationshipKind, Resource,
    Subject,
};
