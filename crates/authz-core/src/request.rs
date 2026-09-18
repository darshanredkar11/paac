use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Canonical authorization request. Built by adapters / llm-bridge; never trusted for authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthzRequest {
    pub principal: Principal,
    pub action: Action,
    pub resource: Resource,
    pub subject: Option<Subject>,
    #[serde(default)]
    pub context: ContextMap,
    #[serde(default)]
    pub relationships: Vec<Relationship>,
    /// Agent or service acting as the principal.
    #[serde(default)]
    pub acting_as: Option<String>,
    /// Human who delegated authority (on_behalf_of).
    #[serde(default)]
    pub on_behalf_of: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub attrs: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Action {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resource {
    pub kind: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub attrs: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    pub id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub attrs: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ContextMap {
    #[serde(flatten)]
    pub values: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Relationship {
    pub kind: RelationshipKind,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    ManagerOf,
    DirectReports,
    GroupMember,
    Delegation,
}

impl AuthzRequest {
    pub fn validate(&self) -> Result<(), crate::AuthzError> {
        if self.principal.id.trim().is_empty() {
            return Err(crate::AuthzError::InvalidRequest(
                "principal.id is required".into(),
            ));
        }
        if self.action.name.trim().is_empty() {
            return Err(crate::AuthzError::InvalidRequest(
                "action.name is required".into(),
            ));
        }
        if self.resource.kind.trim().is_empty() {
            return Err(crate::AuthzError::InvalidRequest(
                "resource.kind is required".into(),
            ));
        }
        Ok(())
    }
}

impl Action {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Resource {
    pub fn kind(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: None,
            attrs: IndexMap::new(),
        }
    }
}

impl Principal {
    pub fn with_roles(id: impl Into<String>, roles: Vec<String>) -> Self {
        Self {
            id: id.into(),
            roles,
            groups: Vec::new(),
            attrs: IndexMap::new(),
        }
    }
}
