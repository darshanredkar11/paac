use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use authz_core::RelationshipKind;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalIdentity {
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub email: Option<String>,
    pub source: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub attrs: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipEdge {
    pub kind: RelationshipKind,
    pub from: String,
    pub to: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentitySnapshot {
    pub users: Vec<CanonicalIdentity>,
    pub groups: Vec<Group>,
    pub relationships: Vec<RelationshipEdge>,
    pub synced_at: Option<String>,
}
