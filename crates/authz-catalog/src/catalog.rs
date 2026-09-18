use std::fs;
use std::path::Path;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use authz_core::{Action, AuthzRequest, ContextMap, Principal, Resource};
use crate::error::CatalogError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogResource {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub sensitivity: Option<String>,
    #[serde(default)]
    pub attrs: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolMapping {
    pub tool_name: String,
    pub action: String,
    pub resource_kind: String,
    #[serde(default)]
    pub resource_id_arg: Option<String>,
    #[serde(default)]
    pub default_attrs: IndexMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ResourceCatalog {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub resources: Vec<CatalogResource>,
    #[serde(default)]
    pub tools: Vec<ToolMapping>,
}

impl ResourceCatalog {
    pub fn find_resource(&self, id_or_kind: &str) -> Option<&CatalogResource> {
        self.resources.iter().find(|r| r.id == id_or_kind || r.kind == id_or_kind)
    }

    pub fn find_tool(&self, name: &str) -> Option<&ToolMapping> {
        self.tools.iter().find(|t| t.tool_name == name)
    }

    /// Build an AuthzRequest for a tool invocation from catalog mapping.
    pub fn authz_for_tool(
        &self,
        principal: Principal,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> AuthzRequest {
        if let Some(m) = self.find_tool(tool_name) {
            let mut attrs = m.default_attrs.clone();
            let resource_id = m
                .resource_id_arg
                .as_ref()
                .and_then(|k| args.get(k))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if let Some(id) = &resource_id {
                if let Some(res) = self.find_resource(id) {
                    if let Some(d) = &res.department {
                        attrs.insert("department".into(), d.clone());
                    }
                    if let Some(s) = &res.sensitivity {
                        attrs.insert("sensitivity".into(), s.clone());
                    }
                    for (k, v) in &res.attrs {
                        attrs.insert(k.clone(), v.clone());
                    }
                }
            }
            // Also copy string args into context for policy.
            let mut ctx = IndexMap::new();
            ctx.insert("tool_name".into(), tool_name.to_string());
            if let Some(obj) = args.as_object() {
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        ctx.insert(format!("arg_{k}"), s.to_string());
                    }
                }
            }
            return AuthzRequest {
                principal,
                action: Action::new(&m.action),
                resource: Resource {
                    kind: m.resource_kind.clone(),
                    id: resource_id,
                    attrs,
                },
                subject: None,
                context: ContextMap { values: ctx },
                relationships: vec![],
                acting_as: Some("agent:paac-proxy".into()),
                on_behalf_of: None,
            };
        }
        // Unknown tool → deny-by-default resource TOOL_UNKNOWN
        let mut ctx = IndexMap::new();
        ctx.insert("tool_name".into(), tool_name.to_string());
        AuthzRequest {
            principal,
            action: Action::new("TOOL_INVOKE"),
            resource: Resource {
                kind: "TOOL_UNKNOWN".into(),
                id: Some(tool_name.to_string()),
                attrs: IndexMap::new(),
            },
            subject: None,
            context: ContextMap { values: ctx },
            relationships: vec![],
            acting_as: Some("agent:paac-proxy".into()),
            on_behalf_of: None,
        }
    }

    pub fn authz_for_retrieve(
        &self,
        principal: Principal,
        collection: &str,
        document_id: Option<&str>,
    ) -> AuthzRequest {
        let mut attrs = IndexMap::new();
        let kind = if let Some(res) = self.find_resource(collection) {
            if let Some(d) = &res.department {
                attrs.insert("department".into(), d.clone());
            }
            if let Some(s) = &res.sensitivity {
                attrs.insert("sensitivity".into(), s.clone());
            }
            for (k, v) in &res.attrs {
                attrs.insert(k.clone(), v.clone());
            }
            res.kind.clone()
        } else {
            "VECTOR_COLLECTION".into()
        };
        let mut ctx = IndexMap::new();
        ctx.insert("collection".into(), collection.to_string());
        AuthzRequest {
            principal,
            action: Action::new("READ"),
            resource: Resource {
                kind,
                id: document_id.map(|s| s.to_string()).or_else(|| Some(collection.to_string())),
                attrs,
            },
            subject: None,
            context: ContextMap { values: ctx },
            relationships: vec![],
            acting_as: Some("agent:paac-proxy".into()),
            on_behalf_of: None,
        }
    }
}

pub fn load_catalog(path: impl AsRef<Path>) -> Result<ResourceCatalog, CatalogError> {
    let data = fs::read_to_string(path.as_ref())?;
    let path_str = path.as_ref().to_string_lossy();
    if path_str.ends_with(".json") {
        serde_json::from_str(&data).map_err(|e| CatalogError::Parse(e.to_string()))
    } else {
        serde_yaml::from_str(&data).map_err(|e| CatalogError::Parse(e.to_string()))
    }
}

pub fn validate_catalog(catalog: &ResourceCatalog) -> Result<(), CatalogError> {
    if catalog.resources.is_empty() && catalog.tools.is_empty() {
        return Err(CatalogError::Validate(
            "catalog has no resources or tools".into(),
        ));
    }
    let mut ids = std::collections::HashSet::new();
    for r in &catalog.resources {
        if r.id.trim().is_empty() || r.kind.trim().is_empty() {
            return Err(CatalogError::Validate(
                "resource id and kind are required".into(),
            ));
        }
        if !ids.insert(r.id.clone()) {
            return Err(CatalogError::Validate(format!("duplicate resource id {}", r.id)));
        }
    }
    for t in &catalog.tools {
        if t.tool_name.trim().is_empty() || t.resource_kind.trim().is_empty() {
            return Err(CatalogError::Validate(
                "tool_name and resource_kind are required".into(),
            ));
        }
        if t.action.trim().is_empty() {
            return Err(CatalogError::Validate("tool action is required".into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_maps_to_resource() {
        let cat = ResourceCatalog {
            version: "1".into(),
            resources: vec![CatalogResource {
                id: "db.hr.employees".into(),
                kind: "DB_TABLE".into(),
                name: "employees".into(),
                department: Some("HR".into()),
                sensitivity: Some("PII".into()),
                attrs: IndexMap::new(),
            }],
            tools: vec![ToolMapping {
                tool_name: "sql_query".into(),
                action: "TOOL_INVOKE".into(),
                resource_kind: "DB_TABLE".into(),
                resource_id_arg: Some("table".into()),
                default_attrs: IndexMap::new(),
            }],
        };
        validate_catalog(&cat).unwrap();
        let req = cat.authz_for_tool(
            Principal::with_roles("user:hr-head", vec!["HR_HEAD".into()]),
            "sql_query",
            &serde_json::json!({"table": "db.hr.employees", "sql": "select 1"}),
        );
        assert_eq!(req.action.name, "TOOL_INVOKE");
        assert_eq!(req.resource.kind, "DB_TABLE");
        assert_eq!(req.resource.id.as_deref(), Some("db.hr.employees"));
        assert_eq!(
            req.resource.attrs.get("sensitivity").map(|s| s.as_str()),
            Some("PII")
        );
    }
}
