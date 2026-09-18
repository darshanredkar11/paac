use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};

use crate::error::AuthzError;
use crate::request::{AuthzRequest, RelationshipKind};

pub struct EntityBuildInput<'a> {
    pub request: &'a AuthzRequest,
    /// Extra group memberships: group_id -> member entity ids
    pub group_members: &'a HashMap<String, Vec<String>>,
}

fn uid(type_name: &str, id: &str) -> Result<EntityUid, AuthzError> {
    let tn = EntityTypeName::from_str(type_name)
        .map_err(|e| AuthzError::Entity(format!("type {type_name}: {e}")))?;
    let eid = EntityId::from_str(id).map_err(|e| AuthzError::Entity(format!("id {id}: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(tn, eid))
}

fn str_attr(v: &str) -> RestrictedExpression {
    RestrictedExpression::from_str(&format!("\"{}\"", v.replace('\"', "\\\"")))
        .expect("string attr")
}

fn set_attr(vals: &[String]) -> RestrictedExpression {
    let inner = vals
        .iter()
        .map(|v| format!("\"{}\"", v.replace('\"', "\\\"")))
        .collect::<Vec<_>>()
        .join(", ");
    RestrictedExpression::from_str(&format!("[{inner}]")).expect("set attr")
}

/// Build Cedar entities from a canonical request + relationship graph.
pub fn build_entities(input: EntityBuildInput<'_>) -> Result<HashSet<Entity>, AuthzError> {
    let req = input.request;
    let mut entities = HashSet::new();
    let mut parents: HashMap<String, HashSet<EntityUid>> = HashMap::new();

    // Collect manager / direct_report edges
    let mut manager_of: HashMap<String, Vec<String>> = HashMap::new();
    let mut direct_reports: HashMap<String, Vec<String>> = HashMap::new();
    let mut group_links: HashMap<String, Vec<String>> = HashMap::new();

    for rel in &req.relationships {
        match rel.kind {
            RelationshipKind::ManagerOf => {
                manager_of
                    .entry(rel.from.clone())
                    .or_default()
                    .push(rel.to.clone());
            }
            RelationshipKind::DirectReports => {
                direct_reports
                    .entry(rel.from.clone())
                    .or_default()
                    .push(rel.to.clone());
            }
            RelationshipKind::GroupMember => {
                group_links
                    .entry(rel.to.clone())
                    .or_default()
                    .push(rel.from.clone());
                parents
                    .entry(rel.from.clone())
                    .or_default()
                    .insert(uid("Group", &rel.to)?);
            }
            RelationshipKind::Delegation => {
                // modeled as attribute on principal later
            }
        }
    }

    for (group, members) in input.group_members {
        for m in members {
            parents
                .entry(m.clone())
                .or_default()
                .insert(uid("Group", group)?);
            group_links
                .entry(group.clone())
                .or_default()
                .push(m.clone());
        }
    }

    // Principal user entity
    {
        let mut attrs = HashMap::new();
        attrs.insert("roles".to_string(), set_attr(&req.principal.roles));
        attrs.insert("groups".to_string(), set_attr(&req.principal.groups));
        for (k, v) in &req.principal.attrs {
            attrs.insert(k.clone(), str_attr(v));
        }
        if let Some(reports) = direct_reports.get(&req.principal.id) {
            attrs.insert("direct_reports".to_string(), set_attr(reports));
        } else {
            attrs.insert("direct_reports".to_string(), set_attr(&[]));
        }
        if let Some(managed) = manager_of.get(&req.principal.id) {
            attrs.insert("manages".to_string(), set_attr(managed));
        }
        if let Some(obo) = &req.on_behalf_of {
            attrs.insert("on_behalf_of".to_string(), str_attr(obo));
        }
        if let Some(acting) = &req.acting_as {
            attrs.insert("acting_as".to_string(), str_attr(acting));
        }
        let p_uid = uid("User", &req.principal.id)?;
        let parent_set = parents
            .get(&req.principal.id)
            .cloned()
            .unwrap_or_default();
        // Also add groups from principal.groups as parents
        let mut all_parents = parent_set;
        for g in &req.principal.groups {
            all_parents.insert(uid("Group", g)?);
        }
        entities.insert(
            Entity::new(p_uid, attrs, all_parents)
                .map_err(|e| AuthzError::Entity(e.to_string()))?,
        );
    }

    // Subject employee entity
    if let Some(subj) = &req.subject {
        let mut attrs = HashMap::new();
        attrs.insert("groups".to_string(), set_attr(&subj.groups));
        for (k, v) in &subj.attrs {
            attrs.insert(k.clone(), str_attr(v));
        }
        let kind = if subj.kind.is_empty() {
            "Employee"
        } else {
            &subj.kind
        };
        // Normalize User/Employee to Employee for subject
        let type_name = if kind.eq_ignore_ascii_case("user") {
            "Employee"
        } else {
            kind
        };
        let s_uid = uid(type_name, &subj.id)?;
        let mut all_parents = parents.get(&subj.id).cloned().unwrap_or_default();
        for g in &subj.groups {
            all_parents.insert(uid("Group", g)?);
        }
        entities.insert(
            Entity::new(s_uid, attrs, all_parents)
                .map_err(|e| AuthzError::Entity(e.to_string()))?,
        );
    }

    // Resource entity
    {
        let mut attrs = HashMap::new();
        attrs.insert("kind".to_string(), str_attr(&req.resource.kind));
        for (k, v) in &req.resource.attrs {
            attrs.insert(k.clone(), str_attr(v));
        }
        let rid = req
            .resource
            .id
            .clone()
            .unwrap_or_else(|| req.resource.kind.clone());
        let r_uid = uid("Resource", &rid)?;
        entities.insert(
            Entity::new(r_uid, attrs, HashSet::new())
                .map_err(|e| AuthzError::Entity(e.to_string()))?,
        );
    }

    // Group entities
    let mut all_groups: HashSet<String> = HashSet::new();
    for g in &req.principal.groups {
        all_groups.insert(g.clone());
    }
    if let Some(s) = &req.subject {
        for g in &s.groups {
            all_groups.insert(g.clone());
        }
    }
    for g in group_links.keys() {
        all_groups.insert(g.clone());
    }
    for g in input.group_members.keys() {
        all_groups.insert(g.clone());
    }
    for g in all_groups {
        let g_uid = uid("Group", &g)?;
        entities.insert(
            Entity::new(g_uid, HashMap::new(), HashSet::new())
                .map_err(|e| AuthzError::Entity(e.to_string()))?,
        );
    }

    // Action entity (Cedar also needs Action entities sometimes; for schema-less we use Action type)
    {
        let a_uid = uid("Action", &req.action.name.to_ascii_uppercase())?;
        entities.insert(
            Entity::new(a_uid, HashMap::new(), HashSet::new())
                .map_err(|e| AuthzError::Entity(e.to_string()))?,
        );
    }

    Ok(entities)
}
