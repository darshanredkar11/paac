//! Minimal visual policy board: role × resource matrix helpers + embedded HTML.

use authz_policy::DslPolicy;
use serde::Serialize;

pub const BOARD_HTML: &str = include_str!("../static/index.html");

#[derive(Debug, Serialize)]
pub struct MatrixCell {
    pub role: String,
    pub resource: String,
    pub policies: Vec<String>,
    pub effect_summary: String,
}

#[derive(Debug, Serialize)]
pub struct PolicyMatrix {
    pub roles: Vec<String>,
    pub resources: Vec<String>,
    pub cells: Vec<MatrixCell>,
}

pub fn build_matrix(policies: &[DslPolicy]) -> PolicyMatrix {
    let mut roles = Vec::new();
    let mut resources = Vec::new();
    for p in policies {
        for r in &p.when_roles {
            if !roles.contains(r) {
                roles.push(r.clone());
            }
        }
        for r in &p.unless_roles {
            if !roles.contains(r) {
                roles.push(r.clone());
            }
        }
        if !resources.contains(&p.resource) {
            resources.push(p.resource.clone());
        }
    }
    if roles.is_empty() {
        roles.push("*".into());
    }
    let mut cells = Vec::new();
    for role in &roles {
        for resource in &resources {
            let matched: Vec<&DslPolicy> = policies
                .iter()
                .filter(|p| {
                    p.resource == *resource
                        && (p.when_roles.is_empty()
                            || p.when_roles.contains(role)
                            || p.unless_roles.contains(role))
                })
                .collect();
            let effect_summary = if matched.is_empty() {
                "DENY (default)".into()
            } else {
                matched
                    .iter()
                    .map(|p| format!("{:?} {}", p.effect, p.id))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            cells.push(MatrixCell {
                role: role.clone(),
                resource: resource.clone(),
                policies: matched.iter().map(|p| p.id.clone()).collect(),
                effect_summary,
            });
        }
    }
    PolicyMatrix {
        roles,
        resources,
        cells,
    }
}
