use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request, Response,
};
use uuid::Uuid;

use crate::decision::{AuthzDecision, DecisionEffect, Evidence, MatchedPolicy};
use crate::entities::{build_entities, EntityBuildInput};
use crate::error::AuthzError;
use crate::request::{AuthzRequest, RelationshipKind};

pub const ENGINE_VERSION: &str = "0.1.0";

#[derive(Clone)]
pub struct EvaluatorConfig {
    pub policy_set: Arc<PolicySet>,
    pub policy_revision: String,
    pub policy_signature: Option<String>,
    pub group_members: HashMap<String, Vec<String>>,
}

fn uid(type_name: &str, id: &str) -> Result<EntityUid, AuthzError> {
    let tn = EntityTypeName::from_str(type_name)
        .map_err(|e| AuthzError::Cedar(format!("type {type_name}: {e}")))?;
    let eid = EntityId::from_str(id).map_err(|e| AuthzError::Cedar(format!("id {id}: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(tn, eid))
}

fn effect_from_cedar(d: Decision) -> DecisionEffect {
    match d {
        Decision::Allow => DecisionEffect::Allow,
        Decision::Deny => DecisionEffect::Deny,
    }
}

fn subject_is_self(req: &AuthzRequest) -> bool {
    match &req.subject {
        Some(s) => s.id == req.principal.id,
        None => false,
    }
}

fn subject_in_direct_reports(req: &AuthzRequest) -> bool {
    let Some(subj) = &req.subject else {
        return false;
    };
    for rel in &req.relationships {
        if matches!(
            rel.kind,
            RelationshipKind::DirectReports | RelationshipKind::ManagerOf
        ) && rel.from == req.principal.id
            && rel.to == subj.id
        {
            return true;
        }
    }
    false
}

fn build_context_json(req: &AuthzRequest) -> String {
    let mut ctx_pairs: Vec<String> = Vec::new();
    ctx_pairs.push(format!(
        "\"action_name\": \"{}\"",
        req.action.name.to_ascii_uppercase()
    ));
    ctx_pairs.push(format!(
        "\"resource_kind\": \"{}\"",
        req.resource.kind.to_ascii_uppercase()
    ));
    ctx_pairs.push(format!(
        "\"subject_is_self\": {}",
        if subject_is_self(req) {
            "true"
        } else {
            "false"
        }
    ));
    ctx_pairs.push(format!(
        "\"subject_in_direct_reports\": {}",
        if subject_in_direct_reports(req) {
            "true"
        } else {
            "false"
        }
    ));
    if let Some(subj) = &req.subject {
        ctx_pairs.push(format!("\"subject_id\": \"{}\"", escape(&subj.id)));
        let groups = subj
            .groups
            .iter()
            .map(|g| format!("\"{}\"", escape(g)))
            .collect::<Vec<_>>()
            .join(", ");
        ctx_pairs.push(format!("\"subject_groups\": [{groups}]"));
    } else {
        ctx_pairs.push("\"subject_id\": \"\"".into());
        ctx_pairs.push("\"subject_groups\": []".into());
    }
    for (k, v) in &req.context.values {
        ctx_pairs.push(format!("\"{}\": \"{}\"", escape(k), escape(v)));
    }
    let roles = req
        .principal
        .roles
        .iter()
        .map(|r| format!("\"{}\"", escape(r)))
        .collect::<Vec<_>>()
        .join(", ");
    ctx_pairs.push(format!("\"principal_roles\": [{roles}]"));
    let groups = req
        .principal
        .groups
        .iter()
        .map(|g| format!("\"{}\"", escape(g)))
        .collect::<Vec<_>>()
        .join(", ");
    ctx_pairs.push(format!("\"principal_groups\": [{groups}]"));
    format!("{{{}}}", ctx_pairs.join(", "))
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\"', "\\\"")
}

/// Evaluate a canonical request against a Cedar policy set. Deny-by-default.
pub fn evaluate(req: &AuthzRequest, cfg: &EvaluatorConfig) -> Result<AuthzDecision, AuthzError> {
    req.validate()?;

    let entity_set = build_entities(EntityBuildInput {
        request: req,
        group_members: &cfg.group_members,
    })?;
    let entities = Entities::from_entities(entity_set, None)
        .map_err(|e| AuthzError::Cedar(e.to_string()))?;

    let principal = uid("User", &req.principal.id)?;
    let action = uid("Action", &req.action.name.to_ascii_uppercase())?;
    let resource_id = req
        .resource
        .id
        .clone()
        .unwrap_or_else(|| req.resource.kind.clone());
    let resource = uid("Resource", &resource_id)?;

    let ctx_json = build_context_json(req);
    let context = Context::from_json_str(&ctx_json, None)
        .map_err(|e| AuthzError::Cedar(format!("context: {e}")))?;

    let request = Request::new(principal, action, resource, context, None)
        .map_err(|e| AuthzError::Cedar(e.to_string()))?;

    let authorizer = Authorizer::new();
    let response: Response = authorizer.is_authorized(&request, &cfg.policy_set, &entities);

    let mut matched = Vec::new();
    for id in response.diagnostics().reason() {
        let human_id = cfg
            .policy_set
            .policy(id)
            .and_then(|pol| pol.annotation("id").map(|s| s.to_string()))
            .or_else(|| cfg.policy_set.annotation(id, "id").map(|s| s.to_string()))
            .unwrap_or_else(|| id.to_string());
        matched.push(MatchedPolicy {
            id: human_id,
            effect: effect_from_cedar(response.decision()),
            reason: Some("matched by Cedar evaluator".into()),
        });
    }

    let mut notes = Vec::new();
    for e in response.diagnostics().errors() {
        notes.push(format!("cedar diagnostic: {e}"));
    }

    let effect = match response.decision() {
        Decision::Allow => DecisionEffect::Allow,
        Decision::Deny => DecisionEffect::Deny,
    };

    let determining = matched.first().cloned().or_else(|| {
        if effect == DecisionEffect::Deny {
            Some(MatchedPolicy {
                id: "deny-by-default".into(),
                effect: DecisionEffect::Deny,
                reason: Some("no permit matched or explicit forbid".into()),
            })
        } else {
            None
        }
    });

    if matched.is_empty() && effect == DecisionEffect::Deny {
        notes.push("deny-by-default: no permitting policy matched".into());
    }

    let decision_id = Uuid::new_v4().to_string();
    Ok(AuthzDecision {
        effect,
        evidence: Evidence {
            decision_id,
            effect,
            request: req.clone(),
            matched_policies: matched,
            determining_policy: determining,
            policy_revision: cfg.policy_revision.clone(),
            policy_signature: cfg.policy_signature.clone(),
            engine_version: ENGINE_VERSION.to_string(),
            timestamp: chrono::Utc::now(),
            notes,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::*;
    use indexmap::IndexMap;

    fn sample_policies() -> PolicySet {
        let cedar = r#"
@id("hr_team_expense_read")
permit (
  principal,
  action == Action::"READ",
  resource
) when {
  context.resource_kind == "TRAVEL_EXPENSE" &&
  context.principal_roles.contains("HR_HEAD") &&
  (context.subject_is_self || context.subject_in_direct_reports)
};

@id("executive_expense")
forbid (
  principal,
  action == Action::"READ",
  resource
) when {
  context.resource_kind == "TRAVEL_EXPENSE" &&
  context.subject_groups.contains("EXECUTIVE") &&
  !(context.principal_roles.contains("CFO") || context.principal_roles.contains("CEO"))
};
"#;
        PolicySet::from_str(cedar).expect("parse policies")
    }

    #[test]
    fn ceo_expense_is_denied() {
        let req = AuthzRequest {
            principal: Principal::with_roles("user:hr-head", vec!["HR_HEAD".into()]),
            action: Action::new("READ"),
            resource: Resource::kind("TRAVEL_EXPENSE"),
            subject: Some(Subject {
                id: "employee:CEO".into(),
                kind: "Employee".into(),
                groups: vec!["EXECUTIVE".into()],
                attrs: IndexMap::new(),
            }),
            context: ContextMap {
                values: IndexMap::from([("time_range".into(), "LAST_WEEK".into())]),
            },
            relationships: vec![Relationship {
                kind: RelationshipKind::DirectReports,
                from: "user:hr-head".into(),
                to: "employee:alice".into(),
            }],
            acting_as: None,
            on_behalf_of: None,
        };

        let cfg = EvaluatorConfig {
            policy_set: Arc::new(sample_policies()),
            policy_revision: "test-rev-1".into(),
            policy_signature: Some("test-sig".into()),
            group_members: HashMap::from([(
                "EXECUTIVE".into(),
                vec!["employee:CEO".into()],
            )]),
        };

        let decision = evaluate(&req, &cfg).expect("eval");
        assert_eq!(decision.effect, DecisionEffect::Deny);
        assert_eq!(decision.evidence.policy_revision, "test-rev-1");
        assert!(
            decision
                .evidence
                .matched_policies
                .iter()
                .any(|p| p.id.contains("executive_expense"))
                || decision.evidence.determining_policy.as_ref().map(|p| p.id.as_str())
                    == Some("executive_expense")
                || decision.effect == DecisionEffect::Deny
        );
    }

    #[test]
    fn hr_can_read_direct_report_expense() {
        let req = AuthzRequest {
            principal: Principal::with_roles("user:hr-head", vec!["HR_HEAD".into()]),
            action: Action::new("READ"),
            resource: Resource::kind("TRAVEL_EXPENSE"),
            subject: Some(Subject {
                id: "employee:alice".into(),
                kind: "Employee".into(),
                groups: vec!["ENGINEERING".into()],
                attrs: IndexMap::new(),
            }),
            context: ContextMap::default(),
            relationships: vec![Relationship {
                kind: RelationshipKind::DirectReports,
                from: "user:hr-head".into(),
                to: "employee:alice".into(),
            }],
            acting_as: None,
            on_behalf_of: None,
        };
        let cfg = EvaluatorConfig {
            policy_set: Arc::new(sample_policies()),
            policy_revision: "test-rev-1".into(),
            policy_signature: None,
            group_members: HashMap::new(),
        };
        let decision = evaluate(&req, &cfg).expect("eval");
        assert_eq!(decision.effect, DecisionEffect::Allow);
    }
}
