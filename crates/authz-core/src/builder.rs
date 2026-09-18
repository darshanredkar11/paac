//! Validated AuthzRequest builders — preferred embeddable API.

use indexmap::IndexMap;

use crate::ids::{ActionName, AgentId, PrincipalId, ResourceId, ResourceKind};
use crate::request::{
    Action, AuthzRequest, ContextMap, Principal, Relationship, Resource, Subject,
};
use crate::AuthzError;

#[derive(Debug, Default)]
pub struct AuthzRequestBuilder {
    principal: Option<Principal>,
    action: Option<Action>,
    resource: Option<Resource>,
    subject: Option<Subject>,
    context: ContextMap,
    relationships: Vec<Relationship>,
    acting_as: Option<String>,
    on_behalf_of: Option<String>,
    delegation_chain: Vec<String>,
}

impl AuthzRequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn principal(mut self, id: impl Into<String>, roles: Vec<String>) -> Result<Self, AuthzError> {
        let id = PrincipalId::new(id)?;
        self.principal = Some(Principal::with_roles(id.into_inner(), roles));
        Ok(self)
    }

    pub fn principal_obj(mut self, p: Principal) -> Result<Self, AuthzError> {
        let _ = PrincipalId::new(&p.id)?;
        self.principal = Some(p);
        Ok(self)
    }

    pub fn agent_principal(
        mut self,
        agent_id: impl Into<String>,
        roles: Vec<String>,
        on_behalf_of: impl Into<String>,
    ) -> Result<Self, AuthzError> {
        let agent = AgentId::new(agent_id)?;
        let human = PrincipalId::new(on_behalf_of)?;
        self.principal = Some(Principal::with_roles(agent.as_str(), roles));
        self.acting_as = Some(agent.into_inner());
        self.on_behalf_of = Some(human.as_str().to_string());
        Ok(self)
    }

    pub fn action(mut self, name: impl Into<String>) -> Result<Self, AuthzError> {
        let a = ActionName::new(name)?;
        self.action = Some(Action::new(a.into_inner()));
        Ok(self)
    }

    pub fn resource_kind(mut self, kind: impl Into<String>) -> Result<Self, AuthzError> {
        let k = ResourceKind::new(kind)?;
        self.resource = Some(Resource::kind(k.into_inner()));
        Ok(self)
    }

    pub fn resource(
        mut self,
        kind: impl Into<String>,
        id: Option<String>,
        attrs: IndexMap<String, String>,
    ) -> Result<Self, AuthzError> {
        let k = ResourceKind::new(kind)?;
        let id = match id {
            Some(i) => Some(ResourceId::new(i)?.into_inner()),
            None => None,
        };
        self.resource = Some(Resource {
            kind: k.into_inner(),
            id,
            attrs,
        });
        Ok(self)
    }

    pub fn subject(mut self, id: impl Into<String>, groups: Vec<String>) -> Result<Self, AuthzError> {
        let id = PrincipalId::new(id)?;
        self.subject = Some(Subject {
            id: id.into_inner(),
            kind: "Employee".into(),
            groups,
            attrs: IndexMap::new(),
        });
        Ok(self)
    }

    pub fn context_kv(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.context.values.insert(k.into(), v.into());
        self
    }

    pub fn relationship(mut self, rel: Relationship) -> Self {
        self.relationships.push(rel);
        self
    }

    pub fn delegation_hop(mut self, principal_id: impl Into<String>) -> Result<Self, AuthzError> {
        let id = PrincipalId::new(principal_id)?;
        self.delegation_chain.push(id.into_inner());
        Ok(self)
    }

    pub fn build(self) -> Result<AuthzRequest, AuthzError> {
        let mut req = AuthzRequest {
            principal: self
                .principal
                .ok_or_else(|| AuthzError::InvalidRequest("principal required".into()))?,
            action: self
                .action
                .ok_or_else(|| AuthzError::InvalidRequest("action required".into()))?,
            resource: self
                .resource
                .ok_or_else(|| AuthzError::InvalidRequest("resource required".into()))?,
            subject: self.subject,
            context: self.context,
            relationships: self.relationships,
            acting_as: self.acting_as,
            on_behalf_of: self.on_behalf_of,
        };
        if !self.delegation_chain.is_empty() {
            req.context
                .values
                .insert("delegation_chain".into(), self.delegation_chain.join(">"));
            req.context.values.insert(
                "delegation_depth".into(),
                self.delegation_chain.len().to_string(),
            );
        }
        req.validate()?;
        Ok(req)
    }
}
