//! Native identity-store adapters and draft policy generators.
//! Humans always commit / sign / deploy — generators never auto-deploy.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::adapters::IdentityAdapter;
use crate::error::IdentityError;
use crate::model::{CanonicalIdentity, Group, IdentitySnapshot};

/// Extension trait: IdP adapters that can also emit draft DSL.
#[async_trait]
pub trait IdpAdapter: IdentityAdapter {
    fn idp_kind(&self) -> &'static str;
    fn draft_policies(&self, snapshot: &IdentitySnapshot) -> String {
        default_drafts_from_groups(self.idp_kind(), snapshot)
    }
}

pub fn default_drafts_from_groups(idp: &str, snapshot: &IdentitySnapshot) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# DRAFT policies from {idp} sync — review, commit, sign, deploy. Never auto-applied.\n\n"
    ));
    for g in &snapshot.groups {
        let gid = g.name.to_ascii_uppercase().replace(' ', "_");
        out.push_str(&format!(
            r#"policy "draft_{idp}_{gid}_self_profile"
when role in [{gid}]
allow READ EMPLOYEE_PROFILE
where subject == SELF

"#
        ));
        if gid.contains("EXEC") || gid.contains("FINANCE") {
            out.push_str(&format!(
                r#"policy "draft_{idp}_{gid}_protect_exec_expense"
deny READ TRAVEL_EXPENSE
where subject in EXECUTIVE_GROUP
unless role in [CFO, CEO]

"#
            ));
        }
        if gid.contains("PAYROLL") {
            out.push_str(
                r#"policy "draft_payroll_export"
deny EXPORT SALARY
unless role == PAYROLL_ADMIN

"#,
            );
        }
    }
    out
}

/// Active Directory (LDAP-shaped) — uses same wire protocol as LDAP with AD conventions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveDirectoryConfig {
    pub url: String,
    pub bind_dn: String,
    #[serde(default)]
    pub bind_password: String,
    pub base_dn: String,
    #[serde(default = "default_true")]
    pub mock: bool,
}

fn default_true() -> bool {
    true
}

pub struct ActiveDirectoryAdapter {
    pub config: ActiveDirectoryConfig,
}

#[async_trait]
impl IdentityAdapter for ActiveDirectoryAdapter {
    fn name(&self) -> &str {
        "active_directory"
    }

    async fn sync(&self) -> Result<IdentitySnapshot, IdentityError> {
        if self.config.mock {
            return Ok(mock_directory_snapshot("active_directory"));
        }
        // Live AD uses LDAP bind+search (same as LdapAdapter live path).
        let ldap = crate::adapters::LdapAdapter::from_config(crate::adapters::LdapConfig {
            url: self.config.url.clone(),
            bind_dn: self.config.bind_dn.clone(),
            bind_password: self.config.bind_password.clone(),
            base_dn: self.config.base_dn.clone(),
            mock: false,
            user_filter: "(objectClass=user)".into(),
            group_filter: "(objectClass=group)".into(),
        });
        ldap.sync().await
    }
}

#[async_trait]
impl IdpAdapter for ActiveDirectoryAdapter {
    fn idp_kind(&self) -> &'static str {
        "ad"
    }
}

/// Microsoft Entra ID (Azure AD) via Microsoft Graph (HTTP; mockable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraConfig {
    pub tenant_id: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default = "default_graph")]
    pub graph_base: String,
    #[serde(default = "default_true")]
    pub mock: bool,
}

fn default_graph() -> String {
    "https://graph.microsoft.com/v1.0".into()
}

pub struct EntraIdAdapter {
    pub config: EntraConfig,
    /// Optional override for tests (pre-fetched JSON).
    pub mock_users: Option<Value>,
    pub mock_groups: Option<Value>,
}

#[async_trait]
impl IdentityAdapter for EntraIdAdapter {
    fn name(&self) -> &str {
        "entra_id"
    }

    async fn sync(&self) -> Result<IdentitySnapshot, IdentityError> {
        if self.config.mock {
            if let (Some(u), Some(g)) = (&self.mock_users, &self.mock_groups) {
                return parse_graph_snapshot(u, g);
            }
            return Ok(mock_directory_snapshot("entra_id"));
        }
        let token = self.fetch_token().await?;
        let client = reqwest::Client::new();
        let users: Value = client
            .get(format!("{}/users?$select=id,displayName,mail,userPrincipalName", self.config.graph_base))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| IdentityError::Msg(e.to_string()))?
            .json()
            .await
            .map_err(|e| IdentityError::Msg(e.to_string()))?;
        let groups: Value = client
            .get(format!("{}/groups?$select=id,displayName", self.config.graph_base))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| IdentityError::Msg(e.to_string()))?
            .json()
            .await
            .map_err(|e| IdentityError::Msg(e.to_string()))?;
        parse_graph_snapshot(&users, &groups)
    }
}

impl EntraIdAdapter {
    async fn fetch_token(&self) -> Result<String, IdentityError> {
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id
        );
        let client = reqwest::Client::new();
        let resp: Value = client
            .post(url)
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret.as_str()),
                ("scope", "https://graph.microsoft.com/.default"),
                ("grant_type", "client_credentials"),
            ])
            .send()
            .await
            .map_err(|e| IdentityError::Msg(e.to_string()))?
            .json()
            .await
            .map_err(|e| IdentityError::Msg(e.to_string()))?;
        resp.get("access_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| IdentityError::Msg("entra token missing access_token".into()))
    }
}

#[async_trait]
impl IdpAdapter for EntraIdAdapter {
    fn idp_kind(&self) -> &'static str {
        "entra"
    }
}

fn parse_graph_snapshot(users: &Value, groups: &Value) -> Result<IdentitySnapshot, IdentityError> {
    let mut out_users = Vec::new();
    if let Some(arr) = users.get("value").and_then(|v| v.as_array()) {
        for u in arr {
            let id = u
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let name = u
                .get("displayName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let email = u
                .get("mail")
                .or_else(|| u.get("userPrincipalName"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            out_users.push(CanonicalIdentity {
                id: format!("user:{id}"),
                display_name: name,
                email,
                source: "entra_id".into(),
                roles: vec![],
                groups: vec![],
                attrs: Default::default(),
            });
        }
    }
    let mut out_groups = Vec::new();
    if let Some(arr) = groups.get("value").and_then(|v| v.as_array()) {
        for g in arr {
            let id = g.get("id").and_then(|v| v.as_str()).unwrap_or("g");
            let name = g
                .get("displayName")
                .and_then(|v| v.as_str())
                .unwrap_or(id)
                .to_string();
            out_groups.push(Group {
                id: id.to_string(),
                name,
                members: vec![],
                source: "entra_id".into(),
            });
        }
    }
    Ok(IdentitySnapshot {
        users: out_users,
        groups: out_groups,
        relationships: vec![],
        synced_at: Some(chrono::Utc::now().to_rfc3339()),
    })
}

/// Amazon Cognito user-pool sync (HTTP ListUsers / ListGroups; mockable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitoConfig {
    pub region: String,
    pub user_pool_id: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: String,
    #[serde(default = "default_true")]
    pub mock: bool,
    /// Test hook: absolute URL to mock ListUsers JSON.
    #[serde(default)]
    pub mock_endpoint: Option<String>,
}

pub struct CognitoAdapter {
    pub config: CognitoConfig,
    pub mock_payload: Option<Value>,
}

#[async_trait]
impl IdentityAdapter for CognitoAdapter {
    fn name(&self) -> &str {
        "cognito"
    }

    async fn sync(&self) -> Result<IdentitySnapshot, IdentityError> {
        if self.config.mock {
            if let Some(p) = &self.mock_payload {
                return parse_cognito_payload(p);
            }
            return Ok(mock_directory_snapshot("cognito"));
        }
        if let Some(url) = &self.config.mock_endpoint {
            let client = reqwest::Client::new();
            let p: Value = client
                .get(url)
                .send()
                .await
                .map_err(|e| IdentityError::Msg(e.to_string()))?
                .json()
                .await
                .map_err(|e| IdentityError::Msg(e.to_string()))?;
            return parse_cognito_payload(&p);
        }
        Err(IdentityError::Msg(
            "live Cognito requires AWS SigV4 client; set mock=true or mock_endpoint for demos".into(),
        ))
    }
}

#[async_trait]
impl IdpAdapter for CognitoAdapter {
    fn idp_kind(&self) -> &'static str {
        "cognito"
    }
}

fn parse_cognito_payload(p: &Value) -> Result<IdentitySnapshot, IdentityError> {
    let mut users = Vec::new();
    if let Some(arr) = p.get("Users").and_then(|v| v.as_array()) {
        for u in arr {
            let username = u
                .get("Username")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let mut email = None;
            let mut roles = Vec::new();
            if let Some(attrs) = u.get("Attributes").and_then(|v| v.as_array()) {
                for a in attrs {
                    let name = a.get("Name").and_then(|v| v.as_str()).unwrap_or("");
                    let val = a.get("Value").and_then(|v| v.as_str()).unwrap_or("");
                    if name == "email" {
                        email = Some(val.to_string());
                    }
                    if name == "custom:roles" {
                        roles = val.split(',').map(|s| s.trim().to_string()).collect();
                    }
                }
            }
            users.push(CanonicalIdentity {
                id: format!("user:{username}"),
                display_name: username.to_string(),
                email,
                source: "cognito".into(),
                roles,
                groups: vec![],
                attrs: Default::default(),
            });
        }
    }
    let mut groups = Vec::new();
    if let Some(arr) = p.get("Groups").and_then(|v| v.as_array()) {
        for g in arr {
            let name = g
                .get("GroupName")
                .and_then(|v| v.as_str())
                .unwrap_or("group")
                .to_string();
            groups.push(Group {
                id: name.clone(),
                name,
                members: vec![],
                source: "cognito".into(),
            });
        }
    }
    Ok(IdentitySnapshot {
        users,
        groups,
        relationships: vec![],
        synced_at: Some(chrono::Utc::now().to_rfc3339()),
    })
}

fn mock_directory_snapshot(source: &str) -> IdentitySnapshot {
    IdentitySnapshot {
        users: vec![CanonicalIdentity {
            id: "user:hr-head".into(),
            display_name: "Alex HR".into(),
            email: Some("hr@example.com".into()),
            source: source.into(),
            roles: vec!["HR_HEAD".into()],
            groups: vec!["HR".into()],
            attrs: Default::default(),
        }],
        groups: vec![
            Group {
                id: "HR".into(),
                name: "HR".into(),
                members: vec!["user:hr-head".into()],
                source: source.into(),
            },
            Group {
                id: "EXECUTIVE".into(),
                name: "EXECUTIVE".into(),
                members: vec!["employee:CEO".into()],
                source: source.into(),
            },
            Group {
                id: "PAYROLL".into(),
                name: "PAYROLL".into(),
                members: vec![],
                source: source.into(),
            },
        ],
        relationships: vec![],
        synced_at: Some(chrono::Utc::now().to_rfc3339()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn entra_mock_sync_and_drafts() {
        let adapter = EntraIdAdapter {
            config: EntraConfig {
                tenant_id: "t".into(),
                client_id: "c".into(),
                client_secret: "s".into(),
                graph_base: default_graph(),
                mock: true,
            },
            mock_users: Some(serde_json::json!({
                "value": [{"id":"1","displayName":"Alex","mail":"a@x.com"}]
            })),
            mock_groups: Some(serde_json::json!({
                "value": [{"id":"g1","displayName":"Finance Exec"}]
            })),
        };
        let snap = adapter.sync().await.unwrap();
        assert_eq!(snap.users.len(), 1);
        let draft = adapter.draft_policies(&snap);
        assert!(draft.contains("DRAFT"));
        assert!(draft.contains("Finance") || draft.contains("FINANCE") || draft.contains("protect_exec"));
    }

    #[tokio::test]
    async fn cognito_mock_payload() {
        let adapter = CognitoAdapter {
            config: CognitoConfig {
                region: "us-east-1".into(),
                user_pool_id: "pool".into(),
                access_key_id: String::new(),
                secret_access_key: String::new(),
                mock: true,
                mock_endpoint: None,
            },
            mock_payload: Some(serde_json::json!({
                "Users": [{
                    "Username": "alice",
                    "Attributes": [
                        {"Name":"email","Value":"a@x.com"},
                        {"Name":"custom:roles","Value":"ENGINEER"}
                    ]
                }],
                "Groups": [{"GroupName":"ENGINEERING"}]
            })),
        };
        let snap = adapter.sync().await.unwrap();
        assert_eq!(snap.users[0].id, "user:alice");
        assert!(snap.users[0].roles.contains(&"ENGINEER".into()));
    }
}
