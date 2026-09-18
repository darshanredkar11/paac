use std::collections::HashMap;
use std::fs;
use std::path::Path;

use async_trait::async_trait;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::error::IdentityError;
use crate::model::{CanonicalIdentity, Group, IdentitySnapshot, RelationshipEdge};
use authz_core::RelationshipKind;
use authz_policy::PolicyStore;

#[async_trait]
pub trait IdentityAdapter: Send + Sync {
    fn name(&self) -> &str;
    async fn sync(&self) -> Result<IdentitySnapshot, IdentityError>;
}

/// Local JSON fixtures for demos and tests.
pub struct LocalFixtureAdapter {
    path: std::path::PathBuf,
}

impl LocalFixtureAdapter {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

#[async_trait]
impl IdentityAdapter for LocalFixtureAdapter {
    fn name(&self) -> &str {
        "local"
    }

    async fn sync(&self) -> Result<IdentitySnapshot, IdentityError> {
        let data = fs::read_to_string(&self.path)?;
        let snap: IdentitySnapshot =
            serde_json::from_str(&data).map_err(|e| IdentityError::Msg(e.to_string()))?;
        Ok(snap)
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
}

/// Normalize JWT/OIDC claims into CanonicalIdentity (verification optional for MVP demos).
pub struct JwtOidcAdapter {
    pub hmac_secret: Option<String>,
}

impl JwtOidcAdapter {
    pub fn normalize_unverified(token: &str) -> Result<CanonicalIdentity, IdentityError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            return Err(IdentityError::Jwt("invalid jwt".into()));
        }
        let payload = base64url_decode(parts[1])?;
        let claims: Claims =
            serde_json::from_slice(&payload).map_err(|e| IdentityError::Jwt(e.to_string()))?;
        Ok(CanonicalIdentity {
            id: claims.sub,
            display_name: claims.name.unwrap_or_default(),
            email: claims.email,
            source: "jwt".into(),
            roles: claims.roles,
            groups: claims.groups,
            attrs: Default::default(),
        })
    }

    pub fn normalize_hs256(
        &self,
        token: &str,
    ) -> Result<CanonicalIdentity, IdentityError> {
        let secret = self
            .hmac_secret
            .as_deref()
            .ok_or_else(|| IdentityError::Jwt("no hmac secret configured".into()))?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map_err(|e| IdentityError::Jwt(e.to_string()))?;
        Ok(CanonicalIdentity {
            id: data.claims.sub,
            display_name: data.claims.name.unwrap_or_default(),
            email: data.claims.email,
            source: "jwt".into(),
            roles: data.claims.roles,
            groups: data.claims.groups,
            attrs: Default::default(),
        })
    }
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, IdentityError> {
    let s = s.replace('-', "+").replace('_', "/");
    let pad = match s.len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    };
    base64_std_decode(&(s + pad))
}

fn base64_std_decode(s: &str) -> Result<Vec<u8>, IdentityError> {
    // minimal decoder without extra dep — use a tiny manual approach via jsonwebtoken's implicit
    // Actually use standard library-ish: include a simple impl with data_encoding style
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut buf = 0u32;
    let mut bits = 0;
    for b in bytes {
        if b == b'=' {
            break;
        }
        let val = T
            .iter()
            .position(|&c| c == b)
            .ok_or_else(|| IdentityError::Jwt("b64".into()))? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: String,
    pub base_dn: String,
    /// When true, use in-memory mock directory instead of network LDAP.
    pub mock: bool,
}

/// In-memory LDAP directory for demos (no network).
#[derive(Debug, Clone, Default)]
pub struct MockLdapDirectory {
    pub users: Vec<CanonicalIdentity>,
    pub groups: Vec<Group>,
    pub relationships: Vec<RelationshipEdge>,
}

impl MockLdapDirectory {
    pub fn demo() -> Self {
        Self {
            users: vec![
                CanonicalIdentity {
                    id: "user:hr-head".into(),
                    display_name: "Alex HR".into(),
                    email: Some("hr@example.com".into()),
                    source: "ldap-mock".into(),
                    roles: vec!["HR_HEAD".into()],
                    groups: vec!["HR".into()],
                    attrs: Default::default(),
                },
                CanonicalIdentity {
                    id: "employee:CEO".into(),
                    display_name: "Casey CEO".into(),
                    email: Some("ceo@example.com".into()),
                    source: "ldap-mock".into(),
                    roles: vec!["CEO".into()],
                    groups: vec!["EXECUTIVE".into()],
                    attrs: Default::default(),
                },
                CanonicalIdentity {
                    id: "employee:alice".into(),
                    display_name: "Alice Engineer".into(),
                    email: Some("alice@example.com".into()),
                    source: "ldap-mock".into(),
                    roles: vec!["ENGINEER".into()],
                    groups: vec!["ENGINEERING".into()],
                    attrs: Default::default(),
                },
            ],
            groups: vec![
                Group {
                    id: "EXECUTIVE".into(),
                    name: "EXECUTIVE".into(),
                    members: vec!["employee:CEO".into()],
                    source: "ldap-mock".into(),
                },
                Group {
                    id: "HR".into(),
                    name: "HR".into(),
                    members: vec!["user:hr-head".into()],
                    source: "ldap-mock".into(),
                },
                Group {
                    id: "ENGINEERING".into(),
                    name: "ENGINEERING".into(),
                    members: vec!["employee:alice".into()],
                    source: "ldap-mock".into(),
                },
                Group {
                    id: "PAYROLL".into(),
                    name: "PAYROLL".into(),
                    members: vec![],
                    source: "ldap-mock".into(),
                },
            ],
            relationships: vec![RelationshipEdge {
                kind: RelationshipKind::DirectReports,
                from: "user:hr-head".into(),
                to: "employee:alice".into(),
                source: "ldap-mock".into(),
            }],
        }
    }
}

pub struct LdapAdapter {
    pub config: LdapConfig,
    pub mock: MockLdapDirectory,
}

impl LdapAdapter {
    pub fn mock_demo() -> Self {
        Self {
            config: LdapConfig {
                url: "ldap://localhost:389".into(),
                bind_dn: "cn=admin,dc=example,dc=com".into(),
                base_dn: "dc=example,dc=com".into(),
                mock: true,
            },
            mock: MockLdapDirectory::demo(),
        }
    }

    /// Generate DRAFT policies from group names. Never auto-deploys.
    pub fn draft_policies_from_groups(snapshot: &IdentitySnapshot) -> String {
        let mut out = String::new();
        out.push_str("# DRAFT policies generated from LDAP group sync\n");
        out.push_str("# Review and commit manually — never auto-deployed.\n\n");
        for g in &snapshot.groups {
            let gid = g.name.to_ascii_uppercase();
            out.push_str(&format!(
                r#"policy "draft_group_{gid}_read_profile"
when role in [{gid}]
allow READ EMPLOYEE_PROFILE
where subject == SELF

"#
            ));
            if gid.contains("EXECUTIVE") || gid == "EXECUTIVE" {
                out.push_str(
                    r#"policy "draft_protect_executive_expenses"
deny READ TRAVEL_EXPENSE
where subject in EXECUTIVE_GROUP
unless role in [CFO, CEO]

"#,
                );
            }
            if gid.contains("PAYROLL") {
                out.push_str(
                    r#"policy "draft_payroll_salary_export"
deny EXPORT SALARY
unless role == PAYROLL_ADMIN

"#,
                );
            }
        }
        out
    }

    pub fn write_drafts_to_store(
        snapshot: &IdentitySnapshot,
        store: &PolicyStore,
    ) -> Result<String, IdentityError> {
        let dsl = Self::draft_policies_from_groups(snapshot);
        store
            .write_draft("ldap-sync", &dsl)
            .map_err(|e| IdentityError::Msg(e.to_string()))?;
        Ok(dsl)
    }
}

#[async_trait]
impl IdentityAdapter for LdapAdapter {
    fn name(&self) -> &str {
        "ldap"
    }

    async fn sync(&self) -> Result<IdentitySnapshot, IdentityError> {
        if !self.config.mock {
            return Err(IdentityError::Msg(
                "live LDAP not configured in MVP; use mock=true or docker-compose demo".into(),
            ));
        }
        Ok(IdentitySnapshot {
            users: self.mock.users.clone(),
            groups: self.mock.groups.clone(),
            relationships: self.mock.relationships.clone(),
            synced_at: Some(chrono::Utc::now().to_rfc3339()),
        })
    }
}

pub fn group_members_map(snapshot: &IdentitySnapshot) -> HashMap<String, Vec<String>> {
    let mut m = HashMap::new();
    for g in &snapshot.groups {
        m.insert(g.id.clone(), g.members.clone());
    }
    m
}

pub fn save_snapshot(path: impl AsRef<Path>, snap: &IdentitySnapshot) -> Result<(), IdentityError> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        path,
        serde_json::to_string_pretty(snap).map_err(|e| IdentityError::Msg(e.to_string()))?,
    )?;
    Ok(())
}
