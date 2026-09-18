use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
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
#[allow(dead_code)]
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
    #[serde(default)]
    exp: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Jwk {
    #[serde(default)]
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    alg: Option<String>,
}

/// JWT / OIDC normalizer with HMAC and optional JWKS (RS256).
pub struct JwtOidcAdapter {
    pub hmac_secret: Option<String>,
    pub jwks_url: Option<String>,
    pub require_exp: bool,
}

impl Default for JwtOidcAdapter {
    fn default() -> Self {
        Self {
            hmac_secret: None,
            jwks_url: None,
            require_exp: false,
        }
    }
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
        Ok(claims_to_identity(claims, "jwt-unverified"))
    }

    pub fn normalize_hs256(&self, token: &str) -> Result<CanonicalIdentity, IdentityError> {
        let secret = self
            .hmac_secret
            .as_deref()
            .ok_or_else(|| IdentityError::Jwt("no hmac secret configured".into()))?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = self.require_exp;
        if !self.require_exp {
            validation.required_spec_claims.clear();
        }
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map_err(|e| IdentityError::Jwt(e.to_string()))?;
        Ok(claims_to_identity(data.claims, "jwt-hs256"))
    }

    pub async fn normalize(&self, token: &str) -> Result<CanonicalIdentity, IdentityError> {
        let header = decode_header(token).map_err(|e| IdentityError::Jwt(e.to_string()))?;
        match header.alg {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => self.normalize_hs256(token),
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                self.normalize_rs_jwks(token, header.kid.as_deref(), header.alg)
                    .await
            }
            other => Err(IdentityError::Jwt(format!("unsupported alg {other:?}"))),
        }
    }

    async fn normalize_rs_jwks(
        &self,
        token: &str,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<CanonicalIdentity, IdentityError> {
        let url = self
            .jwks_url
            .as_deref()
            .ok_or_else(|| IdentityError::Jwt("jwks_url not configured for RS JWT".into()))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| IdentityError::Jwt(e.to_string()))?;
        let jwks: Jwks = client
            .get(url)
            .send()
            .await
            .map_err(|e| IdentityError::Jwt(e.to_string()))?
            .json()
            .await
            .map_err(|e| IdentityError::Jwt(e.to_string()))?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| kid.map(|id| k.kid.as_deref() == Some(id)).unwrap_or(true) && k.kty == "RSA")
            .ok_or_else(|| IdentityError::Jwt("no matching JWK".into()))?;
        let n = jwk
            .n
            .as_deref()
            .ok_or_else(|| IdentityError::Jwt("jwk missing n".into()))?;
        let e = jwk
            .e
            .as_deref()
            .ok_or_else(|| IdentityError::Jwt("jwk missing e".into()))?;
        let key = DecodingKey::from_rsa_components(n, e)
            .map_err(|e| IdentityError::Jwt(e.to_string()))?;
        let mut validation = Validation::new(alg);
        validation.validate_exp = self.require_exp;
        if !self.require_exp {
            validation.required_spec_claims.clear();
        }
        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| IdentityError::Jwt(e.to_string()))?;
        Ok(claims_to_identity(data.claims, "jwt-jwks"))
    }
}

fn claims_to_identity(claims: Claims, source: &str) -> CanonicalIdentity {
    CanonicalIdentity {
        id: claims.sub,
        display_name: claims.name.unwrap_or_default(),
        email: claims.email,
        source: source.into(),
        roles: claims.roles,
        groups: claims.groups,
        attrs: Default::default(),
    }
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, IdentityError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .or_else(|_| {
            let padded = match s.len() % 4 {
                2 => format!("{s}=="),
                3 => format!("{s}="),
                _ => s.to_string(),
            };
            base64::engine::general_purpose::URL_SAFE.decode(padded.as_bytes())
        })
        .map_err(|e| IdentityError::Jwt(e.to_string()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: String,
    #[serde(default)]
    pub bind_password: String,
    pub base_dn: String,
    /// When true, use in-memory mock directory instead of network LDAP.
    pub mock: bool,
    #[serde(default = "default_user_filter")]
    pub user_filter: String,
    #[serde(default = "default_group_filter")]
    pub group_filter: String,
}

fn default_user_filter() -> String {
    "(objectClass=inetOrgPerson)".into()
}
fn default_group_filter() -> String {
    "(objectClass=groupOfNames)".into()
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
                CanonicalIdentity {
                    id: "user:finance".into(),
                    display_name: "Finn Finance".into(),
                    email: Some("finance@example.com".into()),
                    source: "ldap-mock".into(),
                    roles: vec!["FINANCE_ANALYST".into()],
                    groups: vec!["FINANCE".into()],
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
                    id: "FINANCE".into(),
                    name: "FINANCE".into(),
                    members: vec!["user:finance".into()],
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
                bind_password: "admin".into(),
                base_dn: "dc=example,dc=com".into(),
                mock: true,
                user_filter: default_user_filter(),
                group_filter: default_group_filter(),
            },
            mock: MockLdapDirectory::demo(),
        }
    }

    pub fn from_config(config: LdapConfig) -> Self {
        Self {
            mock: MockLdapDirectory::demo(),
            config,
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

    async fn sync_live(&self) -> Result<IdentitySnapshot, IdentityError> {
        use ldap3::{LdapConnAsync, Scope, SearchEntry};

        let (conn, mut ldap) = LdapConnAsync::new(&self.config.url)
            .await
            .map_err(|e| IdentityError::Msg(format!("ldap connect: {e}")))?;
        ldap3::drive!(conn);

        ldap.simple_bind(&self.config.bind_dn, &self.config.bind_password)
            .await
            .map_err(|e| IdentityError::Msg(format!("ldap bind: {e}")))?
            .success()
            .map_err(|e| IdentityError::Msg(format!("ldap bind failed: {e}")))?;

        let (rs, _res) = ldap
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &self.config.user_filter,
                vec!["uid", "cn", "mail", "employeeType", "memberOf"],
            )
            .await
            .map_err(|e| IdentityError::Msg(format!("ldap user search: {e}")))?
            .success()
            .map_err(|e| IdentityError::Msg(format!("ldap user search failed: {e}")))?;

        let mut users = Vec::new();
        for entry in rs {
            let entry = SearchEntry::construct(entry);
            let uid = entry
                .attrs
                .get("uid")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| entry.dn.clone());
            let cn = entry
                .attrs
                .get("cn")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let mail = entry.attrs.get("mail").and_then(|v| v.first()).cloned();
            let roles = entry
                .attrs
                .get("employeeType")
                .cloned()
                .unwrap_or_default();
            let groups = entry
                .attrs
                .get("memberOf")
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|dn| dn.split(',').next().unwrap_or(&dn).trim_start_matches("cn=").to_string())
                .collect();
            users.push(CanonicalIdentity {
                id: format!("user:{uid}"),
                display_name: cn,
                email: mail,
                source: "ldap".into(),
                roles,
                groups,
                attrs: Default::default(),
            });
        }

        let (grs, _) = ldap
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &self.config.group_filter,
                vec!["cn", "member"],
            )
            .await
            .map_err(|e| IdentityError::Msg(format!("ldap group search: {e}")))?
            .success()
            .map_err(|e| IdentityError::Msg(format!("ldap group search failed: {e}")))?;

        let mut groups = Vec::new();
        for entry in grs {
            let entry = SearchEntry::construct(entry);
            let cn = entry
                .attrs
                .get("cn")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| entry.dn.clone());
            let members = entry
                .attrs
                .get("member")
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|dn| {
                    let uid = dn
                        .split(',')
                        .next()
                        .unwrap_or(&dn)
                        .trim_start_matches("uid=")
                        .trim_start_matches("cn=");
                    format!("user:{uid}")
                })
                .collect();
            groups.push(Group {
                id: cn.clone(),
                name: cn,
                members,
                source: "ldap".into(),
            });
        }

        let _ = ldap.unbind().await;
        Ok(IdentitySnapshot {
            users,
            groups,
            relationships: vec![],
            synced_at: Some(chrono::Utc::now().to_rfc3339()),
        })
    }
}

#[async_trait]
impl IdentityAdapter for LdapAdapter {
    fn name(&self) -> &str {
        "ldap"
    }

    async fn sync(&self) -> Result<IdentitySnapshot, IdentityError> {
        if self.config.mock {
            return Ok(IdentitySnapshot {
                users: self.mock.users.clone(),
                groups: self.mock.groups.clone(),
                relationships: self.mock.relationships.clone(),
                synced_at: Some(chrono::Utc::now().to_rfc3339()),
            });
        }
        self.sync_live().await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_ldap_sync() {
        let adapter = LdapAdapter::mock_demo();
        let snap = adapter.sync().await.unwrap();
        assert!(snap.users.len() >= 3);
        assert!(snap.groups.iter().any(|g| g.id == "EXECUTIVE"));
    }

    #[test]
    fn jwt_hs256_roundtrip() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let secret = "test-secret-paac";
        let claims = serde_json::json!({
            "sub": "user:hr-head",
            "name": "Alex",
            "roles": ["HR_HEAD"],
            "groups": ["HR"]
        });
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();
        let adapter = JwtOidcAdapter {
            hmac_secret: Some(secret.into()),
            jwks_url: None,
            require_exp: false,
        };
        let id = adapter.normalize_hs256(&token).unwrap();
        assert_eq!(id.id, "user:hr-head");
        assert!(id.roles.contains(&"HR_HEAD".into()));
    }
}
