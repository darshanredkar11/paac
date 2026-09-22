use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use cedar_policy::PolicySet;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dsl::{parse_dsl, DslPolicy};
use crate::error::PolicyError;
use crate::sign::{sign_bundle, BundleSigner, SignedBundle};
use crate::translate::{cedar_policy_set_from_dsl, dsl_to_cedar};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPolicy {
    pub id: String,
    pub dsl: String,
    pub status: String, // active | draft
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRevision {
    pub revision: String,
    pub message: String,
    pub created_at: String,
    pub cedar: String,
    pub dsl: String,
    pub bundle: Option<SignedBundle>,
}

pub struct PolicyStore {
    root: PathBuf,
}

impl PolicyStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("drafts"))?;
        fs::create_dir_all(root.join("revisions"))?;
        fs::create_dir_all(root.join("deployed"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn write_active_dsl(&self, dsl: &str) -> Result<(), PolicyError> {
        fs::write(self.root.join("active.dsl"), dsl)?;
        Ok(())
    }

    pub fn read_active_dsl(&self) -> Result<String, PolicyError> {
        let path = self.root.join("active.dsl");
        if !path.exists() {
            return Ok(String::new());
        }
        Ok(fs::read_to_string(path)?)
    }

    pub fn validate_dsl(&self, dsl: &str) -> Result<Vec<DslPolicy>, PolicyError> {
        let policies = parse_dsl(dsl)?;
        let _cedar = dsl_to_cedar(&policies)?;
        let set = cedar_policy_set_from_dsl(&policies)?;
        crate::schema::validate_cedar_policy_set(&set)?;
        if policies.is_empty() {
            return Err(PolicyError::Validate("no policies found".into()));
        }
        Ok(policies)
    }

    pub fn commit(&self, message: &str) -> Result<PolicyRevision, PolicyError> {
        let dsl = self.read_active_dsl()?;
        let policies = self.validate_dsl(&dsl)?;
        let cedar = dsl_to_cedar(&policies)?;
        let mut hasher = Sha256::new();
        hasher.update(cedar.as_bytes());
        hasher.update(message.as_bytes());
        hasher.update(Utc::now().timestamp().to_string().as_bytes());
        let revision = hex::encode(&hasher.finalize()[..8]);
        let rev = PolicyRevision {
            revision: revision.clone(),
            message: message.to_string(),
            created_at: Utc::now().to_rfc3339(),
            cedar: cedar.clone(),
            dsl: dsl.clone(),
            bundle: None,
        };
        let path = self.root.join("revisions").join(format!("{revision}.json"));
        fs::write(&path, serde_json::to_string_pretty(&rev).unwrap())?;
        fs::write(self.root.join("HEAD"), &revision)?;
        Ok(rev)
    }

    pub fn sign_head(&self, signer: &dyn BundleSigner) -> Result<SignedBundle, PolicyError> {
        let rev_id = self.head_revision()?.ok_or_else(|| {
            PolicyError::Store("no HEAD revision; run policy commit first".into())
        })?;
        let mut rev = self.load_revision(&rev_id)?;
        let bundle = sign_bundle(signer, &rev.revision, &rev.cedar, &rev.dsl)?;
        rev.bundle = Some(bundle.clone());
        let path = self.root.join("revisions").join(format!("{rev_id}.json"));
        fs::write(path, serde_json::to_string_pretty(&rev).unwrap())?;
        Ok(bundle)
    }

    pub fn deploy_head(&self) -> Result<PolicyRevision, PolicyError> {
        let rev_id = self.head_revision()?.ok_or_else(|| {
            PolicyError::Store("no HEAD revision".into())
        })?;
        let rev = self.load_revision(&rev_id)?;
        if rev.bundle.is_none() {
            return Err(PolicyError::Store(
                "HEAD is not signed; run policy sign first".into(),
            ));
        }
        fs::write(
            self.root.join("deployed").join("current.json"),
            serde_json::to_string_pretty(&rev).unwrap(),
        )?;
        Ok(rev)
    }

    pub fn head_revision(&self) -> Result<Option<String>, PolicyError> {
        let path = self.root.join("HEAD");
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(fs::read_to_string(path)?.trim().to_string()))
    }

    pub fn load_revision(&self, revision: &str) -> Result<PolicyRevision, PolicyError> {
        let path = self.root.join("revisions").join(format!("{revision}.json"));
        let data = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data).map_err(|e| PolicyError::Store(e.to_string()))?)
    }

    pub fn load_deployed(&self) -> Result<Option<PolicyRevision>, PolicyError> {
        let path = self.root.join("deployed").join("current.json");
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(path)?;
        Ok(Some(
            serde_json::from_str(&data).map_err(|e| PolicyError::Store(e.to_string()))?,
        ))
    }

    pub fn policy_set_from_deployed(&self) -> Result<(Arc<PolicySet>, PolicyRevision), PolicyError> {
        let rev = self
            .load_deployed()?
            .ok_or_else(|| PolicyError::Store("no deployed policy bundle".into()))?;
        let set = PolicySet::from_str(&rev.cedar).map_err(|e| PolicyError::Cedar(e.to_string()))?;
        Ok((Arc::new(set), rev))
    }

    pub fn write_draft(&self, name: &str, dsl: &str) -> Result<PathBuf, PolicyError> {
        let path = self.root.join("drafts").join(format!("{name}.dsl"));
        fs::write(&path, dsl)?;
        Ok(path)
    }

    pub fn list_drafts(&self) -> Result<Vec<String>, PolicyError> {
        let mut out = Vec::new();
        for ent in fs::read_dir(self.root.join("drafts"))? {
            let ent = ent?;
            if ent.path().extension().and_then(|s| s.to_str()) == Some("dsl") {
                out.push(
                    ent.path()
                        .file_stem()
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                );
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn diff_active_vs_revision(&self, revision: &str) -> Result<String, PolicyError> {
        let active = self.read_active_dsl()?;
        let rev = self.load_revision(revision)?;
        Ok(simple_diff(&rev.dsl, &active))
    }
}

fn simple_diff(old: &str, new: &str) -> String {
    let mut out = String::new();
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let max = old_lines.len().max(new_lines.len());
    for i in 0..max {
        let a = old_lines.get(i).copied().unwrap_or("");
        let b = new_lines.get(i).copied().unwrap_or("");
        if a != b {
            if !a.is_empty() {
                out.push_str(&format!("- {a}\n"));
            }
            if !b.is_empty() {
                out.push_str(&format!("+ {b}\n"));
            }
        }
    }
    if out.is_empty() {
        out.push_str("(no differences)\n");
    }
    out
}
