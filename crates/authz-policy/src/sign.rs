use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::PolicyError;

/// KMS-friendly signing trait. MVP uses local Ed25519 keys.
pub trait BundleSigner: Send + Sync {
    fn key_id(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PolicyError>;
    fn verifying_key_bytes(&self) -> Vec<u8>;
}

#[derive(Clone)]
pub struct LocalEd25519Signer {
    pub key_id: String,
    signing: SigningKey,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SigningKeyPair {
    pub key_id: String,
    pub secret_hex: String,
    pub public_hex: String,
}

impl LocalEd25519Signer {
    pub fn generate(key_id: impl Into<String>) -> (Self, SigningKeyPair) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let key_id = key_id.into();
        let pair = SigningKeyPair {
            key_id: key_id.clone(),
            secret_hex: hex::encode(signing.to_bytes()),
            public_hex: hex::encode(verifying.to_bytes()),
        };
        (Self { key_id, signing }, pair)
    }

    pub fn from_keypair(pair: &SigningKeyPair) -> Result<Self, PolicyError> {
        let bytes: [u8; 32] = hex::decode(&pair.secret_hex)
            .map_err(|e| PolicyError::Crypto(e.to_string()))?
            .try_into()
            .map_err(|_| PolicyError::Crypto("invalid secret length".into()))?;
        let signing = SigningKey::from_bytes(&bytes);
        Ok(Self {
            key_id: pair.key_id.clone(),
            signing,
        })
    }
}

impl BundleSigner for LocalEd25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, PolicyError> {
        Ok(self.signing.sign(message).to_bytes().to_vec())
    }

    fn verifying_key_bytes(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().to_vec()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBundle {
    pub revision: String,
    pub content_sha256: String,
    pub cedar: String,
    pub dsl: String,
    pub signature_b64: String,
    pub key_id: String,
    pub signed_at: String,
}

pub fn content_digest(cedar: &str) -> String {
    let mut h = Sha256::new();
    h.update(cedar.as_bytes());
    hex::encode(h.finalize())
}

pub fn sign_bundle(
    signer: &dyn BundleSigner,
    revision: &str,
    cedar: &str,
    dsl: &str,
) -> Result<SignedBundle, PolicyError> {
    let content_sha256 = content_digest(cedar);
    let message = format!("{revision}\n{content_sha256}");
    let sig = signer.sign(message.as_bytes())?;
    Ok(SignedBundle {
        revision: revision.to_string(),
        content_sha256,
        cedar: cedar.to_string(),
        dsl: dsl.to_string(),
        signature_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig),
        key_id: signer.key_id().to_string(),
        signed_at: chrono::Utc::now().to_rfc3339(),
    })
}

pub fn verify_bundle(
    bundle: &SignedBundle,
    public_key_bytes: &[u8],
) -> Result<bool, PolicyError> {
    let digest = content_digest(&bundle.cedar);
    if digest != bundle.content_sha256 {
        return Ok(false);
    }
    let message = format!("{}\n{}", bundle.revision, bundle.content_sha256);
    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &bundle.signature_b64,
    )
    .map_err(|e| PolicyError::Crypto(e.to_string()))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| PolicyError::Crypto(e.to_string()))?;
    let pk_arr: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| PolicyError::Crypto("public key must be 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| PolicyError::Crypto(e.to_string()))?;
    Ok(vk.verify(message.as_bytes(), &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let (signer, _) = LocalEd25519Signer::generate("k");
        let bundle = sign_bundle(
            &signer,
            "rev1",
            "permit(principal, action, resource);",
            "dsl",
        )
        .unwrap();
        assert!(verify_bundle(&bundle, &signer.verifying_key_bytes()).unwrap());
        let mut bad2 = bundle.clone();
        bad2.cedar = "forbid(principal, action, resource);".into();
        assert!(!verify_bundle(&bad2, &signer.verifying_key_bytes()).unwrap());
    }
}
