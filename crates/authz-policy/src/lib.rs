//! Human DSL → Cedar, validation, versioned file store, signed policy bundles.

mod dsl;
mod error;
mod sign;
mod store;
mod translate;

pub use dsl::{parse_dsl, DslPolicy, DslEffect};
pub use error::PolicyError;
pub use sign::{sign_bundle, verify_bundle, BundleSigner, LocalEd25519Signer, SignedBundle, SigningKeyPair};
pub use store::{PolicyRevision, PolicyStore, StoredPolicy};
pub use translate::{dsl_to_cedar, cedar_policy_set_from_dsl};
