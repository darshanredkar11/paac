//! Canonical identity model and adapters (local, JWT/JWKS, LDAP, AD, Entra ID, Cognito).

mod adapters;
mod cache;
mod error;
mod idp;
mod model;

pub use adapters::{
    group_members_map, save_snapshot, IdentityAdapter, JwtOidcAdapter, LdapAdapter, LdapConfig,
    LocalFixtureAdapter, MockLdapDirectory,
};
pub use cache::{CachedIdentity, IdentityCache};
pub use error::IdentityError;
pub use idp::{
    default_drafts_from_groups, ActiveDirectoryAdapter, ActiveDirectoryConfig, CognitoAdapter,
    CognitoConfig, EntraConfig, EntraIdAdapter, IdpAdapter,
};
pub use model::{CanonicalIdentity, Group, IdentitySnapshot, RelationshipEdge};
