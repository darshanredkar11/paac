//! Canonical identity model and adapters (local fixtures, JWT/OIDC claims, LDAP sync).

mod adapters;
mod error;
mod model;

pub use adapters::{
    group_members_map, save_snapshot, IdentityAdapter, JwtOidcAdapter, LdapAdapter, LdapConfig,
    LocalFixtureAdapter, MockLdapDirectory,
};
pub use error::IdentityError;
pub use model::{CanonicalIdentity, Group, IdentitySnapshot, RelationshipEdge};
