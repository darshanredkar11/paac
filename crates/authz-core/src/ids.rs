//! Validated newtypes for core identifiers. Prefer these over raw strings at API boundaries.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! id_newtype {
    ($name:ident, $label:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, crate::AuthzError> {
                let v = value.into();
                let t = v.trim();
                if t.is_empty() {
                    return Err(crate::AuthzError::InvalidRequest(format!(
                        "{} must be non-empty",
                        $label
                    )));
                }
                Ok(Self(t.to_string()))
            }

            /// Construct without validation — only for trusted internal paths.
            pub fn from_trusted(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }
    };
}

id_newtype!(PrincipalId, "principal id");
id_newtype!(ResourceKind, "resource kind");
id_newtype!(ResourceId, "resource id");
id_newtype!(DecisionId, "decision id");
id_newtype!(ActionName, "action name");
id_newtype!(AgentId, "agent id");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert!(PrincipalId::new("  ").is_err());
        assert!(PrincipalId::new("user:hr").is_ok());
    }
}
