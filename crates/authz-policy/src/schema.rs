//! Cedar schema definitions and load-time policy validator.

use cedar_policy::{PolicySet, Schema, Validator};
use crate::error::PolicyError;

pub const DEFAULT_CEDAR_SCHEMA_JSON: &str = r#"{
  "": {
    "entityTypes": {
      "User": {
        "shape": {
          "type": "Record",
          "attributes": {}
        }
      },
      "Resource": {
        "shape": {
          "type": "Record",
          "attributes": {}
        }
      }
    },
    "actions": {
      "READ": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Resource"],
          "context": {
            "type": "Record",
            "attributes": {
              "principal_roles": { "type": "Set", "element": { "type": "String" }, "required": true },
              "action_name": { "type": "String", "required": true },
              "resource_kind": { "type": "String", "required": true },
              "subject_is_self": { "type": "Boolean", "required": true },
              "subject_in_direct_reports": { "type": "Boolean", "required": true },
              "subject_groups": { "type": "Set", "element": { "type": "String" }, "required": true }
            }
          }
        }
      },
      "TOOL_INVOKE": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Resource"],
          "context": {
            "type": "Record",
            "attributes": {
              "principal_roles": { "type": "Set", "element": { "type": "String" }, "required": true },
              "action_name": { "type": "String", "required": true },
              "resource_kind": { "type": "String", "required": true },
              "subject_is_self": { "type": "Boolean", "required": true },
              "subject_in_direct_reports": { "type": "Boolean", "required": true },
              "subject_groups": { "type": "Set", "element": { "type": "String" }, "required": true }
            }
          }
        }
      },
      "EXPORT": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Resource"],
          "context": {
            "type": "Record",
            "attributes": {
              "principal_roles": { "type": "Set", "element": { "type": "String" }, "required": true },
              "action_name": { "type": "String", "required": true },
              "resource_kind": { "type": "String", "required": true },
              "subject_is_self": { "type": "Boolean", "required": true },
              "subject_in_direct_reports": { "type": "Boolean", "required": true },
              "subject_groups": { "type": "Set", "element": { "type": "String" }, "required": true }
            }
          }
        }
      }
    }
  }
}"#;

/// Validate a Cedar policy set against the PAAC Cedar schema at load time.
pub fn validate_cedar_policy_set(policy_set: &PolicySet) -> Result<(), PolicyError> {
    let schema = Schema::from_json_str(DEFAULT_CEDAR_SCHEMA_JSON)
        .map_err(|e| PolicyError::Cedar(format!("schema parse error: {e}")))?;
    let validator = Validator::new(schema);
    let result = validator.validate(policy_set, cedar_policy::ValidationMode::Strict);
    if result.validation_passed() {
        Ok(())
    } else {
        let errs: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        Err(PolicyError::Cedar(format!("Cedar schema validation failed: {}", errs.join("; "))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translate::cedar_policy_set_from_dsl;
    use crate::dsl::parse_dsl;

    #[test]
    fn test_schema_validation_passes_for_valid_dsl() {
        let src = r#"
policy "hr_read"
when role == HR_HEAD
allow READ TRAVEL_EXPENSE
"#;
        let policies = parse_dsl(src).unwrap();
        let set = cedar_policy_set_from_dsl(&policies).unwrap();
        assert!(validate_cedar_policy_set(&set).is_ok());
    }
}
