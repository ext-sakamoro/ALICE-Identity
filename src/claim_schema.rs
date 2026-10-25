//! claim schema.

use crate::errors::IdentityError;
use std::collections::BTreeMap;

// ClaimSchema
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSchema {
    pub required_fields: Vec<String>,
    pub field_types: BTreeMap<String, String>,
}

impl ClaimSchema {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            required_fields: Vec::new(),
            field_types: BTreeMap::new(),
        }
    }

    pub fn add_required_field(&mut self, name: &str, field_type: &str) {
        self.required_fields.push(name.to_owned());
        self.field_types
            .insert(name.to_owned(), field_type.to_owned());
    }

    pub fn add_optional_field(&mut self, name: &str, field_type: &str) {
        self.field_types
            .insert(name.to_owned(), field_type.to_owned());
    }

    /// Validate claims against this schema.
    ///
    /// # Errors
    /// Returns an error if required fields are missing or types don't match.
    pub fn validate(&self, claims: &BTreeMap<String, String>) -> Result<(), IdentityError> {
        // Check required fields
        for field in &self.required_fields {
            if !claims.contains_key(field) {
                return Err(IdentityError::ClaimNotFound(field.clone()));
            }
        }

        // Check types (simple type-name matching via prefix convention)
        for (field, value) in claims {
            if let Some(expected_type) = self.field_types.get(field) {
                if !validate_claim_type(value, expected_type) {
                    return Err(IdentityError::InvalidClaimType {
                        field: field.clone(),
                        expected: expected_type.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}

impl Default for ClaimSchema {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple type validation for claim values.
fn validate_claim_type(value: &str, expected: &str) -> bool {
    match expected {
        "integer" => value.parse::<i64>().is_ok(),
        "boolean" => value == "true" || value == "false",
        "date" => {
            value.len() == 10
                && value.chars().nth(4) == Some('-')
                && value.chars().nth(7) == Some('-')
        }
        _ => true,
    }
}
