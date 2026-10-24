//! did.

use crate::errors::IdentityError;
use std::fmt;

// Did
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Did {
    pub method: String,
    pub id: String,
}

impl Did {
    #[must_use]
    pub fn new(method: &str, id: &str) -> Self {
        Self {
            method: method.to_owned(),
            id: id.to_owned(),
        }
    }

    /// Parse a DID string in the format `did:method:id`.
    ///
    /// # Errors
    /// Returns `IdentityError::InvalidDid` when the string does not conform.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 || parts[0] != "did" || parts[1].is_empty() || parts[2].is_empty() {
            return Err(IdentityError::InvalidDid(s.to_owned()));
        }
        Ok(Self {
            method: parts[1].to_owned(),
            id: parts[2].to_owned(),
        })
    }

    /// Validate that the DID has non-empty method and id.
    ///
    /// # Errors
    /// Returns `IdentityError::InvalidDid` if method or id is empty.
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.method.is_empty() || self.id.is_empty() {
            return Err(IdentityError::InvalidDid(self.to_string()));
        }
        Ok(())
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "did:{}:{}", self.method, self.id)
    }
}
