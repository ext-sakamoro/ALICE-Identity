//! errors.

use std::fmt;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    InvalidDid(String),
    DocumentNotFound(String),
    DocumentAlreadyExists(String),
    DocumentDeactivated(String),
    CredentialExpired,
    CredentialRevoked(String),
    InvalidSignature,
    UntrustedIssuer(String),
    SchemaValidation(String),
    ClaimNotFound(String),
    InvalidClaimType { field: String, expected: String },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDid(s) => write!(f, "invalid DID: {s}"),
            Self::DocumentNotFound(s) => write!(f, "DID document not found: {s}"),
            Self::DocumentAlreadyExists(s) => write!(f, "DID document already exists: {s}"),
            Self::DocumentDeactivated(s) => write!(f, "DID document deactivated: {s}"),
            Self::CredentialExpired => write!(f, "credential has expired"),
            Self::CredentialRevoked(s) => write!(f, "credential revoked: {s}"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::UntrustedIssuer(s) => write!(f, "untrusted issuer: {s}"),
            Self::SchemaValidation(s) => write!(f, "schema validation failed: {s}"),
            Self::ClaimNotFound(s) => write!(f, "claim not found: {s}"),
            Self::InvalidClaimType { field, expected } => {
                write!(f, "claim '{field}' expected type '{expected}'")
            }
        }
    }
}
