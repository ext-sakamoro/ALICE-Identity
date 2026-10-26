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
    CredentialNotYetValid,
    /// A credential issued under another credential format (alice-sign's cred identifier) than this
    /// build verifies: the two identifiers
    UnsupportedCredentialFormat {
        stored: [u8; 32],
        expected: [u8; 32],
    },
    /// The shown claims are not covered by the credential's signature, or their positions or
    /// proofs are malformed (why, from alice-sign's claims check)
    DisclosureRefused(String),
    CredentialRevoked(String),
    InvalidSignature,
    UntrustedIssuer(String),
    SchemaValidation(String),
    ClaimNotFound(String),
    InvalidClaimType {
        field: String,
        expected: String,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDid(s) => write!(f, "invalid DID: {s}"),
            Self::DocumentNotFound(s) => write!(f, "DID document not found: {s}"),
            Self::DocumentAlreadyExists(s) => write!(f, "DID document already exists: {s}"),
            Self::DocumentDeactivated(s) => write!(f, "DID document deactivated: {s}"),
            Self::CredentialExpired => write!(f, "credential has expired"),
            Self::CredentialNotYetValid => write!(f, "credential is not yet valid"),
            Self::UnsupportedCredentialFormat { stored, expected } => {
                write!(f, "credential format ")?;
                for b in stored {
                    write!(f, "{b:02x}")?;
                }
                write!(f, " is not this build's ")?;
                for b in expected {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
            Self::DisclosureRefused(why) => write!(f, "disclosure refused: {why}"),
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
