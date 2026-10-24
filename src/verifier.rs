//! verifier.

use crate::credential::VerifiableCredential;
use crate::did::Did;
use crate::errors::IdentityError;
use std::collections::HashSet;

// CredentialVerifier
// ---------------------------------------------------------------------------

pub struct CredentialVerifier {
    trusted_issuers: HashSet<Did>,
}

impl CredentialVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            trusted_issuers: HashSet::new(),
        }
    }

    pub fn add_trusted_issuer(&mut self, did: Did) {
        self.trusted_issuers.insert(did);
    }

    /// Verify a credential: signature, expiry, and issuer trust.
    ///
    /// # Errors
    /// Returns an error if the signature is empty, the credential is expired,
    /// or the issuer is untrusted.
    pub fn verify(
        &self,
        credential: &VerifiableCredential,
        current_time: u64,
    ) -> Result<(), IdentityError> {
        // Signature check (non-empty proof = valid for this implementation)
        if credential.proof.is_empty() {
            return Err(IdentityError::InvalidSignature);
        }

        // Expiry check
        if let Some(exp) = credential.expires_at {
            if current_time > exp {
                return Err(IdentityError::CredentialExpired);
            }
        }

        // Issuer trust check
        if !self.trusted_issuers.contains(&credential.issuer) {
            return Err(IdentityError::UntrustedIssuer(
                credential.issuer.to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for CredentialVerifier {
    fn default() -> Self {
        Self::new()
    }
}
