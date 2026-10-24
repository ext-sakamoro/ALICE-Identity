//! selective disclosure.

use crate::credential::VerifiableCredential;
use crate::errors::IdentityError;
use std::collections::HashMap;

// SelectiveDisclosure
// ---------------------------------------------------------------------------

pub struct SelectiveDisclosure;

impl SelectiveDisclosure {
    /// Create a new credential revealing only the specified claims.
    ///
    /// # Errors
    /// Returns an error if a requested field is not present in the original claims.
    pub fn disclose(
        credential: &VerifiableCredential,
        fields: &[&str],
    ) -> Result<VerifiableCredential, IdentityError> {
        let mut disclosed_claims = HashMap::new();
        for &field in fields {
            let value = credential
                .claims
                .get(field)
                .ok_or_else(|| IdentityError::ClaimNotFound(field.to_owned()))?;
            disclosed_claims.insert(field.to_owned(), value.clone());
        }

        Ok(VerifiableCredential {
            context: credential.context.clone(),
            credential_type: credential.credential_type.clone(),
            issuer: credential.issuer.clone(),
            subject: credential.subject.clone(),
            issued_at: credential.issued_at,
            expires_at: credential.expires_at,
            claims: disclosed_claims,
            proof: credential.proof.clone(),
        })
    }
}
