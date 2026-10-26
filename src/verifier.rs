//! verifier.

use alice_sign::cred::{CredError, RevokedSet};
use std::collections::{BTreeMap, BTreeSet};

use crate::credential::{claim_error, CredentialPresentation, SUBJECT_CLAIM, TYPE_CLAIM};
use crate::did::Did;
use crate::errors::IdentityError;

// CredentialVerifier
// ---------------------------------------------------------------------------

/// The issuers a verifier trusts.
pub struct CredentialVerifier {
    trusted_issuers: BTreeSet<Did>,
}

/// What a verified presentation establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaims {
    /// The issuer that signed the credential.
    pub issuer: Did,
    /// The subject the credential is about.
    pub subject: Did,
    /// The credential's type.
    pub credential_type: String,
    /// The shown claims (without `@subject` and `@type`), by name.
    pub claims: BTreeMap<String, String>,
}

impl CredentialVerifier {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            trusted_issuers: BTreeSet::new(),
        }
    }

    pub fn add_trusted_issuer(&mut self, did: Did) {
        self.trusted_issuers.insert(did);
    }

    /// Verify a presentation at `now`: the issuer is trusted, the credential is signed by the
    /// Ed25519 key of the issuer's `did:key`, `now` is inside its window `[issued_at, expires_at)`,
    /// the signer is not in `revoked`, and every shown claim is covered by the signature.
    ///
    /// # Errors
    /// `UntrustedIssuer` for an issuer not added; `InvalidDid` for an issuer DID that is not an
    /// Ed25519 `did:key`; `CredentialExpired` at or after `expires_at`, `CredentialNotYetValid`
    /// before `issued_at`; `CredentialRevoked` for a revoked signer key; `InvalidSignature` for a
    /// signature by another key, a changed credential or a shown claim it does not cover;
    /// `ClaimNotFound` when the subject or type is not shown.
    pub fn verify(
        &self,
        presentation: &CredentialPresentation,
        now: u64,
        revoked: &impl RevokedSet,
    ) -> Result<VerifiedClaims, IdentityError> {
        let issuer = &presentation.issuer;
        if !self.trusted_issuers.contains(issuer) {
            return Err(IdentityError::UntrustedIssuer(issuer.to_string()));
        }
        let key = issuer.ed25519_public_key()?;
        let payload = presentation
            .signed
            .verify_at(&key, now, revoked)
            .map_err(|e| match e {
                CredError::Expired => IdentityError::CredentialExpired,
                CredError::NotYetValid => IdentityError::CredentialNotYetValid,
                CredError::Revoked => IdentityError::CredentialRevoked(issuer.to_string()),
                _ => IdentityError::InvalidSignature,
            })?;
        let shown = presentation
            .disclosure
            .verify(payload)
            .map_err(claim_error)?;
        let mut claims: BTreeMap<String, String> = shown
            .into_iter()
            .map(|c| (c.name.clone(), c.value.clone()))
            .collect();
        let subject = claims
            .remove(SUBJECT_CLAIM)
            .ok_or_else(|| IdentityError::ClaimNotFound(SUBJECT_CLAIM.to_owned()))?;
        let credential_type = claims
            .remove(TYPE_CLAIM)
            .ok_or_else(|| IdentityError::ClaimNotFound(TYPE_CLAIM.to_owned()))?;
        Ok(VerifiedClaims {
            issuer: issuer.clone(),
            subject: Did::parse(&subject)?,
            credential_type,
            claims,
        })
    }
}

impl Default for CredentialVerifier {
    fn default() -> Self {
        Self::new()
    }
}
