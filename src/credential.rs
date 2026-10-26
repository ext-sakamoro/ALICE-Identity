//! credential.
//!
//! A verifiable credential is an [`alice_sign::cred::SignedCredential`] over the payload of an
//! [`alice_sign::cred::claims::ClaimSet`]: the issuer signs the payload with the Ed25519 key of its
//! `did:key`, the validity window is the credential's `[issued_at, expires_at)`, and the holder keeps
//! the claims (with their salts) to show some of them later as a [`CredentialPresentation`].
//! Signing, the validity window and the selective disclosure are alice-sign's; this module binds them
//! to DIDs (the issuer's key comes from its DID, the subject and the credential type are claims).

use alice_sign::cred::claims::{Claim, ClaimError, ClaimSet, Disclosure, SALT_LENGTH};
use alice_sign::cred::{SignedCredential, ValidityWindow};
use alice_sign::KeyPair;
use std::collections::BTreeMap;

use crate::did::Did;
use crate::errors::IdentityError;

/// The claim naming the credential's subject (always shown).
pub const SUBJECT_CLAIM: &str = "@subject";
/// The claim naming the credential's type (always shown).
pub const TYPE_CLAIM: &str = "@type";

// VerifiableCredential
// ---------------------------------------------------------------------------

/// A credential as its holder keeps it: the issuer's signed credential and the claims under it.
#[derive(Debug, Clone)]
pub struct VerifiableCredential {
    /// The issuer's `did:key` (its Ed25519 key signs the credential).
    pub issuer: Did,
    /// The signature over the claims' payload and the validity window.
    pub signed: SignedCredential,
    claims: ClaimSet,
}

/// What an issuer puts in a credential besides the claims.
#[derive(Debug, Clone)]
pub struct CredentialTerms<'a> {
    /// The credential's type (shown as the `@type` claim).
    pub credential_type: &'a str,
    /// The subject (shown as the `@subject` claim).
    pub subject: &'a Did,
    /// First valid second (UNIX).
    pub issued_at: u64,
    /// First invalid second (UNIX); `None` for no expiry.
    pub expires_at: Option<u64>,
}

impl VerifiableCredential {
    /// Issue a credential signed by `issuer` over `claims` (each with its salt; one fresh salt per
    /// claim from a cryptographic source), with the subject and type added as claims.
    ///
    /// # Errors
    /// `IdentityError::SchemaValidation` when a claim name repeats or is one of the reserved
    /// `@subject` / `@type`.
    pub fn issue(
        issuer: &KeyPair,
        terms: &CredentialTerms<'_>,
        claims: Vec<Claim>,
        reserved_salts: [[u8; SALT_LENGTH]; 2],
    ) -> Result<Self, IdentityError> {
        if let Some(c) = claims
            .iter()
            .find(|c| c.name == SUBJECT_CLAIM || c.name == TYPE_CLAIM)
        {
            return Err(IdentityError::SchemaValidation(format!(
                "claim name {} is reserved",
                c.name
            )));
        }
        let mut all = claims;
        all.push(Claim::new(
            SUBJECT_CLAIM,
            terms.subject.to_string(),
            reserved_salts[0],
        ));
        all.push(Claim::new(
            TYPE_CLAIM,
            terms.credential_type,
            reserved_salts[1],
        ));
        let claims = ClaimSet::new(all).map_err(claim_error)?;
        let window = ValidityWindow::new(terms.issued_at, terms.expires_at.unwrap_or(u64::MAX));
        Ok(Self {
            issuer: Did::key_ed25519(&issuer.public()),
            signed: SignedCredential::sign(issuer, claims.payload(), window),
            claims,
        })
    }

    /// The claims the holder keeps (without `@subject` and `@type`), by name.
    #[must_use]
    pub fn claims(&self) -> BTreeMap<String, String> {
        self.claims
            .claims()
            .iter()
            .filter(|c| c.name != SUBJECT_CLAIM && c.name != TYPE_CLAIM)
            .map(|c| (c.name.clone(), c.value.clone()))
            .collect()
    }

    /// A presentation showing the claims named in `fields` (and the subject and type), keeping the
    /// others hidden.
    ///
    /// # Errors
    /// `IdentityError::ClaimNotFound` when a field is not a claim of the credential.
    pub fn present(&self, fields: &[&str]) -> Result<CredentialPresentation, IdentityError> {
        let mut names: Vec<&str> = fields.to_vec();
        names.extend([SUBJECT_CLAIM, TYPE_CLAIM]);
        let disclosure = self.claims.disclose(&names).map_err(claim_error)?;
        Ok(CredentialPresentation {
            issuer: self.issuer.clone(),
            signed: self.signed.clone(),
            disclosure,
        })
    }
}

// CredentialPresentation
// ---------------------------------------------------------------------------

/// Some claims of a credential, as a verifier receives them; nothing in it is trusted until
/// [`crate::verifier::CredentialVerifier::verify`] accepts it.
#[derive(Debug, Clone)]
pub struct CredentialPresentation {
    /// The issuer's `did:key`.
    pub issuer: Did,
    /// The issuer's signed credential.
    pub signed: SignedCredential,
    /// The shown claims with their proofs.
    pub disclosure: Disclosure,
}

pub(crate) fn claim_error(e: ClaimError) -> IdentityError {
    match e {
        ClaimError::UnknownName(n) => IdentityError::ClaimNotFound(n),
        ClaimError::DuplicateName(n) => {
            IdentityError::SchemaValidation(format!("claim name {n} appears twice"))
        }
        _ => IdentityError::InvalidSignature,
    }
}
