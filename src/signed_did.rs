//! `W3C DID Core` v1.0 + `Verifiable Credentials Data Integrity`.
//!
//! Provides:
//!
//! - [`DidDocument`] with a `verificationMethod` array carrying `Ed25519`
//!   public keys.
//! - [`ClaimSet`] representing subject attributes.
//! - [`SignedClaim`] signed by an issuer key over the canonical claim bytes,
//!   ready to be embedded in a `W3C VC` (see
//!   `alice_sign::VerifiableCredentialBuilder`).

use alice_sign::{hash_data, Hash, KeyPair, PublicKey, Signature};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// DidDocument
// ---------------------------------------------------------------------------

/// A minimal W3C DID Document.
#[derive(Debug, Clone)]
pub struct DidDocument {
    pub did: String,
    pub verification_methods: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
}

impl DidDocument {
    /// Construct a document with a single `Ed25519VerificationKey2020`.
    #[must_use]
    pub fn new(did: impl Into<String>, key: PublicKey) -> Self {
        let did = did.into();
        let method_id = format!("{did}#keys-1");
        let vm = VerificationMethod {
            id: method_id.clone(),
            controller: did.clone(),
            public_key: key,
        };
        Self {
            did,
            verification_methods: vec![vm],
            authentication: vec![method_id.clone()],
            assertion_method: vec![method_id],
        }
    }

    /// Look up a verification method by fragment (e.g. `"keys-1"`).
    #[must_use]
    pub fn method_by_fragment(&self, fragment: &str) -> Option<&VerificationMethod> {
        self.verification_methods
            .iter()
            .find(|m| m.id.ends_with(&format!("#{fragment}")))
    }
}

/// A single `Ed25519VerificationKey2020` entry.
#[derive(Debug, Clone)]
pub struct VerificationMethod {
    pub id: String,
    pub controller: String,
    pub public_key: PublicKey,
}

// ---------------------------------------------------------------------------
// ClaimSet
// ---------------------------------------------------------------------------

/// Structured claims about the subject.
#[derive(Debug, Clone, Default)]
pub struct ClaimSet {
    pub subject: String,
    pub claims: BTreeMap<String, String>,
}

impl ClaimSet {
    /// Construct an empty claim set for `subject`.
    #[must_use]
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            claims: BTreeMap::new(),
        }
    }

    /// Insert or overwrite a claim.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.claims.insert(key.into(), value.into());
    }

    /// Canonical byte layout (deterministic thanks to `BTreeMap`).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        push_len(&mut buf, self.subject.as_bytes());
        buf.extend_from_slice(&(self.claims.len() as u64).to_le_bytes());
        for (k, v) in &self.claims {
            push_len(&mut buf, k.as_bytes());
            push_len(&mut buf, v.as_bytes());
        }
        buf
    }

    /// `SHA-256` digest of the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        hash_data(&self.canonical_bytes())
    }
}

// ---------------------------------------------------------------------------
// SignedClaim
// ---------------------------------------------------------------------------

/// A [`ClaimSet`] committed to by an issuer signature.
#[derive(Debug, Clone)]
pub struct SignedClaim {
    pub claims: ClaimSet,
    pub issuer_public: PublicKey,
    pub signature: Signature,
}

impl SignedClaim {
    /// Sign a claim set with `issuer`.
    #[must_use]
    pub fn issue(issuer: &KeyPair, claims: ClaimSet) -> Self {
        let bytes = claims.canonical_bytes();
        let signature = issuer.sign(&bytes);
        Self {
            claims,
            issuer_public: issuer.public(),
            signature,
        }
    }

    /// Verify the signature under the recorded issuer key.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.issuer_public
            .verify(&self.claims.canonical_bytes(), &self.signature)
    }

    /// Verify against an expected issuer key.
    #[must_use]
    pub fn verify_by(&self, expected_issuer: &PublicKey) -> bool {
        &self.issuer_public == expected_issuer && self.verify()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn push_len(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_document_has_single_verification_method() {
        let kp = KeyPair::from_seed([1u8; 32]);
        let doc = DidDocument::new("did:example:alice", kp.public());
        assert_eq!(doc.verification_methods.len(), 1);
        assert!(doc.method_by_fragment("keys-1").is_some());
    }

    #[test]
    fn method_by_fragment_returns_none_for_unknown() {
        let kp = KeyPair::from_seed([1u8; 32]);
        let doc = DidDocument::new("did:example:alice", kp.public());
        assert!(doc.method_by_fragment("keys-2").is_none());
    }

    #[test]
    fn claim_set_digest_is_deterministic_across_insert_order() {
        let mut a = ClaimSet::new("did:example:alice");
        a.insert("name", "Alice");
        a.insert("age", "30");
        let mut b = ClaimSet::new("did:example:alice");
        b.insert("age", "30");
        b.insert("name", "Alice");
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn signed_claim_verifies_under_issuer() {
        let issuer = KeyPair::from_seed([1u8; 32]);
        let mut claims = ClaimSet::new("did:example:alice");
        claims.insert("degree", "PhD");
        let signed = SignedClaim::issue(&issuer, claims);
        assert!(signed.verify());
        assert!(signed.verify_by(&issuer.public()));
    }

    #[test]
    fn tampered_claim_breaks_signature() {
        let issuer = KeyPair::from_seed([1u8; 32]);
        let mut claims = ClaimSet::new("did:example:alice");
        claims.insert("degree", "PhD");
        let mut signed = SignedClaim::issue(&issuer, claims);
        signed.claims.insert("degree", "MSc");
        assert!(!signed.verify());
    }

    #[test]
    fn wrong_issuer_key_rejects() {
        let issuer = KeyPair::from_seed([1u8; 32]);
        let other = KeyPair::from_seed([2u8; 32]);
        let mut claims = ClaimSet::new("did:example:alice");
        claims.insert("k", "v");
        let signed = SignedClaim::issue(&issuer, claims);
        assert!(!signed.verify_by(&other.public()));
    }

    #[test]
    fn empty_claim_set_still_verifies() {
        let issuer = KeyPair::from_seed([1u8; 32]);
        let signed = SignedClaim::issue(&issuer, ClaimSet::new("did:example:alice"));
        assert!(signed.verify());
    }
}
