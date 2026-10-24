//! Revocation of device certificates: a master key signs a sequenced list of the certificate ids
//! it has revoked, and [`CertRevocations`] keeps the newest list each master has published.
//!
//! The list is encoded as one canonical byte layout and signed with its own context prefix, so it
//! is never mistaken for a device certificate or any other statement under the same key:
//!
//! ```text
//! signed = REVOCATION_LIST_CONTEXT || body
//! body   = version (1) || issuer_public (32) || sequence (u64 BE) || issued_at (u64 BE)
//!          || count (u32 BE) || cert_id (16) * count, strictly ascending
//! bytes  = body || signature (64)
//! ```
//!
//! Members that receive lists in different orders converge: a higher sequence replaces a lower
//! one, a lower one is ignored, and two different lists with the same sequence are a conflict.

use crate::device_cert::DeviceCert;
use alice_sign::{KeyPair, PublicKey, Signature};
use std::collections::HashMap;
use std::fmt;

/// The only list layout this version reads and writes
pub const REVOCATION_LIST_VERSION: u8 = 1;

/// Prefixed to the body before signing (domain separation)
pub const REVOCATION_LIST_CONTEXT: &[u8] = b"alice-identity revocation-list v1";

/// Bytes before the ids: version, issuer key, sequence, issued_at, count
const HEAD: usize = 1 + 32 + 8 + 8 + 4;
const ID: usize = 16;
const SIGNATURE: usize = 64;

/// A master key's signed list of the device certificate ids it has revoked
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationList {
    version: u8,
    issuer_public: [u8; 32],
    sequence: u64,
    issued_at: u64,
    revoked: Vec<[u8; 16]>,
    signature: [u8; 64],
}

/// Why a list was not decoded or accepted
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationListError {
    /// The layout version is not [`REVOCATION_LIST_VERSION`]
    UnsupportedVersion(u8),
    /// The bytes do not hold one whole list in canonical form (the reason names the part)
    Malformed(&'static str),
    /// The list names another issuer than the master key it is checked against
    IssuerMismatch,
    /// The signature does not verify (strictly) over the context and the body
    BadSignature,
    /// Another list from the same master has the same sequence and different content
    Conflict { sequence: u64 },
}

impl fmt::Display for RevocationListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported revocation list version {v}"),
            Self::Malformed(what) => write!(f, "malformed revocation list: {what}"),
            Self::IssuerMismatch => {
                write!(f, "revocation list issuer is not the expected master key")
            }
            Self::BadSignature => write!(f, "revocation list signature does not verify"),
            Self::Conflict { sequence } => write!(
                f,
                "a different revocation list with sequence {sequence} is already kept"
            ),
        }
    }
}

impl std::error::Error for RevocationListError {}

impl RevocationList {
    /// Sign the list of `revoked` ids (in any order, repeats allowed: they are sorted and merged)
    #[must_use]
    pub fn issue(master: &KeyPair, sequence: u64, issued_at: u64, revoked: &[[u8; 16]]) -> Self {
        let mut ids = revoked.to_vec();
        ids.sort_unstable();
        ids.dedup();
        let mut list = Self {
            version: REVOCATION_LIST_VERSION,
            issuer_public: master.public().0,
            sequence,
            issued_at,
            revoked: ids,
            signature: [0; SIGNATURE],
        };
        list.signature = master.sign(&list.signed_message()).0;
        list
    }

    /// The body: everything the signature covers after the context
    fn body(&self) -> Vec<u8> {
        // a list is built only by `issue` and `from_bytes`; neither can hold more ids than a
        // u32 counts (from_bytes reads the count from a u32, issue would need 64 GiB of ids)
        let count = u32::try_from(self.revoked.len()).expect("id count fits the u32 field");
        let mut b = Vec::with_capacity(HEAD + ID * self.revoked.len());
        b.extend_from_slice(&[self.version]);
        b.extend_from_slice(&self.issuer_public);
        b.extend_from_slice(&self.sequence.to_be_bytes());
        b.extend_from_slice(&self.issued_at.to_be_bytes());
        b.extend_from_slice(&count.to_be_bytes());
        for id in &self.revoked {
            b.extend_from_slice(id);
        }
        b
    }

    /// The bytes the signature covers: [`REVOCATION_LIST_CONTEXT`] followed by the body
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = REVOCATION_LIST_CONTEXT.to_vec();
        m.extend_from_slice(&self.body());
        m
    }

    /// The canonical encoding: the body followed by the signature
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decode a list (the signature is not checked here; see [`RevocationList::verify`])
    ///
    /// # Errors
    /// [`RevocationListError::Malformed`] for a wrong length or ids not strictly ascending,
    /// [`RevocationListError::UnsupportedVersion`]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RevocationListError> {
        let (&version, _) = bytes
            .split_first()
            .ok_or(RevocationListError::Malformed("version"))?;
        if version != REVOCATION_LIST_VERSION {
            return Err(RevocationListError::UnsupportedVersion(version));
        }
        if bytes.len() < HEAD {
            return Err(RevocationListError::Malformed("header"));
        }
        let count = u32::from_be_bytes(bytes[HEAD - 4..HEAD].try_into().expect("4 bytes"));
        let ids_len = usize::try_from(count)
            .ok()
            .and_then(|c| c.checked_mul(ID))
            .ok_or(RevocationListError::Malformed("count"))?;
        if bytes.len() - HEAD != ids_len + SIGNATURE {
            return Err(RevocationListError::Malformed("length for the count"));
        }
        let revoked: Vec<[u8; 16]> = bytes[HEAD..HEAD + ids_len]
            .chunks_exact(ID)
            .map(|c| c.try_into().expect("16 bytes"))
            .collect();
        if revoked.windows(2).any(|w| w[0] >= w[1]) {
            return Err(RevocationListError::Malformed("order"));
        }
        let u64_at = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        Ok(Self {
            version,
            issuer_public: bytes[1..33].try_into().expect("32 bytes"),
            sequence: u64_at(33),
            issued_at: u64_at(41),
            revoked,
            signature: bytes[HEAD + ids_len..].try_into().expect("64 bytes"),
        })
    }

    /// Accept the list only if `master` issued it and its signature verifies strictly
    ///
    /// # Errors
    /// The first failing check, in this order: version, issuer, signature
    pub fn verify(&self, master: &PublicKey) -> Result<(), RevocationListError> {
        if self.version != REVOCATION_LIST_VERSION {
            return Err(RevocationListError::UnsupportedVersion(self.version));
        }
        if self.issuer_public != master.0 {
            return Err(RevocationListError::IssuerMismatch);
        }
        if !master.verify_strict(&self.signed_message(), &Signature(self.signature)) {
            return Err(RevocationListError::BadSignature);
        }
        Ok(())
    }

    /// Whether `cert_id` is on the list
    #[must_use]
    pub fn contains(&self, cert_id: &[u8; 16]) -> bool {
        self.revoked.binary_search(cert_id).is_ok()
    }

    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    #[must_use]
    pub const fn issuer_public(&self) -> &[u8; 32] {
        &self.issuer_public
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// The revoked ids, strictly ascending
    #[must_use]
    pub fn revoked(&self) -> &[[u8; 16]] {
        &self.revoked
    }

    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// What [`CertRevocations::accept`] did with a verified list
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// The first list from this master, or a higher sequence: it is now the one kept
    Replaced,
    /// The same list as the one kept (same sequence, same bytes)
    Unchanged,
    /// A lower sequence than the one kept: ignored
    Older,
}

/// The newest verified revocation list of each master key, keyed by the master's public key
#[derive(Debug, Clone, Default)]
pub struct CertRevocations {
    lists: HashMap<[u8; 32], RevocationList>,
}

impl CertRevocations {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify `list` against `master` and keep it if it is newer than the one kept
    ///
    /// # Errors
    /// The list's own verification errors, or [`RevocationListError::Conflict`] when a different
    /// list with the same sequence is already kept (the kept one stays)
    pub fn accept(
        &mut self,
        list: RevocationList,
        master: &PublicKey,
    ) -> Result<Accepted, RevocationListError> {
        list.verify(master)?;
        match self.lists.get(&master.0) {
            Some(kept) if kept.sequence > list.sequence => Ok(Accepted::Older),
            Some(kept) if kept.sequence == list.sequence => {
                if *kept == list {
                    Ok(Accepted::Unchanged)
                } else {
                    Err(RevocationListError::Conflict {
                        sequence: list.sequence,
                    })
                }
            }
            _ => {
                self.lists.insert(master.0, list);
                Ok(Accepted::Replaced)
            }
        }
    }

    /// The sequence of the list kept for `master`, if any
    #[must_use]
    pub fn sequence(&self, master: &PublicKey) -> Option<u64> {
        self.lists.get(&master.0).map(RevocationList::sequence)
    }

    /// Whether the newest list of `master` revokes `cert_id` (no list: not revoked)
    #[must_use]
    pub fn is_revoked(&self, master: &PublicKey, cert_id: &[u8; 16]) -> bool {
        self.lists
            .get(&master.0)
            .is_some_and(|l| l.contains(cert_id))
    }

    /// Whether the newest list of the certificate's issuer revokes it
    #[must_use]
    pub fn revokes(&self, cert: &DeviceCert) -> bool {
        self.is_revoked(&PublicKey(*cert.issuer_public()), cert.cert_id())
    }
}
