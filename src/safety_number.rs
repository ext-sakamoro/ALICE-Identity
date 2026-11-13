//! The safety number of two identities.
//!
//! A string of digits both people compute from their two master
//! keys and compare (read aloud, or one device scans the other's QR code of [`SafetyNumber::as_bytes`]).
//! It is the same on both sides, and it changes when either key changes in any bit, so a key swapped
//! in transit (a person in the middle) shows as a different number.
//!
//! ```text
//! for each party (pub = its 32-byte Ed25519 master public key, did = the did:key text of pub):
//!   h_0     = SHA-256(SAFETY_NUMBER_CONTEXT || len(did) (u16 BE) || did || pub)
//!   h_{k+1} = SHA-256(h_k || pub)                     for k = 0 .. SAFETY_NUMBER_ITERATIONS - 1
//!   digits  = for i in 0..6: (h[5i .. 5i+5] as a 40-bit big-endian number) mod 100000, as 5 digits
//! number  = the two parties' 30 digits in ascending order, joined (60 digits)
//! bytes   = the two parties' final h in ascending order, joined (64 bytes)
//! ```
//!
//! The iterations make a search for a second key with the same 30 digits cost that many hashes per
//! try. Sorting makes the order of the arguments irrelevant. The input is the public key only (the
//! did:key is derived from it), so no spelling of an identifier can change the number. Nothing here
//! reads a clock, a random source or the network.

use crate::did::Did;
use alice_crypto::sha256::digest;
use alice_sign::PublicKey;
use std::fmt::{self, Write as _};

/// Prefixed to the first hash of each party (domain separation)
pub const SAFETY_NUMBER_CONTEXT: &[u8] = b"alice-identity safety-number v1";

/// The hashes after the first, per party
pub const SAFETY_NUMBER_ITERATIONS: usize = 5200;

/// The digits of a safety number
pub const SAFETY_NUMBER_DIGITS: usize = 60;

/// The safety number of two identities (see the module documentation)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    digits: String,
    bytes: [u8; 64],
}

/// Why no safety number was computed
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyNumberError {
    /// Both keys are the same key: there is no second party to compare with
    SameParty,
}

impl fmt::Display for SafetyNumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameParty => f.write_str("a safety number needs two different keys"),
        }
    }
}

impl std::error::Error for SafetyNumberError {}

/// One party's final hash and its 30 digits
fn party(public: &PublicKey) -> ([u8; 32], String) {
    let did = Did::key_ed25519(public).to_string();
    let len = u16::try_from(did.len()).expect("a did:key is 56 characters");
    let mut first = Vec::with_capacity(SAFETY_NUMBER_CONTEXT.len() + 2 + did.len() + 32);
    first.extend_from_slice(SAFETY_NUMBER_CONTEXT);
    first.extend_from_slice(&len.to_be_bytes());
    first.extend_from_slice(did.as_bytes());
    first.extend_from_slice(&public.0);
    let mut h = digest(&first);
    let mut next = [0u8; 64];
    next[32..].copy_from_slice(&public.0);
    for _ in 0..SAFETY_NUMBER_ITERATIONS {
        next[..32].copy_from_slice(&h);
        h = digest(&next);
    }
    let mut digits = String::with_capacity(30);
    for i in 0..6 {
        let v = h[5 * i..5 * i + 5]
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        write!(digits, "{:05}", v % 100_000).expect("writing to a String");
    }
    (h, digits)
}

/// The safety number of the identities whose master public keys are `a` and `b`
///
/// # Errors
/// [`SafetyNumberError::SameParty`] when `a` and `b` are the same key
pub fn safety_number(a: &PublicKey, b: &PublicKey) -> Result<SafetyNumber, SafetyNumberError> {
    if a.0 == b.0 {
        return Err(SafetyNumberError::SameParty);
    }
    let (ha, da) = party(a);
    let (hb, db) = party(b);
    let (lo_d, hi_d) = if da <= db { (da, db) } else { (db, da) };
    let (lo_h, hi_h) = if ha <= hb { (ha, hb) } else { (hb, ha) };
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&lo_h);
    bytes[32..].copy_from_slice(&hi_h);
    Ok(SafetyNumber {
        digits: lo_d + &hi_d,
        bytes,
    })
}

impl SafetyNumber {
    /// The 60 digits, without separators
    #[must_use]
    pub fn digits(&self) -> &str {
        &self.digits
    }

    /// The 60 digits as 12 groups of 5, separated by single spaces (for reading aloud)
    #[must_use]
    pub fn grouped(&self) -> String {
        self.digits
            .as_bytes()
            .chunks(5)
            .map(|g| std::str::from_utf8(g).expect("ASCII digits"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The two parties' final hashes in ascending order (for comparing by QR code)
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }
}

impl fmt::Display for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.grouped())
    }
}
