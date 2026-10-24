//! public key.

use crate::did::Did;

// PublicKeyEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyEntry {
    pub id: String,
    pub key_type: String,
    pub controller: Did,
    pub public_key_bytes: Vec<u8>,
}
