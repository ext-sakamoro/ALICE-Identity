//! credential.

use crate::did::Did;
use std::collections::BTreeMap;

// VerifiableCredential
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiableCredential {
    pub context: String,
    pub credential_type: String,
    pub issuer: Did,
    pub subject: Did,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub claims: BTreeMap<String, String>,
    pub proof: Vec<u8>,
}
