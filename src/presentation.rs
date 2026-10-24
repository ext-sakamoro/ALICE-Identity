//! presentation.

use crate::did::Did;

use crate::credential::VerifiableCredential;

// VerifiablePresentation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiablePresentation {
    pub holder: Did,
    pub credentials: Vec<VerifiableCredential>,
    pub proof: Vec<u8>,
}
