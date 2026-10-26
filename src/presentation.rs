//! presentation.

use crate::credential::CredentialPresentation;
use crate::did::Did;

// VerifiablePresentation
// ---------------------------------------------------------------------------

/// Credentials a holder presents together; each is verified on its own by
/// [`crate::verifier::CredentialVerifier::verify`]. The holder is a label: nothing here proves the
/// presenter is the holder.
#[derive(Debug, Clone)]
pub struct VerifiablePresentation {
    pub holder: Did,
    pub credentials: Vec<CredentialPresentation>,
}
