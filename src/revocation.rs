//! revocation.

use std::collections::HashSet;

// RevocationRegistry
// ---------------------------------------------------------------------------

pub struct RevocationRegistry {
    revoked: HashSet<String>,
}

impl RevocationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            revoked: HashSet::new(),
        }
    }

    /// Revoke a credential by its ID.
    pub fn revoke(&mut self, credential_id: &str) {
        self.revoked.insert(credential_id.to_owned());
    }

    /// Check if a credential is revoked.
    #[must_use]
    pub fn is_revoked(&self, credential_id: &str) -> bool {
        self.revoked.contains(credential_id)
    }

    /// Un-revoke a credential (restore).
    pub fn restore(&mut self, credential_id: &str) {
        self.revoked.remove(credential_id);
    }

    /// Return the number of revoked credentials.
    #[must_use]
    pub fn count(&self) -> usize {
        self.revoked.len()
    }
}

impl Default for RevocationRegistry {
    fn default() -> Self {
        Self::new()
    }
}
