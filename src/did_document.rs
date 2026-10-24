//! did document.

use crate::did::Did;
use crate::public_key::PublicKeyEntry;
use crate::service_endpoint::ServiceEndpoint;

// DidDocument
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidDocument {
    pub id: Did,
    pub public_keys: Vec<PublicKeyEntry>,
    pub services: Vec<ServiceEndpoint>,
    pub created: u64,
    pub updated: u64,
}

impl DidDocument {
    #[must_use]
    pub const fn new(id: Did, created: u64) -> Self {
        Self {
            id,
            public_keys: Vec::new(),
            services: Vec::new(),
            created,
            updated: created,
        }
    }

    pub fn add_public_key(&mut self, key: PublicKeyEntry) {
        self.public_keys.push(key);
    }

    pub fn add_service(&mut self, service: ServiceEndpoint) {
        self.services.push(service);
    }
}
