//! resolver.

use crate::did::Did;
use crate::did_document::DidDocument;
use crate::errors::IdentityError;
use std::collections::{HashMap, HashSet};

// DidResolver
// ---------------------------------------------------------------------------

pub struct DidResolver {
    documents: HashMap<String, DidDocument>,
    deactivated: HashSet<String>,
}

impl DidResolver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            documents: HashMap::new(),
            deactivated: HashSet::new(),
        }
    }

    /// Register a new DID document.
    ///
    /// # Errors
    /// Returns an error if a document with the same DID already exists.
    pub fn register(&mut self, doc: DidDocument) -> Result<(), IdentityError> {
        let key = doc.id.to_string();
        if self.documents.contains_key(&key) {
            return Err(IdentityError::DocumentAlreadyExists(key));
        }
        self.documents.insert(key, doc);
        Ok(())
    }

    /// Resolve a DID to its document.
    ///
    /// # Errors
    /// Returns an error if the document is not found or has been deactivated.
    pub fn resolve(&self, did: &Did) -> Result<&DidDocument, IdentityError> {
        let key = did.to_string();
        if self.deactivated.contains(&key) {
            return Err(IdentityError::DocumentDeactivated(key));
        }
        self.documents
            .get(&key)
            .ok_or(IdentityError::DocumentNotFound(key))
    }

    /// Update an existing DID document.
    ///
    /// # Errors
    /// Returns an error if the document does not exist or is deactivated.
    pub fn update(&mut self, doc: DidDocument) -> Result<(), IdentityError> {
        let key = doc.id.to_string();
        if self.deactivated.contains(&key) {
            return Err(IdentityError::DocumentDeactivated(key));
        }
        if !self.documents.contains_key(&key) {
            return Err(IdentityError::DocumentNotFound(key));
        }
        self.documents.insert(key, doc);
        Ok(())
    }

    /// Deactivate a DID document.
    ///
    /// # Errors
    /// Returns an error if the document does not exist.
    pub fn deactivate(&mut self, did: &Did) -> Result<(), IdentityError> {
        let key = did.to_string();
        if !self.documents.contains_key(&key) {
            return Err(IdentityError::DocumentNotFound(key));
        }
        self.deactivated.insert(key);
        Ok(())
    }

    /// Check if a DID is deactivated.
    #[must_use]
    pub fn is_deactivated(&self, did: &Did) -> bool {
        self.deactivated.contains(&did.to_string())
    }
}

impl Default for DidResolver {
    fn default() -> Self {
        Self::new()
    }
}
