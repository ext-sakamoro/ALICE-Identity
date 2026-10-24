//! Resolving a DID to its master public key.
//!
//! Identity defines the question ([`MasterKeyResolver`]); the source of the answer (a registry of
//! DID documents, an offline cache, a directory) is the product's. [`DidResolver`] answers it
//! from the documents it holds: the master key is the one entry whose id is `<did>#master`,
//! controlled by that DID and 32 bytes long.

use crate::did::Did;
use crate::errors::IdentityError;
use crate::resolver::DidResolver;
use alice_sign::PublicKey;
use std::fmt;

/// The fragment of the public key entry that holds a DID's master key
pub const MASTER_KEY_FRAGMENT: &str = "#master";

/// Why a DID's master key could not be resolved
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// No document for the DID
    NotFound,
    /// The DID's document is deactivated
    Deactivated,
    /// The document has no `<did>#master` entry
    NoMasterKey,
    /// The document has more than one `<did>#master` entry
    AmbiguousMasterKey,
    /// The entry is controlled by another DID or does not hold 32 bytes
    InvalidMasterKey,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "DID document not found"),
            Self::Deactivated => write!(f, "DID document is deactivated"),
            Self::NoMasterKey => write!(f, "DID document has no master key entry"),
            Self::AmbiguousMasterKey => {
                write!(f, "DID document has more than one master key entry")
            }
            Self::InvalidMasterKey => write!(
                f,
                "invalid master key entry (another controller, or not 32 bytes)"
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Finds the master public key of a DID
pub trait MasterKeyResolver {
    /// The master public key of `did`
    ///
    /// # Errors
    /// [`ResolveError`] when the DID has no usable master key
    fn master_key(&self, did: &Did) -> Result<PublicKey, ResolveError>;
}

impl MasterKeyResolver for DidResolver {
    fn master_key(&self, did: &Did) -> Result<PublicKey, ResolveError> {
        let doc = match self.resolve(did) {
            Ok(doc) => doc,
            Err(IdentityError::DocumentDeactivated(_)) => return Err(ResolveError::Deactivated),
            Err(_) => return Err(ResolveError::NotFound),
        };
        let id = format!("{did}{MASTER_KEY_FRAGMENT}");
        let mut entries = doc.public_keys.iter().filter(|k| k.id == id);
        let entry = entries.next().ok_or(ResolveError::NoMasterKey)?;
        if entries.next().is_some() {
            return Err(ResolveError::AmbiguousMasterKey);
        }
        if entry.controller != *did {
            return Err(ResolveError::InvalidMasterKey);
        }
        let key: [u8; 32] = entry
            .public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ResolveError::InvalidMasterKey)?;
        Ok(PublicKey(key))
    }
}
