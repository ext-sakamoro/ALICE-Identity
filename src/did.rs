//! did.

use crate::base58;
use crate::errors::IdentityError;
use alice_sign::PublicKey;
use std::fmt;

// Did
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Did {
    pub method: String,
    pub id: String,
}

/// The multicodec of an Ed25519 public key (0xed) as its unsigned varint
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

impl Did {
    #[must_use]
    pub fn new(method: &str, id: &str) -> Self {
        Self {
            method: method.to_owned(),
            id: id.to_owned(),
        }
    }

    /// Parse a DID string in the format `did:method:id`.
    ///
    /// # Errors
    /// Returns `IdentityError::InvalidDid` when the string does not conform.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 || parts[0] != "did" || parts[1].is_empty() || parts[2].is_empty() {
            return Err(IdentityError::InvalidDid(s.to_owned()));
        }
        Ok(Self {
            method: parts[1].to_owned(),
            id: parts[2].to_owned(),
        })
    }

    /// The did:key of an Ed25519 public key: `did:key:z` + base58btc(0xed 0x01 ‖ the 32 key bytes)
    /// (the multicodec of an Ed25519 public key is 0xed, written as the varint 0xed 0x01)
    #[must_use]
    pub fn key_ed25519(public: &PublicKey) -> Self {
        let mut bytes = Vec::with_capacity(ED25519_MULTICODEC.len() + public.0.len());
        bytes.extend_from_slice(&ED25519_MULTICODEC);
        bytes.extend_from_slice(&public.0);
        Self::new("key", &format!("z{}", base58::encode(&bytes)))
    }

    /// The Ed25519 public key a did:key carries
    ///
    /// # Errors
    /// `IdentityError::InvalidDid` when the DID is not of method `key`, its multibase is not
    /// base58btc (`z`), a character is outside the base58btc alphabet, the decoded bytes do not
    /// start with the Ed25519 multicodec 0xed 0x01, or they are not 34 long.
    pub fn ed25519_public_key(&self) -> Result<PublicKey, IdentityError> {
        let refuse = |why: &str| IdentityError::InvalidDid(format!("{self}: {why}"));
        if self.method != "key" {
            return Err(refuse("not a did:key"));
        }
        let Some(text) = self.id.strip_prefix('z') else {
            return Err(refuse("the multibase is not base58btc ('z')"));
        };
        let bytes = base58::decode(text).map_err(|e| refuse(&e.to_string()))?;
        if bytes.get(..2) != Some(&ED25519_MULTICODEC[..]) {
            return Err(refuse(
                "not an Ed25519 public key (multicodec is not 0xed 0x01)",
            ));
        }
        if bytes.len() != ED25519_MULTICODEC.len() + 32 {
            return Err(refuse(&format!(
                "the decoded length is {}, not 34",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[2..]);
        Ok(PublicKey(key))
    }

    /// Validate that the DID has non-empty method and id.
    ///
    /// # Errors
    /// Returns `IdentityError::InvalidDid` if method or id is empty.
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.method.is_empty() || self.id.is_empty() {
            return Err(IdentityError::InvalidDid(self.to_string()));
        }
        Ok(())
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "did:{}:{}", self.method, self.id)
    }
}
