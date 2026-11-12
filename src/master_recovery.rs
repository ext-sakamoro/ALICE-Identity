//! Recovery of the master key after the devices are lost, keeping the same DID.
//!
//! A DID here is `did:key` of the master public key, so the identity lives exactly as long as the master
//! secret (the 32-byte Ed25519 seed). Two ways bring the seed back:
//!
//! - **recovery code** ([`MasterRecoveryBlob`]): the seed sealed under a [`RecoveryCode`] the person wrote down,
//!   bound to the master public key, so one person's blob never opens as another's;
//! - **shares** ([`split_master`] / [`recover_master`]): the seed split k-of-n among people the person trusts.
//!
//! Either way the seed that comes back is checked against the DID before it is used: its public key must be the
//! DID's key. The DID is the only check a recovered seed needs, so a changed share or a blob of someone else is
//! refused without any key held in advance, and with more than k shares the inconsistent ones are named.
//!
//! After recovery the master revokes the lost devices with [`crate::cert_revocation::RevocationList::extend`],
//! which keeps every device it revoked before, and issues certificates for the new ones. A device revoked before
//! the loss stays revoked: receivers refuse a newer list that leaves it out
//! ([`crate::cert_revocation::RevocationListError::DropsRevoked`]).
//!
//! What does not come back: messages no own device holds, the DID when the seed is lost with neither a code nor
//! enough shares, and what was read on a lost device before it was revoked.

use crate::did::Did;
use alice_crypto::recovery_code::{RecoveryCode, RecoveryCodeError};
use alice_crypto::{Shard, SssError};
use alice_sign::KeyPair;

/// The prefix of the associated data a seed is sealed under (followed by the master public key).
pub const MASTER_RECOVERY_CONTEXT: &[u8] = b"alice-identity master-recovery v1";

/// The master seed sealed under a recovery code, bound to the master public key.
#[derive(Clone, PartialEq, Eq)]
pub struct MasterRecoveryBlob {
    master_public: [u8; 32],
    sealed: Vec<u8>,
}

/// A master key brought back from shares, and the x of each share given that is not of it.
#[derive(Debug)]
pub struct RecoveredMaster {
    /// The master key, whose public key is the DID's key.
    pub key: KeyPair,
    /// The x coordinates of the shares that were left out because they do not give the DID's key.
    pub inconsistent: Vec<u8>,
}

/// Why a master key was not sealed, split or brought back.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterRecoveryError {
    /// The recovery code layer refused (wrong code, changed bytes, empty secret, no random source).
    Code(RecoveryCodeError),
    /// The shares are not enough, not of one split or malformed.
    Shares(SssError),
    /// The seed that came back does not give this DID's key.
    NotThisIdentity,
    /// More than k shares were given and no k of them give this DID's key.
    NoConsistentSet,
    /// The DID is not a `did:key` of an Ed25519 key.
    NotAKeyDid,
    /// Bytes that are not a sealed master blob.
    Malformed,
}

impl MasterRecoveryBlob {
    /// Seal the master `seed` under `code`.
    ///
    /// # Errors
    ///
    /// [`MasterRecoveryError::Code`] when the random source is unavailable.
    pub fn seal(seed: &[u8; 32], code: &RecoveryCode) -> Result<Self, MasterRecoveryError> {
        let _ = (seed, code);
        todo!("STUB: sealing the master seed (device-loss recovery step 2)")
    }

    /// The blob as bytes: the master public key (32) followed by the sealed seed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let _ = (&self.master_public, &self.sealed);
        todo!("STUB: master blob bytes (device-loss recovery step 2)")
    }

    /// A blob from [`Self::to_bytes`].
    ///
    /// # Errors
    ///
    /// [`MasterRecoveryError::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MasterRecoveryError> {
        let _ = bytes;
        todo!("STUB: master blob from bytes (device-loss recovery step 2)")
    }

    /// Open with `code` and return the master key, only when its public key is `expected`'s key.
    ///
    /// # Errors
    ///
    /// [`MasterRecoveryError::NotAKeyDid`], [`MasterRecoveryError::NotThisIdentity`] (the blob is of another DID) or
    /// [`MasterRecoveryError::Code`] (wrong code, changed bytes).
    pub fn open(
        &self,
        code: &RecoveryCode,
        expected: &Did,
    ) -> Result<KeyPair, MasterRecoveryError> {
        let _ = (code, expected);
        todo!("STUB: opening the master blob (device-loss recovery step 2)")
    }
}

impl core::fmt::Debug for MasterRecoveryBlob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MasterRecoveryBlob")
            .field("sealed_len", &self.sealed.len())
            .finish_non_exhaustive()
    }
}

/// Split the master `seed` into `n` shares of which any `k` bring it back.
///
/// # Errors
///
/// [`MasterRecoveryError::Shares`] for `k < 2`, `k > n` or no random source.
pub fn split_master(seed: &[u8; 32], n: u8, k: u8) -> Result<Vec<Shard>, MasterRecoveryError> {
    let _ = (seed, n, k);
    todo!("STUB: splitting the master seed (device-loss recovery step 2)")
}

/// Bring the master key back from `shares`, checked against `expected`.
///
/// With exactly k shares the seed they give must be the DID's; with more, the first set of k (in the order given)
/// that gives the DID's key is used and the others are named in [`RecoveredMaster::inconsistent`].
///
/// # Errors
///
/// [`MasterRecoveryError::Shares`] (fewer than k, mixed splits), [`MasterRecoveryError::NotThisIdentity`] (k shares
/// that do not give the DID's key), [`MasterRecoveryError::NoConsistentSet`] or [`MasterRecoveryError::NotAKeyDid`].
pub fn recover_master(
    shares: &[Shard],
    expected: &Did,
) -> Result<RecoveredMaster, MasterRecoveryError> {
    let _ = (shares, expected);
    todo!("STUB: recovering the master seed (device-loss recovery step 2)")
}
