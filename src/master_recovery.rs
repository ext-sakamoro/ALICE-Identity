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
use alice_crypto::recovery_code::{
    open_secret, seal_secret, RecoveryCode, RecoveryCodeError, RECOVERY_BLOB_OVERHEAD,
};
use alice_crypto::{Shard, SssError};
use alice_sign::{KeyPair, PublicKey};

/// The prefix of the associated data a seed is sealed under (followed by the master public key).
pub const MASTER_RECOVERY_CONTEXT: &[u8] = b"alice-identity master-recovery v1";

/// The most sets of k shares [`recover_master`] tries when more than k are given; beyond it the call is refused
/// ([`MasterRecoveryError::TooManyShares`]) rather than spend unbounded time.
pub const MAX_RECOVERY_SETS: u64 = 4096;

/// The associated data the seed of `master_public` is sealed under
fn aad(master_public: &[u8; 32]) -> Vec<u8> {
    let mut a = Vec::with_capacity(MASTER_RECOVERY_CONTEXT.len() + 32);
    a.extend_from_slice(MASTER_RECOVERY_CONTEXT);
    a.extend_from_slice(master_public);
    a
}

/// The DID's Ed25519 key
fn did_key(did: &Did) -> Result<PublicKey, MasterRecoveryError> {
    did.ed25519_public_key()
        .map_err(|_| MasterRecoveryError::NotAKeyDid)
}

/// The key of `seed` when it is the DID's
fn key_of(seed: &[u8], expected: &PublicKey) -> Result<KeyPair, MasterRecoveryError> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| MasterRecoveryError::NotThisIdentity)?;
    let key = KeyPair::from_seed(seed);
    if key.public() == *expected {
        Ok(key)
    } else {
        Err(MasterRecoveryError::NotThisIdentity)
    }
}

/// C(n, k), saturating at `u64::MAX`
fn binomial(n: u64, k: u64) -> u64 {
    let k = k.min(n - k);
    (0..k).fold(1u64, |acc, i| {
        acc.checked_mul(n - i).map_or(u64::MAX, |v| v / (i + 1))
    })
}

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
    /// More than k shares given and more than [`MAX_RECOVERY_SETS`] sets of k among them.
    TooManyShares,
}

impl core::fmt::Display for MasterRecoveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Code(e) => write!(f, "recovery code: {e}"),
            Self::Shares(e) => write!(f, "shares: {e}"),
            Self::NotThisIdentity => f.write_str("the recovered key is not this DID's key"),
            Self::NoConsistentSet => f.write_str("no set of k shares gives this DID's key"),
            Self::NotAKeyDid => f.write_str("the DID is not a did:key of an Ed25519 key"),
            Self::Malformed => f.write_str("not a sealed master blob"),
            Self::TooManyShares => {
                write!(f, "more than {MAX_RECOVERY_SETS} sets of k shares to try")
            }
        }
    }
}

impl std::error::Error for MasterRecoveryError {}

impl MasterRecoveryBlob {
    /// Seal the master `seed` under `code`.
    ///
    /// # Errors
    ///
    /// [`MasterRecoveryError::Code`] when the random source is unavailable.
    pub fn seal(seed: &[u8; 32], code: &RecoveryCode) -> Result<Self, MasterRecoveryError> {
        let master_public = KeyPair::from_seed(*seed).public().0;
        let sealed =
            seal_secret(code, seed, &aad(&master_public)).map_err(MasterRecoveryError::Code)?;
        Ok(Self {
            master_public,
            sealed,
        })
    }

    /// The blob as bytes: the master public key (32) followed by the sealed seed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.sealed.len());
        out.extend_from_slice(&self.master_public);
        out.extend_from_slice(&self.sealed);
        out
    }

    /// A blob from [`Self::to_bytes`].
    ///
    /// # Errors
    ///
    /// [`MasterRecoveryError::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MasterRecoveryError> {
        // the master public key, then a sealed secret of at least one byte
        if bytes.len() <= 32 + RECOVERY_BLOB_OVERHEAD {
            return Err(MasterRecoveryError::Malformed);
        }
        let mut master_public = [0u8; 32];
        master_public.copy_from_slice(&bytes[..32]);
        Ok(Self {
            master_public,
            sealed: bytes[32..].to_vec(),
        })
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
        let want = did_key(expected)?;
        // the seed's own key is the check (a blob of another DID, or one whose header claims this DID over another
        // seed, ends there)
        let seed = open_secret(code, &self.sealed, &aad(&self.master_public))
            .map_err(MasterRecoveryError::Code)?;
        key_of(&seed, &want)
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
    alice_crypto::sss::split(seed, n, k).map_err(MasterRecoveryError::Shares)
}

/// Bring the master key back from `shares`, checked against `expected`.
///
/// With exactly k shares the seed they give must be the DID's. With more, every set of k is tried, and among the
/// sets whose seed is the DID's the one whose polynomial passes through the most of the given shares is used (the
/// first such in lexicographic order of positions); the shares off that polynomial are named in
/// [`RecoveredMaster::inconsistent`]. The key returned is always the DID's key. The naming is exact when at least k
/// of the shares are genuine: their polynomial passes through all of them, while a polynomial through a changed
/// share passes through fewer genuine ones. With fewer than k genuine shares, changed shares that cancel out can
/// still give the DID's key; it is returned, and the naming then reflects the set that gave it.
///
/// # Errors
///
/// [`MasterRecoveryError::Shares`] (fewer than k, mixed splits), [`MasterRecoveryError::NotThisIdentity`] (k shares
/// that do not give the DID's key), [`MasterRecoveryError::NoConsistentSet`], [`MasterRecoveryError::TooManyShares`]
/// or [`MasterRecoveryError::NotAKeyDid`].
pub fn recover_master(
    shares: &[Shard],
    expected: &Did,
) -> Result<RecoveredMaster, MasterRecoveryError> {
    let want = did_key(expected)?;
    // the usual errors (none, fewer than k, mixed splits, duplicate x) come from recovering them all
    let all = alice_crypto::recover(shares).map_err(MasterRecoveryError::Shares)?;
    let k = usize::from(shares[0].threshold());
    if shares.len() == k {
        return key_of(&all, &want).map(|key| RecoveredMaster {
            key,
            inconsistent: Vec::new(),
        });
    }
    // every share on one polynomial whose seed is the DID's: k - 1 of them and each other share give that seed
    if let Ok(key) = key_of(&all, &want) {
        let on_one = shares[k - 1..].iter().all(|s| {
            let mut probe: Vec<Shard> = shares[..k - 1].to_vec();
            probe.push(s.clone());
            alice_crypto::recover(&probe).is_ok_and(|p| *p == *all)
        });
        if on_one {
            return Ok(RecoveredMaster {
                key,
                inconsistent: Vec::new(),
            });
        }
    }
    if binomial(shares.len() as u64, k as u64) > MAX_RECOVERY_SETS {
        return Err(MasterRecoveryError::TooManyShares);
    }
    // the best set so far: (shares on its polynomial, its key, which shares are on it)
    let mut best: Option<(usize, KeyPair, Vec<bool>)> = None;
    let mut idx: Vec<usize> = (0..k).collect();
    loop {
        let set: Vec<Shard> = idx.iter().map(|&i| shares[i].clone()).collect();
        let seed = alice_crypto::recover(&set).map_err(MasterRecoveryError::Shares)?;
        if let Ok(key) = key_of(&seed, &want) {
            // a share outside the set is on its polynomial when k - 1 of the set and it give the same seed (its y
            // enters every byte of the constant term with a non-zero Lagrange weight, so any change in it shows)
            let on: Vec<bool> = (0..shares.len())
                .map(|i| {
                    idx.contains(&i) || {
                        let mut probe: Vec<Shard> = set[..k - 1].to_vec();
                        probe.push(shares[i].clone());
                        alice_crypto::recover(&probe).is_ok_and(|p| *p == *seed)
                    }
                })
                .collect();
            let support = on.iter().filter(|&&b| b).count();
            if best.as_ref().is_none_or(|(s, _, _)| support > *s) {
                best = Some((support, key, on));
            }
        }
        // the next set in lexicographic order
        let mut i = k;
        let advanced = loop {
            if i == 0 {
                break false;
            }
            i -= 1;
            if idx[i] < shares.len() - k + i {
                break true;
            }
        };
        if !advanced {
            break;
        }
        idx[i] += 1;
        for j in i + 1..k {
            idx[j] = idx[j - 1] + 1;
        }
    }
    let (_, key, on) = best.ok_or(MasterRecoveryError::NoConsistentSet)?;
    let inconsistent = shares
        .iter()
        .zip(&on)
        .filter(|(_, &o)| !o)
        .map(|(s, _)| s.x())
        .collect();
    Ok(RecoveredMaster { key, inconsistent })
}
