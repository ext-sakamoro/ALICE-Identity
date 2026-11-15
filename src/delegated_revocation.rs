//! Revocation lists signed by a delegate of an offline master key.
//!
//! A relay publishes a revocation list ([`RevocationList`]) often, but the operator's master key stays
//! offline. The master therefore certifies a delegate key for the service
//! [`REVOCATION_DELEGATE_SERVICE`] (a service certificate, [`crate::service_cert`]) and the delegate signs the
//! lists. [`DelegatedRevocations`] keeps the newest list it has accepted for one master, with the delegate
//! certificate that vouches for its signer.
//!
//! # The delegate certificate
//!
//! - it is a service certificate for [`REVOCATION_DELEGATE_SERVICE`] issued by the master
//!   ([`issue_revocation_delegate`]); its signing key is the delegate's Ed25519 key;
//! - its Noise static key is [`REVOCATION_DELEGATE_NOISE_STATIC`] (all zero): the delegate signs lists and is
//!   never the peer of a channel. A certificate with another Noise key is refused
//!   ([`DelegatedRevocationError::NotAZeroNoiseKey`]). An all-zero X25519 key is a small-order point, so
//!   a Diffie-Hellman with it gives the all-zero shared secret, which a key agreement that checks for it
//!   refuses;
//! - it is valid for at most [`REVOCATION_DELEGATE_MAX_LIFETIME_SECS`] (7 days), stricter than the general
//!   [`crate::service_cert::SERVICE_CERT_MAX_LIFETIME_SECS`] (30 days), enforced at verification.
//!
//! # Ordering by (epoch, sequence)
//!
//! The epoch of a list is the `issued_at` of the delegate certificate that vouches for its signer; the
//! master signed it. Lists are ordered by (epoch, sequence):
//!
//! - a list under a newer epoch replaces the kept one whatever their sequences;
//! - a list under an older epoch than the kept one is refused ([`DelegatedRevocationError::OlderEpoch`]);
//! - within one epoch the sequence must rise ([`DelegatedRevocationError::OlderSequence`]), a list with
//!   the same sequence and the same content changes nothing ([`Accepted::Unchanged`]), and a list with the
//!   same sequence and other content is refused with the digests of both
//!   ([`DelegatedRevocationError::Conflict`]); the kept list stays;
//! - within one epoch a newer list keeps every device the kept one revokes
//!   ([`DelegatedRevocationError::DropsRevoked`]), as [`crate::cert_revocation::CertRevocations`] does;
//!   a new epoch may drop entries, so the master's next delegate can undo what a leaked delegate signed;
//! - one epoch has one delegate key: a list under the same epoch signed by another delegate key is
//!   refused ([`DelegatedRevocationError::DelegateConflict`]).
//!
//! A leaked delegate key can sign a list with sequence `u64::MAX - 1` under its epoch E. The master's next
//! delegate (epoch E' > E) supersedes it with a list of any sequence, and from then on every list under E
//! is refused. The next list may also name the leaked delegate's [`crate::device_cert::DeviceId`]: a
//! delegate whose id the kept list revokes is refused.
//!
//! # Freshness
//!
//! A list is accepted only when it is fresh ([`RevocationList::is_fresh`]): `now - window <= issued_at <=
//! now + MAX_CLOCK_SKEW_SECS`. The window is the caller's; [`DEFAULT_REVOCATION_FRESHNESS_WINDOW_SECS`]
//! (24 hours) is the default, and a relay re-signs its list every quarter of the window (6 hours). A
//! caller that acts on revocation calls [`DelegatedRevocations::require_fresh`] at each use: nothing kept, or
//! a kept list that has gone stale, is a refusal. The clock statements of [`RevocationList::is_fresh`]
//! apply.
//!
//! # Limits
//!
//! - **The signing job stopping.** Lists are signed online by the delegate. If the operator's signing
//!   job stops, every caller that requires a fresh list refuses the relay once the newest list is older
//!   than the window (24 hours by default). When the delegate certificate also expires (at most 7 days
//!   after it was issued), no new list can be signed until the master issues the next delegate. The
//!   refusal is the intended outcome: a relay whose revocation status cannot be shown is not used.
//! - **A leaked delegate key.** Until its certificate expires (at most
//!   [`REVOCATION_DELEGATE_MAX_LIFETIME_SECS`]), a leaked epoch-E key can keep signing fresh lists under
//!   E. A caller that never sees a list under a newer epoch E' accepts them; freshness does not shorten
//!   this. A caller that talks only to a compromised relay is exposed for at most the delegate's lifetime.
//! - **A clock behind on a fresh install.** With nothing kept, an old list looks fresh for as far as the
//!   clock is behind; only the certificate checks under the same clock bound it (see
//!   [`RevocationList::is_fresh`]).
//!
//! # Persistence
//!
//! [`DelegatedRevocations::to_bytes`] encodes the kept state:
//!
//! ```text
//! bytes = version (1) || kept (1: 0 or 1) || state (when kept) || SHA-256(everything before) (32)
//! state = master (32) || epoch (u64 BE) || sequence (u64 BE)
//!         || certificate length (u16 BE) || delegate certificate || list length (u32 BE) || list
//! ```
//!
//! [`DelegatedRevocations::from_bytes`] refuses any change to the bytes (the digest covers them all, and
//! the epoch and sequence must equal the certificate's and the list's), but checks no signature: the
//! digest has no key. [`DelegatedRevocations::restore`] reads the bytes and checks every signature and
//! certificate rule again under the master, except the times: the stored list may be stale and the stored
//! delegate may have expired, and freshness is checked per use ([`DelegatedRevocations::require_fresh`]).
//!
//! The digest detects corruption, not replacement. Anyone who can write where the bytes are stored can
//! put back an older, validly signed state and lower the (epoch, sequence) floor. The gain is bounded by
//! the window: the restored list goes stale within it, after which a fresh list is required. Keeping the
//! floor where that writer cannot rewind it is the caller's choice.

use crate::artifact::Revocation;
use crate::cert_revocation::{Accepted, CertRevocations, RevocationList, RevocationListError};
use crate::device_cert::{DeviceCert, DeviceCertError, DeviceId};
use crate::service_cert::{
    issue_service_cert, service_subject, verify_service_cert, ServiceCertError,
};
use alice_crypto::sha256::digest;
use alice_sign::{KeyPair, PublicKey};
use std::fmt;

/// The service name of a revocation delegate's certificate
pub const REVOCATION_DELEGATE_SERVICE: &str = "relay-revocations";

/// The Noise static key of a revocation delegate's certificate: all zero, so the certificate is never a
/// channel peer's
pub const REVOCATION_DELEGATE_NOISE_STATIC: [u8; 32] = [0; 32];

/// The longest a revocation delegate's certificate is valid, `not_after - issued_at`, in seconds (7 days)
pub const REVOCATION_DELEGATE_MAX_LIFETIME_SECS: u64 = 7 * 86_400;

/// The default freshness window of a revocation list, in seconds (24 hours): a relay re-signs its list
/// every quarter of it (6 hours), so a list missed or delayed three times is still fresh
pub const DEFAULT_REVOCATION_FRESHNESS_WINDOW_SECS: u64 = 86_400;

/// The only state layout this version reads and writes
pub const DELEGATED_REVOCATIONS_VERSION: u8 = 1;

const DIGEST: usize = 32;

/// Why a delegate, a list or a stored state was refused
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegatedRevocationError {
    /// The delegate certificate is not a valid service certificate for [`REVOCATION_DELEGATE_SERVICE`] from
    /// the master (issuer, signature, validity window, service, revocation)
    DelegateCert(ServiceCertError),
    /// The delegate certificate's Noise static key is not [`REVOCATION_DELEGATE_NOISE_STATIC`]
    NotAZeroNoiseKey,
    /// The delegate certificate's `not_after - issued_at` is over [`REVOCATION_DELEGATE_MAX_LIFETIME_SECS`]
    LifetimeTooLong(u64),
    /// The list names another signer than the delegate's signing key
    WrongSigner,
    /// The list's signature does not verify (strictly) under the delegate's signing key
    BadSignature,
    /// The list was issued before `now - window`
    Stale { issued_at: u64, now: u64 },
    /// The list is dated after `now + MAX_CLOCK_SKEW_SECS`
    FromTheFuture { issued_at: u64, now: u64 },
    /// The list's epoch is older than the kept one's
    OlderEpoch { kept: u64, offered: u64 },
    /// Within the kept epoch, the list's sequence is lower than the kept one's
    OlderSequence { epoch: u64, kept: u64, offered: u64 },
    /// Within the kept epoch, another list has the same sequence (the SHA-256 of both encoded lists is
    /// given; the kept list stays)
    Conflict {
        epoch: u64,
        sequence: u64,
        kept_digest: [u8; 32],
        offered_digest: [u8; 32],
    },
    /// Within the kept epoch, the list is signed by another delegate key than the kept one
    DelegateConflict { epoch: u64 },
    /// Within the kept epoch, a newer list leaves out a device the kept list revokes (the kept list stays)
    DropsRevoked { device_id: DeviceId },
    /// The kept state belongs to another master key
    OtherMaster,
    /// No list is kept
    NothingKept,
    /// The stored state's layout version is not [`DELEGATED_REVOCATIONS_VERSION`]
    UnsupportedVersion(u8),
    /// The stored state is not one whole, unchanged state (the reason names the part)
    Malformed(&'static str),
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl fmt::Display for DelegatedRevocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DelegateCert(e) => write!(f, "revocation delegate: {e}"),
            Self::NotAZeroNoiseKey => {
                write!(f, "revocation delegate certificate has a non-zero Noise key")
            }
            Self::LifetimeTooLong(secs) => write!(
                f,
                "revocation delegate lifetime {secs} s is over {REVOCATION_DELEGATE_MAX_LIFETIME_SECS} s"
            ),
            Self::WrongSigner => write!(
                f,
                "revocation list names another signer than the delegate key"
            ),
            Self::BadSignature => write!(
                f,
                "revocation list signature does not verify under the delegate key"
            ),
            Self::Stale { issued_at, now } => write!(
                f,
                "revocation list issued at {issued_at} is stale at {now}"
            ),
            Self::FromTheFuture { issued_at, now } => write!(
                f,
                "revocation list issued at {issued_at} is from the future at {now}"
            ),
            Self::OlderEpoch { kept, offered } => write!(
                f,
                "revocation list epoch {offered} is older than the kept epoch {kept}"
            ),
            Self::OlderSequence {
                epoch,
                kept,
                offered,
            } => write!(
                f,
                "revocation list sequence {offered} is lower than the kept {kept} in epoch {epoch}"
            ),
            Self::Conflict {
                epoch,
                sequence,
                kept_digest,
                offered_digest,
            } => write!(
                f,
                "conflicting revocation lists at epoch {epoch} sequence {sequence}: kept sha256 {} offered sha256 {}",
                hex(kept_digest),
                hex(offered_digest)
            ),
            Self::DelegateConflict { epoch } => write!(
                f,
                "another delegate key signs revocation lists in epoch {epoch}"
            ),
            Self::DropsRevoked { device_id } => write!(
                f,
                "a newer revocation list leaves out the revoked device {device_id}"
            ),
            Self::OtherMaster => write!(f, "the kept revocations belong to another master key"),
            Self::NothingKept => write!(f, "no revocation list is kept"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported delegated revocations version {v}")
            }
            Self::Malformed(what) => write!(f, "malformed delegated revocations: {what}"),
        }
    }
}

impl std::error::Error for DelegatedRevocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DelegateCert(e) => Some(e),
            _ => None,
        }
    }
}

/// Certify `delegate_public` as the master's revocation delegate from `issued_at` to `not_after`
/// (a service certificate for [`REVOCATION_DELEGATE_SERVICE`] with the all-zero Noise key)
///
/// # Errors
/// [`DelegatedRevocationError::LifetimeTooLong`] when `not_after - issued_at` is over
/// [`REVOCATION_DELEGATE_MAX_LIFETIME_SECS`], [`DelegatedRevocationError::DelegateCert`] when the service
/// certificate is not issued (`not_after <= issued_at`)
pub fn issue_revocation_delegate(
    master: &KeyPair,
    delegate_public: [u8; 32],
    issued_at: u64,
    not_after: u64,
) -> Result<DeviceCert, DelegatedRevocationError> {
    let lifetime = not_after.saturating_sub(issued_at);
    if lifetime > REVOCATION_DELEGATE_MAX_LIFETIME_SECS {
        return Err(DelegatedRevocationError::LifetimeTooLong(lifetime));
    }
    issue_service_cert(
        master,
        REVOCATION_DELEGATE_SERVICE,
        delegate_public,
        REVOCATION_DELEGATE_NOISE_STATIC,
        issued_at,
        not_after,
    )
    .map_err(DelegatedRevocationError::DelegateCert)
}

/// The delegate rules beyond the service certificate: the zero Noise key and the 7-day bound
fn delegate_rules(delegate: &DeviceCert) -> Result<(), DelegatedRevocationError> {
    if *delegate.noise_static() != REVOCATION_DELEGATE_NOISE_STATIC {
        return Err(DelegatedRevocationError::NotAZeroNoiseKey);
    }
    let lifetime = delegate.not_after().saturating_sub(delegate.issued_at());
    if lifetime > REVOCATION_DELEGATE_MAX_LIFETIME_SECS {
        return Err(DelegatedRevocationError::LifetimeTooLong(lifetime));
    }
    Ok(())
}

/// The list is signed by the delegate: it names the delegate's key and its signature verifies under it
fn signed_by(list: &RevocationList, delegate: &DeviceCert) -> Result<(), DelegatedRevocationError> {
    if list.issuer_public() != delegate.device_public() {
        return Err(DelegatedRevocationError::WrongSigner);
    }
    list.verify(&PublicKey(*delegate.device_public()))
        .map_err(|_| DelegatedRevocationError::BadSignature)
}

const fn freshness(
    list: &RevocationList,
    now: u64,
    window: u64,
) -> Result<(), DelegatedRevocationError> {
    if list.is_fresh(now, window) {
        return Ok(());
    }
    let issued_at = list.issued_at();
    if issued_at > now {
        Err(DelegatedRevocationError::FromTheFuture { issued_at, now })
    } else {
        Err(DelegatedRevocationError::Stale { issued_at, now })
    }
}

#[derive(Debug, Clone)]
struct Kept {
    master: PublicKey,
    delegate: DeviceCert,
    list: RevocationList,
    /// the list as the newest list of `master`, for [`Revocation::Checked`]
    view: CertRevocations,
}

impl Kept {
    fn new(master: PublicKey, delegate: DeviceCert, list: RevocationList) -> Self {
        let view = CertRevocations::with_list(&master, list.clone());
        Self {
            master,
            delegate,
            list,
            view,
        }
    }

    const fn epoch(&self) -> u64 {
        self.delegate.issued_at()
    }
}

/// The newest revocation list of one master key, signed by a delegate the master certified
#[derive(Debug, Clone, Default)]
pub struct DelegatedRevocations {
    kept: Option<Kept>,
}

impl DelegatedRevocations {
    /// Nothing kept
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept `list`, signed by the delegate `delegate` certifies, under `master` at `now`
    ///
    /// The checks run in this order and the first failing one is returned; the kept state changes only
    /// when the list is accepted:
    ///
    /// 1. the kept state, if any, belongs to `master` ([`DelegatedRevocationError::OtherMaster`]);
    /// 2. `delegate` is a service certificate for [`REVOCATION_DELEGATE_SERVICE`] from `master` at `now`
    ///    that the kept list does not revoke ([`crate::service_cert::verify_service_cert`];
    ///    [`DelegatedRevocationError::DelegateCert`]), its Noise key is all zero
    ///    ([`DelegatedRevocationError::NotAZeroNoiseKey`]) and its lifetime is at most 7 days
    ///    ([`DelegatedRevocationError::LifetimeTooLong`]);
    /// 3. the list names the delegate's signing key ([`DelegatedRevocationError::WrongSigner`]) and its
    ///    signature verifies under it ([`DelegatedRevocationError::BadSignature`]);
    /// 4. the list is fresh at `now` for `window` ([`DelegatedRevocationError::Stale`] /
    ///    [`DelegatedRevocationError::FromTheFuture`]);
    /// 5. the (epoch, sequence) ordering of the module documentation.
    ///
    /// # Errors
    /// See the order above
    pub fn accept(
        &mut self,
        list: RevocationList,
        delegate: &DeviceCert,
        master: &PublicKey,
        now: u64,
        window: u64,
    ) -> Result<Accepted, DelegatedRevocationError> {
        if let Some(kept) = &self.kept {
            if kept.master != *master {
                return Err(DelegatedRevocationError::OtherMaster);
            }
        }
        verify_service_cert(
            delegate,
            master,
            REVOCATION_DELEGATE_SERVICE,
            now,
            self.revocation(),
        )
        .map_err(DelegatedRevocationError::DelegateCert)?;
        delegate_rules(delegate)?;
        signed_by(&list, delegate)?;
        freshness(&list, now, window)?;
        let epoch = delegate.issued_at();
        let Some(kept) = &self.kept else {
            self.kept = Some(Kept::new(*master, delegate.clone(), list));
            return Ok(Accepted::Replaced);
        };
        let kept_epoch = kept.epoch();
        if epoch < kept_epoch {
            return Err(DelegatedRevocationError::OlderEpoch {
                kept: kept_epoch,
                offered: epoch,
            });
        }
        if epoch > kept_epoch {
            self.kept = Some(Kept::new(*master, delegate.clone(), list));
            return Ok(Accepted::Replaced);
        }
        if kept.delegate.device_public() != delegate.device_public() {
            return Err(DelegatedRevocationError::DelegateConflict { epoch });
        }
        let (kept_seq, seq) = (kept.list.sequence(), list.sequence());
        if seq < kept_seq {
            return Err(DelegatedRevocationError::OlderSequence {
                epoch,
                kept: kept_seq,
                offered: seq,
            });
        }
        if seq == kept_seq {
            if kept.list == list {
                return Ok(Accepted::Unchanged);
            }
            return Err(DelegatedRevocationError::Conflict {
                epoch,
                sequence: seq,
                kept_digest: digest(&kept.list.to_bytes()),
                offered_digest: digest(&list.to_bytes()),
            });
        }
        if let Some(dropped) = kept.list.revoked().iter().find(|id| !list.contains(id)) {
            return Err(DelegatedRevocationError::DropsRevoked {
                device_id: *dropped,
            });
        }
        self.kept = Some(Kept::new(*master, delegate.clone(), list));
        Ok(Accepted::Replaced)
    }

    /// Refuse unless a list is kept and it is fresh at `now` for `window` (the rule a caller applies before
    /// acting on revocation)
    ///
    /// # Errors
    /// [`DelegatedRevocationError::NothingKept`], [`DelegatedRevocationError::Stale`],
    /// [`DelegatedRevocationError::FromTheFuture`]
    pub fn require_fresh(&self, now: u64, window: u64) -> Result<(), DelegatedRevocationError> {
        let kept = self
            .kept
            .as_ref()
            .ok_or(DelegatedRevocationError::NothingKept)?;
        freshness(&kept.list, now, window)
    }

    /// Whether the kept list revokes `cert` (a certificate of the kept master; nothing kept: not revoked)
    ///
    /// This does not check freshness; see [`Self::require_fresh`].
    #[must_use]
    pub fn revokes(&self, cert: &DeviceCert) -> bool {
        self.kept.as_ref().is_some_and(|k| k.view.revokes(cert))
    }

    /// The kept list as a [`Revocation`] for [`crate::service_cert::verify_service_cert`] and the artifact
    /// verifiers: [`Revocation::Checked`] when a list is kept, [`Revocation::NoListAvailable`] otherwise
    ///
    /// This does not check freshness; see [`Self::require_fresh`].
    #[must_use]
    pub fn revocation(&self) -> Revocation<'_> {
        self.kept.as_ref().map_or(Revocation::NoListAvailable, |k| {
            Revocation::Checked(&k.view)
        })
    }

    /// The epoch (the delegate certificate's `issued_at`) of the kept list
    #[must_use]
    pub fn epoch(&self) -> Option<u64> {
        self.kept.as_ref().map(Kept::epoch)
    }

    /// The sequence of the kept list
    #[must_use]
    pub fn sequence(&self) -> Option<u64> {
        self.kept.as_ref().map(|k| k.list.sequence())
    }

    /// The kept list
    #[must_use]
    pub fn list(&self) -> Option<&RevocationList> {
        self.kept.as_ref().map(|k| &k.list)
    }

    /// The certificate of the kept list's signer
    #[must_use]
    pub fn delegate(&self) -> Option<&DeviceCert> {
        self.kept.as_ref().map(|k| &k.delegate)
    }

    /// The master key of the kept list
    #[must_use]
    pub fn master(&self) -> Option<&PublicKey> {
        self.kept.as_ref().map(|k| &k.master)
    }

    /// The encoded kept state (see the module documentation)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![DELEGATED_REVOCATIONS_VERSION];
        match &self.kept {
            None => b.push(0),
            Some(k) => {
                b.push(1);
                let cert = k.delegate.to_bytes();
                let list = k.list.to_bytes();
                // a certificate is at most MAX_DEVICE_CERT_LEN (450) bytes; a list is built by `issue` or
                // `from_bytes`, whose id count is a u32, so its length is far under 4 GiB in any real use
                let cert_len = u16::try_from(cert.len()).expect("a certificate fits a u16 length");
                let list_len = u32::try_from(list.len()).expect("a kept list fits a u32 length");
                b.extend_from_slice(&k.master.0);
                b.extend_from_slice(&k.epoch().to_be_bytes());
                b.extend_from_slice(&k.list.sequence().to_be_bytes());
                b.extend_from_slice(&cert_len.to_be_bytes());
                b.extend_from_slice(&cert);
                b.extend_from_slice(&list_len.to_be_bytes());
                b.extend_from_slice(&list);
            }
        }
        let d = digest(&b);
        b.extend_from_slice(&d);
        b
    }

    /// Decode a stored state, checking its integrity (digest, layout, the epoch and the sequence against the
    /// certificate and the list) but no signature: see [`Self::restore`]
    ///
    /// # Errors
    /// [`DelegatedRevocationError::UnsupportedVersion`], [`DelegatedRevocationError::Malformed`]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DelegatedRevocationError> {
        let (&version, _) = bytes
            .split_first()
            .ok_or(DelegatedRevocationError::Malformed("version"))?;
        if version != DELEGATED_REVOCATIONS_VERSION {
            return Err(DelegatedRevocationError::UnsupportedVersion(version));
        }
        let body_len = bytes
            .len()
            .checked_sub(DIGEST)
            .ok_or(DelegatedRevocationError::Malformed("digest"))?;
        let (body, stored) = bytes.split_at(body_len);
        if digest(body) != stored {
            return Err(DelegatedRevocationError::Malformed("digest"));
        }
        let mut r = Reader(&body[1..]);
        let kept = match r.take(1, "kept flag")? {
            [0] => None,
            [1] => Some(r.state()?),
            _ => return Err(DelegatedRevocationError::Malformed("kept flag")),
        };
        if !r.0.is_empty() {
            return Err(DelegatedRevocationError::Malformed("trailing bytes"));
        }
        Ok(Self { kept })
    }

    /// Decode a stored state and check it again under `master`: the delegate certificate's issuer and
    /// signature, its service, Noise key and lifetime, and the list's signer and signature
    ///
    /// The times are not checked: the stored list may be stale and the stored delegate may have expired.
    /// Freshness is checked at each use ([`Self::require_fresh`]), and the next [`Self::accept`] checks the
    /// next delegate at its `now`.
    ///
    /// # Errors
    /// As [`Self::from_bytes`], then [`DelegatedRevocationError::OtherMaster`],
    /// [`DelegatedRevocationError::DelegateCert`], [`DelegatedRevocationError::NotAZeroNoiseKey`],
    /// [`DelegatedRevocationError::LifetimeTooLong`], [`DelegatedRevocationError::WrongSigner`],
    /// [`DelegatedRevocationError::BadSignature`]
    pub fn restore(bytes: &[u8], master: &PublicKey) -> Result<Self, DelegatedRevocationError> {
        let state = Self::from_bytes(bytes)?;
        if let Some(k) = &state.kept {
            if k.master != *master {
                return Err(DelegatedRevocationError::OtherMaster);
            }
            k.delegate
                .verify_signature(master)
                .map_err(|e| DelegatedRevocationError::DelegateCert(ServiceCertError::Cert(e)))?;
            let expected = service_subject(REVOCATION_DELEGATE_SERVICE)
                .map_err(DelegatedRevocationError::DelegateCert)?;
            if *k.delegate.subject() != expected {
                return Err(DelegatedRevocationError::DelegateCert(
                    ServiceCertError::WrongService,
                ));
            }
            delegate_rules(&k.delegate)?;
            signed_by(&k.list, &k.delegate)?;
        }
        Ok(state)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    const fn take(
        &mut self,
        n: usize,
        what: &'static str,
    ) -> Result<&'a [u8], DelegatedRevocationError> {
        if self.0.len() < n {
            return Err(DelegatedRevocationError::Malformed(what));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u64(&mut self, what: &'static str) -> Result<u64, DelegatedRevocationError> {
        Ok(u64::from_be_bytes(
            self.take(8, what)?.try_into().expect("8 bytes"),
        ))
    }

    fn state(&mut self) -> Result<Kept, DelegatedRevocationError> {
        let master = PublicKey(self.take(32, "master")?.try_into().expect("32 bytes"));
        let epoch = self.u64("epoch")?;
        let sequence = self.u64("sequence")?;
        let cert_len = u16::from_be_bytes(
            self.take(2, "certificate length")?
                .try_into()
                .expect("2 bytes"),
        );
        let delegate = DeviceCert::from_bytes(self.take(usize::from(cert_len), "certificate")?)
            .map_err(|e: DeviceCertError| {
                DelegatedRevocationError::DelegateCert(ServiceCertError::Cert(e))
            })?;
        let list_len =
            u32::from_be_bytes(self.take(4, "list length")?.try_into().expect("4 bytes"));
        let list_len = usize::try_from(list_len)
            .map_err(|_| DelegatedRevocationError::Malformed("list length"))?;
        let list = RevocationList::from_bytes(self.take(list_len, "list")?).map_err(
            |e: RevocationListError| match e {
                RevocationListError::UnsupportedVersion(_) => {
                    DelegatedRevocationError::Malformed("list version")
                }
                _ => DelegatedRevocationError::Malformed("list"),
            },
        )?;
        if delegate.issued_at() != epoch {
            return Err(DelegatedRevocationError::Malformed("epoch"));
        }
        if list.sequence() != sequence {
            return Err(DelegatedRevocationError::Malformed("sequence"));
        }
        if delegate.issuer_public() != &master.0 {
            return Err(DelegatedRevocationError::Malformed("certificate issuer"));
        }
        Ok(Kept::new(master, delegate, list))
    }
}
